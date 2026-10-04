#!/usr/bin/env bash
# Upload the built artifacts to the GitHub Release for the current tag.
#
# This is the only step in the release train that touches the network, and it is
# a separate script for that reason rather than for tidiness. `dist build`
# writing files into target/distrib is completely reversible; creating a
# Release that other people can already fetch is not. They must not share a
# failure domain, and a `dist build` that fails halfway must leave nothing
# published.
#
# `gh` does the upload rather than a dist CI backend. That is not a workaround
# for GitHub Actions being prohibited here — `scripts/ci-policy.sh` would fail
# the run — it is the whole reason the release does not need a workflow. dist's
# `ci = ["github"]` backend exists to build on hosted runners and upload the
# results; here every build happens on the machine cutting the release, so what
# is left for the backend to do is one `gh release create`.
#
# Refuses to run without --confirm, and refuses to run twice. Both are
# deliberate: a release is the one artefact in this project that is immediately
# and permanently visible, and an accidental or repeated publish is not
# something a re-run should be able to cause.

set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONFIRM=0
DRAFT=0

usage() {
  cat <<'TXT'
Usage: scripts/publish-release.sh --confirm [--draft]

  --confirm   Required. Without it this script explains what it would do and
              exits 0 without publishing anything. There is no --yes, no
              interactive prompt and no environment variable that stands in
              for it: a publish that can be triggered by a flag someone
              added to a Makefile is a publish that will eventually happen
              from a Makefile.
  --draft     Create the Release as a draft. The artifacts are uploaded and
              nothing is announced until the draft is published by hand.
              Useful the first time, and the right default for a project below
              1.0 that has not been installed on a real machine yet.

Run scripts/verify-release-artifacts.py first. This script does not repeat
those checks, because a check that runs twice and can fail differently the
second time is a check whose result you will stop trusting.
TXT
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm) CONFIRM=1; shift ;;
    --draft)   DRAFT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "publish-release: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
TAG="v${VERSION}"
DISTRIB="target/distrib"

if ! command -v gh >/dev/null 2>&1; then
  echo "publish-release: gh is not installed. Authenticate with: gh auth login" >&2
  exit 1
fi

if [[ ! -f "${DISTRIB}/dist-manifest.json" ]]; then
  echo "publish-release: ${DISTRIB}/dist-manifest.json is missing. Run dist build first." >&2
  exit 1
fi

# Uploading to a Release that already exists appends to it. `gh` does not
# refuse on its own, and the result is a release whose artifact list is a mix
# of two builds with one tag, which is exactly the state
# verify-release-artifacts.py cannot detect afterwards.
if gh release view "$TAG" >/dev/null 2>&1; then
  echo "publish-release: a GitHub Release for ${TAG} already exists." >&2
  echo "  Either this is a re-run of a publish that succeeded, or someone else" >&2
  echo "  released this tag. Both need a human; refusing." >&2
  echo "  To see what is there:  gh release view ${TAG}" >&2
  exit 1
fi

# Collect the artifacts. Built from the manifest rather than from a glob, so
# that what is uploaded is what dist said it produced. A glob would also pick
# up a `dist-manifest.json` from a previous run of a different version, and
# uploading a manifest that describes other artifacts is how a release ends up
# advertising files it does not contain.
#
# Signatures are the one deliberate carve-out: a `<artifact>.minisig` sidecar
# produced by the sign stage rides alongside its artifact when present. The
# sidecar is not in the manifest because dist does not know about signatures,
# but it is not a directory-listing gamble either: it attaches only to a name
# the manifest already listed, and the sign stage verified each one against
# the staged public key before this script ran. `release.pub` rides along so
# a verifier can check the signature without trusting this repository to
# describe its own key.
mapfile -t ASSETS < <(
  python3 - "${DISTRIB}/dist-manifest.json" "${DISTRIB}" <<'PY'
import json, sys, pathlib
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
distrib = pathlib.Path(sys.argv[2])
seen = set()
for release in manifest.get("releases", []):
    for name in release.get("artifacts", []):
        if name in seen:
            continue
        seen.add(name)
        path = distrib / name
        # source.tar.gz and sha256.sum are workspace-global; emit them once.
        print(path)
        sidecar = distrib / f"{name}.minisig"
        if sidecar.exists():
            print(sidecar)
pubkey = distrib / "release.pub"
if pubkey.exists():
    print(pubkey)
# The product boundary, published beside the archive. It is not a dist artifact
# so it is not in dist-manifest.json, but the installer downloads it and decides
# from it which components it is allowed to install — a release that omits it
# serves an installer that cannot run. Its digest is in the signed sha256.sum
# (scripts/pin-manifest-into-checksums.py runs before the sign stage), so it
# arrives as a covered byte rather than as a second, unsigned declaration of
# what the product is.
manifest = distrib / "manifest.toml"
if manifest.exists():
    print(manifest)
else:
    sys.exit(f"publish-release: {manifest} is missing. Run "
             f"scripts/pin-manifest-into-checksums.py before publishing: the "
             f"installer downloads the manifest and a release without one is a "
             f"release nobody can install.")
PY
)

if [[ ${#ASSETS[@]} -eq 0 ]]; then
  echo "publish-release: the manifest lists no artifacts. Refusing to create an empty release." >&2
  exit 1
fi

if [[ $CONFIRM -ne 1 ]]; then
  DRAFT_NOTE=""
  [[ $DRAFT -eq 1 ]] && DRAFT_NOTE=" (as a draft)"
  cat <<EOF
publish-release: dry run. Nothing was uploaded.

Would create a GitHub Release for ${TAG} with ${#ASSETS[@]} assets:
EOF
  printf '  %s\n' "${ASSETS[@]}"
  cat <<EOF

Re-run with --confirm to actually publish${DRAFT_NOTE}.

The assets above come from dist-manifest.json, not from a directory listing,
so a stale file left over from a previous build cannot be uploaded by
accident.
EOF
  exit 0
fi

# The notes go to a file rather than through a process substitution. A process
# substitution hides the exit status of the command inside it, so a failure
# there would produce an empty release body and still exit 0 from this script.
NOTES="$(mktemp)"
trap 'rm -f "$NOTES"' EXIT
cat > "$NOTES" <<EOF
agent-secretless ${VERSION}

Binaries, checksums and installers for ${TAG}.

Install the CLI:

    curl -LsSf https://github.com/rubentxu/agent-secretless/releases/download/${TAG}/asv-cli-installer.sh | sh

The broker is a separate install — it is a daemon, not a command you run, and
it needs a systemd user unit. See the README, "Installing".
EOF

FLAGS=(--title "$TAG" --notes-file "$NOTES")
[[ $DRAFT -eq 1 ]] && FLAGS+=(--draft)

echo "publish-release: creating ${TAG} with ${#ASSETS[@]} assets"
gh release create "$TAG" "${ASSETS[@]}" "${FLAGS[@]}"

echo
echo "publish-release: ${TAG} created. Verify before announcing:"
echo "  gh release view ${TAG} --json assets --jq '.assets[].name'"
echo "  curl -LsSf https://github.com/rubentxu/agent-secretless/releases/download/${TAG}/sha256.sum"
