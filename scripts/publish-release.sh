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

# The product boundary must be present **before** any asset is collected, and
# this check is in the shell rather than inside the collector on purpose.
#
# It used to live in the python that builds ASSETS, calling `sys.exit` when
# `manifest.toml` was absent. That never stopped a publish: the python runs
# inside a `$( )` feeding `mapfile`, so its failure was the exit status of a
# command substitution nobody checked, while `mapfile` returned cleanly with
# the nine artifacts already printed. The guard read as a guard, printed its
# message, and the release went out anyway.
#
# v0.35.0 is the release that proved it. It shipped nine assets with no
# manifest and a signed `sha256.sum` that did not list one — so the installer
# found an authority that did not cover the file that decides what it may
# install, which is a refusal rather than an installation. The release had to
# be repaired after the fact. A check that cannot fail is a comment.
if [[ ! -f "${DISTRIB}/manifest.toml" ]]; then
  echo "publish-release: ${DISTRIB}/manifest.toml is missing." >&2
  echo "  Run scripts/pin-manifest-into-checksums.py before publishing, then" >&2
  echo "  re-run scripts/sign-release-artifacts.sh so the signed sha256.sum" >&2
  echo "  covers the manifest. The installer downloads the manifest and" >&2
  echo "  decides from it which components it may install: a release without" >&2
  echo "  one is a release nobody can install, and a signed sha256.sum that" >&2
  echo "  does not list it is a verifier refusing what it cannot cover." >&2
  exit 1
fi

# The install line in the release notes used to carry a hand-typed asset name.
#
# v0.36.0 is the release that proves what that costs. The notes said
# `curl ... /download/v0.36.0/asv-cli-installer.sh | sh`, dist had produced
# `agent-secretless-installer.sh`, and the URL was a 404 — so the official
# install instruction for a published release did not install anything. The
# name was correct when it was written, which is exactly why nothing noticed:
# a hand-typed name can be right twice in a row and wrong the third time, and
# no gate compared it with the manifest.
#
# So the name is read from `dist-manifest.json` — the same file the upload
# list was built from — and the check is that it is the *one* installer the
# manifest declares. A second installer artifact makes this fail rather than
# pick one, because "the install line names an installer" is not the claim
# being made; "it names the installer this release actually ships" is.
INSTALLER_NAME="$(python3 - "${DISTRIB}/dist-manifest.json" <<'PY'
import json, sys, pathlib
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
artifacts = manifest.get("artifacts", {})
names = sorted(a["name"] for a in artifacts.values()
               if isinstance(a, dict) and a.get("kind") == "installer")
if len(names) != 1:
    sys.exit(f"publish-release: expected exactly one artifact of kind "
             f"'installer' in the manifest, found {len(names)}: {names}. The "
             f"install line in the release notes must name the installer this "
             f"release ships, and there is no way to choose between two.")
print(names[0])
PY
)" || exit 1

# The same reasoning applies to where the download comes from. The notes had
# the repository slug typed out as well, lowercase, and nothing checked it
# against the remote this release is actually cut from.
REPO_SLUG="$(python3 - <<'PY'
import re, subprocess, sys
url = subprocess.run(["git", "config", "--get", "remote.origin.url"],
                     capture_output=True, text=True).stdout.strip()
# `[:/]` covers an https URL and an scp-style `git@host:owner/repo`, and the
# non-greedy `[^/:]+` with an optional `.git` is what strips the suffix.
#
# The sed this replaced looked correct and was not: with `.*[:/]+` greedy in
# front of it, `(\.git)?$` never got the chance to match, and the release URL
# came out as `.../agent-secretless.git/releases/...`, which 404s. It was only
# caught because the rewritten URL was fetched and asked for its status code
# rather than read and believed — the same rule this release violated twice
# already, in the asset name and in the README.
m = re.search(r"[:/]([^/:]+/[^/:]+?)(?:\.git)?$", url) if url else None
if not m:
    sys.exit("publish-release: could not read an owner/repo slug from "
             "remote.origin.url. The install line in the release notes must "
             "point at the repository this release was cut from, and that "
             "cannot be typed out by hand.")
print(m.group(1))
PY
)" || exit 1

# Uploading to a Release that already exists appends to it. `gh` does not
# refuse on its own, and the result is a release whose artifact list is a mix
# of two builds with one tag, which is exactly the state
# verify-release-artifacts.py cannot detect afterwards.
#
# The install line is resolved *before* this refusal, and repeated in it. That
# ordering is the fix for a repair being impossible: v0.36.0 shipped notes
# naming an asset that 404s, and the person repairing it cannot see what the
# script would publish, because this check exits first and the dry run below is
# unreachable once a release exists. Both of the two things the notes got wrong
# — the repository slug and the installer name — are pure derivations with no
# side effects, so computing them costs nothing and makes the refusal carry
# the line to check against.
if gh release view "$TAG" >/dev/null 2>&1; then
  echo "publish-release: a GitHub Release for ${TAG} already exists." >&2
  echo "  Either this is a re-run of a publish that succeeded, or someone else" >&2
  echo "  released this tag. Both need a human; refusing." >&2
  echo "  To see what is there:  gh release view ${TAG}" >&2
  echo "  The install line this script derives for ${TAG}:" >&2
  echo "    curl -LsSf https://github.com/${REPO_SLUG}/releases/download/${TAG}/${INSTALLER_NAME} | sh" >&2
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

and the release notes would tell a reader to install with:

    curl -LsSf https://github.com/${REPO_SLUG}/releases/download/${TAG}/${INSTALLER_NAME} | sh

Re-run with --confirm to actually publish${DRAFT_NOTE}.

The assets above come from dist-manifest.json, not from a directory listing,
so a stale file left over from a previous build cannot be uploaded by
accident. The install line is printed rather than assembled silently because
the repository slug and the installer name are the two things in the notes
that v0.36.0 got wrong, and both are now derived — the point of showing them
is that a reader can fetch the URL and see a 200 rather than trust it.
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

    curl -LsSf https://github.com/${REPO_SLUG}/releases/download/${TAG}/${INSTALLER_NAME} | sh

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
