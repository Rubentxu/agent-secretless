#!/usr/bin/env bash
# Sign the built release artifacts with the project's minisign key.
#
# Position in the release train: after verify-artifacts, before publish.
# What gets signed is `sha256.sum` — which pins every artifact by digest —
# plus each archive the manifest lists, so a downloader can check a single
# signature against the checksum file, or the archive bytes directly.
# The public key is staged beside the artifacts as `release.pub` so a
# verifier can check the signature without trusting this repository: the
# key identifies the signer, and the fingerprint should be compared
# against a channel that is not this repo.
#
# The key lives OUTSIDE the repository, by default in
#   ~/.config/asv/release-keys/v0-release.key
# (override with ASV_RELEASE_SIGNING_KEY). A secret key inside the repo
# would be one `git add -f` away from publication, and a signature whose
# signing key ships with the thing it signs attests to nothing.
#
# Password policy, stated honestly: the v0 key is generated passwordless
# (`rsign generate -W`) and protected by filesystem permissions alone —
# the key file is 0600 and its directory 0700. That is a deliberate
# first-iteration trade for a single-maintainer release process, and it
# is recorded as an honest gap: re-key with a passphrase before 1.0.
# rsign reads `RSIGN_PASSWORD` for a password-protected key when that
# variable is set, so the upgrade path needs no script change.

set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KEY="${ASV_RELEASE_SIGNING_KEY:-$HOME/.config/asv/release-keys/v0-release.key}"
DISTRIB="target/distrib"
MANIFEST="$DISTRIB/dist-manifest.json"
RSIGN="${ASV_RSIGN:-rsign}"
command -v "$RSIGN" >/dev/null 2>&1 || RSIGN="$HOME/.cargo/bin/rsign"

if [[ ! -x $(command -v "$RSIGN" 2>/dev/null || echo "$RSIGN") ]]; then
  echo "sign-release: rsign is not installed. Install with: cargo install rsign2" >&2
  exit 1
fi
if [[ ! -f "$KEY" ]]; then
  echo "sign-release: no signing key at $KEY." >&2
  echo "  Generate one: rsign generate -W -p <pub> -s <sec> -c 'agent-secretless release key'" >&2
  echo "  Signing is a release-train stage, not an optional extra: an unsigned" >&2
  echo "  artifact set must fail loudly here rather than publish quietly." >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "sign-release: $MANIFEST is missing. Run dist build first." >&2
  exit 1
fi

# Sign sha256.sum plus every archive-class artifact the manifest lists.
# Checksum files and text metadata are not signed individually: sha256.sum
# already pins them, and one signature over that file is the anchor.
python3 - "$MANIFEST" <<'PY' | sort -u > /tmp/sign-targets.$$
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
seen = set()
print("sha256.sum", file=sys.stdout)
for release in manifest.get("releases", []):
    for name in release.get("artifacts", []):
        if name in seen or name in ("sha256.sum", "source.tar.gz"):
            continue
        seen.add(name)
        if name.endswith((".zst", ".gz", ".exe", ".msi", ".deb", ".rpm")):
            print(name, file=sys.stdout)
PY
mapfile -t TARGETS < /tmp/sign-targets.$$
rm -f /tmp/sign-targets.$$

# Stage the public key BEFORE signing: the sign-then-verify loop below
# checks every fresh signature against this staged copy, so it must exist
# first. Same bytes as the repo's packaging/release.pub, so a verifier can
# fetch both from the release without trusting either to describe the other.
cp packaging/release.pub "$DISTRIB/release.pub"

FAILED=0
for name in "${TARGETS[@]}"; do
  file="$DISTRIB/$name"
  sig="$file.minisig"
  if [[ ! -f "$file" ]]; then
    echo "sign-release: $name listed by the manifest is missing; refusing to sign a partial set" >&2
    FAILED=1
    continue
  fi
  "$RSIGN" sign -W -s "$KEY" -x "$sig" "$file"
  # Sign-then-verify: a signature this script just produced must verify
  # against the staged public key, or the staging is broken and the
  # release must not continue.
  if "$RSIGN" verify -p "$DISTRIB/release.pub" -x "$sig" "$file" >/dev/null; then
    echo "sign-release: $name signed (verified)"
  else
    echo "sign-release: signature for $name does NOT verify against the staged public key" >&2
    FAILED=1
  fi
done

if [[ $FAILED -ne 0 ]]; then
  echo "sign-release: FAILED" >&2
  exit 1
fi
echo "sign-release: ${#TARGETS[@]} artifacts signed and verified"
