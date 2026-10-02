#!/usr/bin/env bash
# Make the release archives byte-reproducible, after dist's packaging.
#
# Measured on this repository (backlog bl-bl-01M3YN9BHE000387XAKRC47X00):
# two consecutive `dist build` runs on the same machine and path produce
# different archives, because the tar embeds packaging-time mtimes in every
# header. dist 0.32.0 ignores SOURCE_DATE_EPOCH (also measured), so the
# normalization has to happen after packaging, before anything that pins
# the bytes: the checksums, the sha256.sum line, and the signatures.
#
# Touchpoints kept coherent here: the archive, its `.sha256` sidecar, and
# its line in `sha256.sum`. The sign stage runs after this one and signs
# the normalized bytes.

set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DISTRIB="target/distrib"
MANIFEST="$DISTRIB/dist-manifest.json"
# The epoch is not "now" and not HEAD: it is the release commit's timestamp,
# taken from the tag the manifest announces. Building the same release from
# any later checkout must produce the same bytes, so the anchor is what the
# release IS (its tag), not where the builder happens to be.
ANNOUNCEMENT_TAG="$(python3 -c "
import json, pathlib, sys
m = json.loads(pathlib.Path('$MANIFEST').read_text())
print(m.get('announcement_tag', ''))
")"
if [[ -n "$ANNOUNCEMENT_TAG" ]] && git rev-parse "${ANNOUNCEMENT_TAG}^{commit}" >/dev/null 2>&1; then
  EPOCH="$(git log -1 --format=%ct "${ANNOUNCEMENT_TAG}^{commit}")"
else
  # No tag in this checkout (building from an untagged worktree): fall back
  # to HEAD and say so - the bytes are then deterministic per checkout, not
  # per release, and the difference is visible in this stage's output.
  EPOCH="$(git log -1 --format=%ct HEAD)"
  echo "normalize-release: no tag resolved from the manifest; anchoring to HEAD (epoch=$EPOCH)" >&2
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo "normalize-release: $MANIFEST is missing. Run dist build first." >&2
  exit 1
fi

command -v zstd >/dev/null 2>&1 || { echo "normalize-release: zstd is not installed" >&2; exit 1; }

mapfile -t ARCHIVES < <(python3 - "$MANIFEST" <<'PY'
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
for release in manifest.get("releases", []):
    for name in release.get("artifacts", []):
        if name.endswith(".tar.zst"):
            print(name)
PY
)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for name in "${ARCHIVES[@]}"; do
  archive="$DISTRIB/$name"
  if [[ ! -f "$archive" ]]; then
    echo "normalize-release: $name listed by the manifest is missing" >&2
    exit 1
  fi

  # Extract, repack deterministic, recompress deterministic. GNU tar's
  # --sort=name + --mtime + --owner/--group/--numeric-owner remove the
  # three sources of variance the original archive carried; zstd -T1
  # removes thread-count scheduling from the compression. Level 19 is
  # fixed: the same bytes through the same level are the same output.
  stage="$WORK/${name%.tar.zst}"
  mkdir -p "$stage"
  tar --zstd -xf "$archive" -C "$stage"
  (cd "$stage" && tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 \
      --numeric-owner -cf - .) \
    | zstd -q -T1 -19 -o "$WORK/$name.new"

  if cmp -s "$archive" "$WORK/$name.new"; then
    echo "normalize-release: $name already normalized"
    continue
  fi

  new_digest="$(sha256sum "$WORK/$name.new" | cut -d' ' -f1)"
  mv "$WORK/$name.new" "$archive"
  printf '%s  %s\n' "$new_digest" "$name" > "$DISTRIB/$name.sha256"

  # Rewrite this archive's line in sha256.sum, preserving every other
  # artifact's line exactly as dist wrote it.
  python3 - "$DISTRIB/sha256.sum" "$name" "$new_digest" <<'PY'
import pathlib, sys
sums = pathlib.Path(sys.argv[1])
name, digest = sys.argv[2], sys.argv[3]
lines = sums.read_text().splitlines(keepends=True)
out = []
for line in lines:
    if line.endswith(f"  {name}\n") or line.rstrip("\n").endswith(f"  {name}"):
        out.append(f"{digest}  {name}\n")
    else:
        out.append(line)
sums.write_text("".join(out))
PY
  echo "normalize-release: $name normalized (epoch=$EPOCH, sha256=$new_digest)"
done

# Determinism self-check: normalizing an already-normalized archive must
# be a no-op. Re-run the same transformation and compare.
for name in "${ARCHIVES[@]}"; do
  stage="$WORK/check-${name%.tar.zst}"
  mkdir -p "$stage"
  tar --zstd -xf "$DISTRIB/$name" -C "$stage"
  (cd "$stage" && tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 \
      --numeric-owner -cf - .) \
    | zstd -q -T1 -19 -o "$WORK/check.tar.zst"
  cmp "$DISTRIB/$name" "$WORK/check.tar.zst" \
    || { echo "normalize-release: self-check FAILED for $name — normalization is not deterministic" >&2; exit 1; }
  echo "normalize-release: self-check deterministic for $name"
done
