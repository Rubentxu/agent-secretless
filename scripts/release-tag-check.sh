#!/usr/bin/env bash
# Verify the tag being released is the tag dist will announce.
#
# dist takes the version from the workspace `Cargo.toml` and the release tag
# from git. Nothing makes those two agree, and when they disagree the failure
# is quiet: the build succeeds, the artifacts are named for one version, and
# they get uploaded under another. This check turns that into a red line
# before four minutes of compilation.
#
# Deliberately strict about *annotated* tags. A lightweight tag is a ref to a
# commit; an annotated one is an object with an author, a date and a message,
# which is what makes `git describe`, a changelog generator, and an auditor
# able to say what a release was without trusting whoever pushed the branch.

set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() { echo "release-tag-check: $*" >&2; exit 1; }

# The workspace version, read the same way cargo reads it. A regex rather than a
# TOML parse because python3 is not assumed present for a two-line read, and
# because the first `version` in a Cargo.toml is the one cargo uses.
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
[[ -n "$VERSION" ]] || fail "could not read a version from the workspace Cargo.toml"
[[ "$VERSION" != *"workspace"* ]] || fail "the root Cargo.toml does not pin a literal version"

TAG="v${VERSION}"

# 1. The tag has to exist locally.
git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null \
  || fail "no local tag ${TAG}. The workspace says ${VERSION}; run:
         git tag -a ${TAG} -m 'agent-secretless ${VERSION}'
         git push origin ${TAG}"

# 2. It has to be annotated, not lightweight.
git cat-file -t "refs/tags/${TAG}" | grep -q '^tag$' \
  || fail "${TAG} is a lightweight tag. A release tag records who released it and
         when, and a lightweight ref does not:
         git tag -d ${TAG} && git tag -a ${TAG} -m 'agent-secretless ${VERSION}'"

# 3. It has to point at HEAD. A release built from a commit the tag does not
#    name is a release nobody can reproduce from the tag.
HEAD_SHA="$(git rev-parse HEAD)"
TAG_SHA="$(git rev-list -n1 "${TAG}")"
[[ "$HEAD_SHA" == "$TAG_SHA" ]] \
  || fail "${TAG} points at ${TAG_SHA:0:12} but HEAD is ${HEAD_SHA:0:12}.
         Either check out the tagged commit, or move the tag:
           git tag -f -a ${TAG} -m 'agent-secretless ${VERSION}'"

# 4. It has to be pushed. `gh release create` uploads to an existing tag's
#    release; creating a Release for a tag the remote has never seen produces a
#    link that 404s for everyone except the machine that made it.
if git ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "release-tag-check: ${TAG} is annotated, matches HEAD, and is pushed"
else
  fail "${TAG} exists locally but is not on origin.
         git push origin ${TAG}
         A GitHub Release for a tag the remote has never seen links to nothing."
fi
