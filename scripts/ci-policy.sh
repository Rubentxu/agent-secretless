#!/usr/bin/env bash
# Fails when GitHub Actions reappears in this repository.
#
# GitHub Actions was removed as a CI authority: `pipeline.kts` run through
# PipelineK is the only definition of what this project's gates are. Deleting
# `.github/workflows/verify.yml` alone would not hold — a future contributor
# adds a workflow, it never runs on anyone's machine, and the divergence is
# invisible until something breaks. This guard is what makes the prohibition
# real rather than aspirational.
#
# It is a stage in `pipeline.kts`, so it runs on every gate invocation and a
# reintroduced workflow is a red pipeline, not a review comment nobody reads.
#
# Exit 0 when no workflow is present, 1 with an explanation when one is.

set -euo pipefail

WORKFLOW_DIR=".github/workflows"

if [[ ! -d "$WORKFLOW_DIR" ]]; then
  echo "ci-policy: no $WORKFLOW_DIR; GitHub Actions is absent, as required"
  exit 0
fi

# `-A` so a directory holding only editor droppings or a .gitkeep does not read
# as "a workflow exists". Any real file is a violation.
present="$(find "$WORKFLOW_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null || true)"

if [[ -z "$present" ]]; then
  echo "ci-policy: $WORKFLOW_DIR exists but holds no workflow; nothing to prohibit"
  exit 0
fi

cat >&2 <<EOF
ci-policy: GitHub Actions is prohibited in this repository.

These workflow files are present:
$present

pipeline.kts, run through PipelineK, is the CI authority. A workflow here
would define a second, divergent set of gates that never runs on a
contributor's machine — the exact condition this guard exists to prevent.

Move the gate into pipeline.kts. If you need a remote trigger for a
matrix or a release train, say so explicitly rather than reintroducing a
workflow by default.
EOF
exit 1
