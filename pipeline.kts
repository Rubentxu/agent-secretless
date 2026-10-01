// CI authority for agent-secretless.
//
// PipelineK is the only definition of what this project's gates are. GitHub
// Actions was removed; `scripts/ci-policy.sh` fails the run if a workflow
// reappears, so the removal holds rather than merely being noted.
//
// Migrated from .github/workflows/verify.yml. Every command below was observed
// in the repository — no invented wrappers, no command that exists only to
// fill a template. The stages follow observable responsibility, not the old
// job count: a stage exists because it separates a budget, a failure
// semantics, or a runtime that nothing else needs.

// PipelineK runs every `sh` step in a throwaway per-step workspace, not in the
// directory the command was launched from, so a bare `cargo fmt` finds no
// Cargo.toml. `user.dir` is the JVM's working directory — the repository root
// whoever ran `pipelinek run pipeline.kts` — which keeps the pipeline portable
// instead of baking one machine's absolute path into a committed file.
val repo = System.getProperty("user.dir")

pipeline {
    stages {
        // The prohibition, enforced, and first. This started out last on the
        // reasoning that it should not mask the gates before it — but the run
        // that taught me the workspace layout also showed the cost: stages
        // after a failure never execute, so a last-positioned policy check
        // silently stops running the moment anything else goes red, which is
        // exactly when its verdict is least likely to be missed. It is a
        // sub-second check, and it should fail before anyone waits ten minutes
        // for a build to learn that CI came back.
        stage("ci-policy") {
            dir(repo) {
                sh("scripts/ci-policy.sh")
            }
        }

        // The status table that M11/M13 completion is delegated to, checked
        // against the repository. Placed early for the same reason ci-policy is
        // first and not for the same cost: `cargo test --list` does compile, but
        // on the same profile and target dir the `test` stage uses, so the work
        // is cached rather than repeated — and it puts a falsified governance
        // document in front of the 15-minute PostgreSQL substrate and the
        // 30-minute adversarial stage instead of behind them.
        stage("gate-status") {
            dir(repo) {
                sh("python3 scripts/check-gate-status.py")
                sh("python3 tests/gate_status_drift.py")
                sh("python3 tests/check_gates_claims.py")
                // SDDK derives a project's identity from the git remote URL,
                // and a checkout pointing at a different repository resolves
                // to a different project with an empty ledger — where a write
                // succeeds with no warning at all. Measured 2026-10-01;
                // backlog bl-bl-01M3RYX76R000387QXS2QR7NC0, P0. The guard is
                // in the same stage as the other claim-vs-repository checks
                // because that is what it is: a claim in this repository that
                // the repository can contradict. The falsifiability suite runs
                // beside it for the same reason it does for the others — a
                // guard that cannot fail is not a guard, and this repository
                // has now found three that could not.
                sh("python3 scripts/check-project-identity.py")
                sh("python3 tests/project_identity_drift.py")
            }
        }

        // Cheap, and it fails first on the things a reviewer would notice.
        stage("static") {
            dir(repo) {
                sh("cargo fmt --all -- --check")
                sh("cargo clippy --workspace --all-targets --locked -- -D warnings")
            }
        }

        // Compiles the product and, as a side effect the adversarial harness
        // depends on, produces the real `asv-brokerd` and `asv` binaries it
        // attacks. The old workflow had to repeat this build in a second job
        // for exactly that reason.
        stage("build") {
            dir(repo) {
                sh("cargo build --workspace --locked")
            }
        }

        stage("test") {
            dir(repo) {
                sh("cargo test --workspace --locked")
            }
        }

        // The M6 property against a real PostgreSQL. This is the stage that
        // silently skipped for three releases and let a write-as-read
        // authorization bypass ship green; `uat033-pg-substrate.sh run` sets
        // ASV_UAT033_REQUIRE=1, so a substrate that fails to come up is a
        // failure rather than a green skip.
        stage("integration-uat033") {
            dir(repo) {
                timeout(time = 15, unit = "MINUTES") {
                    sh("scripts/uat033-pg-substrate.sh run")
                }
            }
        }

        // The harness, and the falsifiability suite in the same stage: a green
        // harness that cannot fail is precisely what the second command exists
        // to catch, so separating them would let the first vouch for the
        // second.
        stage("adversarial") {
            dir(repo) {
                timeout(time = 30, unit = "MINUTES") {
                    sh("python3 tests/adversarial/run_harness.py")
                    sh("python3 tests/adversarial/test_falsifiability.py")
                }
            }
        }

        // The spec pack is normative and imported byte-for-byte, so a modified
        // file is an unreviewed edit or a corrupted checkout.
        stage("spec-integrity") {
            dir(repo) {
                sh("cd agent-secretless-vault-spec && sha256sum --check --strict SHA256SUMS")
            }
        }

        // Enforced, not advisory. This used to record its exit code instead of
        // failing the run, justified by UAT gate-map defects that were tracked
        // in the backlog. Those defects are resolved: `check-gates.py` reports
        // 0 hard defects and 0 warnings with 34/34 UAT carrying a gate and 0
        // orphaned. An exception that outlives its justification stops guarding
        // while still looking like a gate, so it was removed rather than
        // reworded. Future gate-map drift turning this red is the intended
        // behaviour of a gate, not a reason to reintroduce the exception.
        stage("spec-gates") {
            dir(repo) {
                sh("python3 tools/check-gates.py")
            }
        }
    }
}
