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
                // The release configuration, checked against the repository.
                // Same reasoning as the two lines above and the same stage,
                // because it is the same kind of check: a claim about what
                // ships, which the repository can contradict. `ci-policy.sh`
                // fails when a workflow *file* exists, which catches the
                // outcome but not the cause — dist writes that file only when
                // somebody runs `dist init` or `dist generate`, so a
                // `ci = ["github"]` added to dist-workspace.toml sits in the
                // tree producing no failing test until the command that acts
                // on it. This guard also compares the systemd unit's ExecStart
                // against the installer's `install-path`, which is a real
                // disagreement that already happened once and would have
                // shipped a service that installs cleanly and never starts.
                // Cheap: it reads three files and no tool is required.
                sh("python3 scripts/check-release-config.py")
                // UAT-DX-001. The product boundary is a gate, not a convention:
                // `asv-vault-tool` is declared in its own source as an
                // exerciser for the adversarial harness, and under the previous
                // arrangement it would have been packaged for users because
                // dist ships whatever `[[bin]]` the workspace contains. The
                // archive inspection is skipped here and enforced in
                // pipeline.release.kts, because there is no built artifact in a
                // gate run — and a check that reports success because it had
                // nothing to look at is the failure this repository keeps
                // finding.
                sh("python3 tests/distribution_bundle.py")
                // The falsifiability suite runs beside it for the same reason
                // it does for the others. It has already earned its place: it
                // caught a `--root` override that applied to two of the three
                // paths the guard reads, which had three of these cases
                // passing against the real checkout instead of against the
                // broken tree they had built.
                sh("python3 tests/release_config_drift.py")
                // DX1. The bundle gate above asks "what is in the archive".
                // This asks the question it cannot see: whether anything a
                // user is *told to run* names a component the manifest
                // excludes. `install-broker-service.sh` printed three setup
                // steps whose first was `asv-vault-tool create` — a binary
                // the manifest classifies test-harness and the bundle does
                // not contain. Every gate in this file was green while the
                // installation instructions were unfollowable.
                sh("python3 tests/install_path_contract.py")
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

        // DX2. Runs the built binary, not the test harness: the goldens pin
        // the shape of the document an agent actually receives, and a golden
        // produced by calling the code directly would keep passing after the
        // wiring between them broke.
        //
        // The goldens pin shape and the property tests pin meaning. Neither
        // catches what the other catches — the property tests say nothing
        // about a key that *moved*, and a golden cannot say that a value is
        // the wrong one. An agent contract is consumed by name, so both are
        // needed.
        // Runs after `build` because stages execute in declaration order.
        // There is no `dependsOn` in this DSL: `StageSpec` carries steps,
        // options, environment, directives and a post-condition, and no
        // dependency field. A `dependsOn("build")` here does not fail loudly
        // at review time — it fails the first time anybody runs the pipeline,
        // which is why this line existed unrun.
        stage("agent-contract") {
            dir(repo) {
                sh("python3 tests/agent_contract.py")
            }
        }

        // DX4. The exit test is that two independent channels install the
        // same product, so the check builds a release, installs it through
        // both entry points, and compares the bytes. It also runs the two
        // refusals UAT-DX-008 asks for: a bundle whose bytes were altered, and
        // a bundle carrying a binary no component declares.
        stage("distribution-channels") {
            dir(repo) {
                sh("python3 tests/distribution_channels.py")
            }
        }

        // Does the published skill still describe this build? The skill lives
        // in another repository (ADR-05), so this stage is cross-repository.
        //
        // The exit code is the design. `skill_contract.py` exits 77 when it
        // cannot find a skill checkout, and that is translated into a loud
        // skip rather than into a pass or a failure: a machine without the
        // sibling checkout genuinely cannot run the comparison, and a stage
        // that fails there teaches people to delete the stage. The stage
        // reports 0 only after saying out loud that it did not compare
        // anything.
        //
        // Written with `sh` and nothing else because `sh`, `dir` and
        // `timeout` are the only constructs this file already proves; an
        // unproven DSL call in a pipeline file is a build that stops working
        // for everyone the first time it is parsed, and this file is parsed.
        stage("skill-contract") {
            dir(repo) {
                sh(
                    """
                    set -u
                    set +e
                    python3 tests/skill_contract.py
                    code=${'$'}?
                    set -e
                    if [ "${'$'}code" = "77" ]; then
                      echo "skill-contract SKIPPED: no agent-secretless checkout found."
                      echo "  Set ASV_SKILL_DIR to the skills/agent-secretless directory"
                      echo "  of a Rubentxu/agent-skill checkout to compare the skill."
                      exit 0
                    fi
                    exit "${'$'}code"
                    """.trimIndent()
                )
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
