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

pipeline {
    stages {
        // The prohibition, enforced, and first. This started out last on the
        // reasoning that it should not mask the gates before it — but the run
        // that taught me the ordering also showed the cost: stages
        // after a failure never execute, so a last-positioned policy check
        // silently stops running the moment anything else goes red, which is
        // exactly when its verdict is least likely to be missed. It is a
        // sub-second check, and it should fail before anyone waits ten minutes
        // for a build to learn that CI came back.
        stage("ci-policy") {
            sh("scripts/ci-policy.sh")
        }

        // The status table that M11/M13 completion is delegated to, checked
        // against the repository. Placed early for the same reason ci-policy is
        // first and not for the same cost: `cargo test --list` does compile, but
        // on the same profile and target dir the `test` stage uses, so the work
        // is cached rather than repeated — and it puts a falsified governance
        // document in front of the 15-minute PostgreSQL substrate and the
        // 30-minute adversarial stage instead of behind them.
        stage("gate-status") {
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
            // V1-C0. Every guard above checks code, tests or configuration.
            // None of them read `README.md`, `README-es.md` or the spec pack,
            // and the V1-C0 rebaseline found twelve stale or false claims
            // there by measurement: the broker's IPC protocol documented as
            // v2 while `PROTOCOL_VERSION` was 4, both READMEs marking M11 and
            // M12 done while the gates table had them NOT MET, and a
            // quick-start test count that had drifted by 174 without a single
            // failing check. A second copy of milestone status in the most-read
            // file in the repository is a second authority, and this stage is
            // where claim-vs-repository checks live.
            //
            // The falsifiability suite runs beside it, and it has already paid
            // for itself: two of its thirteen cases failed on its first run
            // because the guard had bound its spec-pack paths at import time,
            // so the vocabulary check was reading the real gates table instead
            // of the synthetic one the test had built. The guard was fixed,
            // not the test. That is the second time in this repository that a
            // "the test passes" moment was a test passing for the wrong
            // reason.
            sh("python3 scripts/check-doc-claims.py")
            sh("python3 tests/doc_claims_drift.py")
        }

        // The counts in three documents are transcribed from a run by hand, and
        // five numbers per profile is exactly the kind of thing that is wrong
        // without anybody noticing. This stage does not run the suite -- it
        // checks the arithmetic of two logs the release certification produced,
        // which is why it takes its inputs as arguments and is documented for
        // that rather than being wired to a path that does not exist on every
        // machine. `tests/test_counts_drift.py` is what makes it a guard rather
        // than a script: nine cases, of which eight must refuse.
        stage("test-counts") {
            sh("python3 tests/test_counts_drift.py")
        }

        // Cheap, and it fails first on the things a reviewer would notice.
        //
        // This stage ran `cargo clippy … -D warnings` and it was red on main:
        // eight errors in `asv-broker`, `could not compile … due to 8 previous
        // errors`. It had been red since `71e9096`, the commit that adopted
        // PipelineK as the CI authority, because the tree carries clippy debt
        // that `1e337d7` fixed at a baseline of 263 on purpose.
        //
        // `-D warnings` and that baseline are mutually exclusive: `-D warnings`
        // fails at one warning and the ratchet allows 263. The stage was
        // enforcing the destination as though it were the present, so nothing
        // ran it and nothing looked. `-D warnings` is B6 and B8, where the
        // count reaches zero; until then the declared policy is the ratchet, and
        // the stage measures that.
        //
        // What this gives up, stated plainly: a count can be satisfied by
        // trading one lint for another, which a lint-set diff would not allow.
        // That is a real weakening and it is the deal the baseline describes —
        // "hold the debt instead of describing it" — not a silent improvement.
        stage("static") {
            sh("cargo fmt --all -- --check")
            sh("python3 scripts/check-clippy-ratchet.py")
        }

        // Compiles the product and, as a side effect the adversarial harness
        // depends on, produces the real `asv-brokerd` and `asv` binaries it
        // attacks. The old workflow had to repeat this build in a second job
        // for exactly that reason.
        stage("build") {
            sh("cargo build --workspace --locked")
        }

        stage("test") {
            sh("cargo test --workspace --locked")
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
            sh("python3 tests/agent_contract.py")
        }

        // DX4. The exit test is that two independent channels install the
        // same product, so the check builds a release, installs it through
        // both entry points, and compares the bytes. It also runs the two
        // refusals UAT-DX-008 asks for: a bundle whose bytes were altered, and
        // a bundle carrying a binary no component declares.
        stage("distribution-channels") {
            sh("python3 tests/distribution_channels.py")
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

        // The M6 property against a real PostgreSQL. This is the stage that
        // silently skipped for three releases and let a write-as-read
        // authorization bypass ship green; `uat033-pg-substrate.sh run` sets
        // ASV_UAT033_REQUIRE=1, so a substrate that fails to come up is a
        // failure rather than a green skip.
        stage("integration-uat033") {
            timeout(time = 15, unit = "MINUTES") {
                sh("scripts/uat033-pg-substrate.sh run")
            }
        }

        // The harness, and the falsifiability suite in the same stage: a green
        // harness that cannot fail is precisely what the second command exists
        // to catch, so separating them would let the first vouch for the
        // second.
        stage("adversarial") {
            timeout(time = 30, unit = "MINUTES") {
                sh("python3 tests/adversarial/run_harness.py")
                sh("python3 tests/adversarial/test_falsifiability.py")
            }
        }

        // The spec pack is normative and imported byte-for-byte, so a modified
        // file is an unreviewed edit or a corrupted checkout.
        stage("spec-integrity") {
            sh("cd agent-secretless-vault-spec && sha256sum --check --strict SHA256SUMS")
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
            sh("python3 tools/check-gates.py")
        }

        // Everything R0 built, run on every change instead of when somebody
        // remembers.
        //
        // These four were hermetic, green and absent from this file. `r0_gate`
        // was worse — the whole block's exit gate, run by hand and by nothing
        // else — and a gate that runs only in the one place nobody looks is the
        // same object as no gate at all. That is the sentence this repository
        // already writes about its own checks, and it applied to itself.
        //
        // Only the hermetic four are here. `scripts/check-documented-install.py`
        // and `tests/r0_gate.py` are deliberately absent and that is a measured
        // gap, not an oversight: the first installs from a published release and
        // the second delegates to it, so neither can be green until v0.37.0
        // exists, and adding a permanently red stage would stop the run rather
        // than guard anything. They are listed in the roadmap row for R0 and are
        // the reason R0 is not closed.
        stage("truthfulness") {
            timeout(time = 45, unit = "MINUTES") {
                sh("python3 tests/provenance_falsification.py")
                sh("python3 tests/release_authority_drift.py")
                sh("python3 tests/documented_install_drift.py")
                sh("python3 tests/r0_gate_drift.py")
            }
        }
    }
}
