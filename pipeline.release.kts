// The release train — the expensive, deliberate half of releasing.
//
// Deliberately a *separate* file from `pipeline.kts`. The gates run on every
// change; this runs when someone is cutting a release, and it does a release
// build of every binary with LTO, which is minutes of work nobody should pay
// for on an ordinary edit. What that split buys is not just time: the cheap
// `check-release-config.py` gate in `pipeline.kts` can then keep the release
// configuration honest on every commit, so the expensive half never discovers
// a stale config at the moment it is trying to publish.
//
// There is no GitHub Actions workflow here and there is not going to be one.
// `scripts/ci-policy.sh` fails any pipeline run that finds one, and the release
// does not need it: dist's CI backend would exist to build on hosted runners
// and upload the results, and every step below runs on the machine doing the
// releasing, with `gh` doing the upload. See `docs/distribution.md`.
//
// The steps are ordered so that the cheap, decisive checks come first. A
// version mismatch is caught before four minutes of compilation, not after.

pipeline {
    stages {
        // The same prohibition as the gates run, repeated because this file
        // runs separately and a stage that is only in one of the two files is
        // a stage that can be missing exactly when someone is in a hurry.
        stage("ci-policy") {
            sh("scripts/ci-policy.sh")
        }

        // Everything cheap, before anything expensive.
        stage("preflight") {
            sh("python3 scripts/check-release-config.py")
            sh("python3 scripts/check-gate-status.py")
            // The published skill is part of the product, so a release that
            // cannot see it is not a release that can be verified. The suite
            // fails rather than skips when the skill is absent — a skip here
            // would let the one thing R0.3 exists to establish be decided by
            // whether this machine happened to have a sibling checkout.
            //
            // It is also a network step, and everything below this line is
            // not. It sits here, in preflight, for that reason: a release that
            // discovers at the publish stage that its own agent entry point is
            // unpublished has already created a Release other people can
            // fetch.
            sh("if [ ! -d ../agent-skill/skills/agent-secretless ]; then git clone --depth 1 https://github.com/Rubentxu/agent-skill.git ../agent-skill; fi")
            sh("python3 tests/skill_contract.py")
            // R0's own exit gate. It re-derives all four of R0's conditions
            // from the repository rather than reading a status cell, and it
            // runs the provenance campaign, so it costs about a minute and
            // buys the statement "R0 is closed" backed by the same evidence
            // that closed it.
            sh("python3 tests/r0_gate.py")
            // R0.1 on its own, over every release rather than the one being cut.
            //
            // `r0_gate.py` above answers "is the roadmap honest"; this answers
            // "does any published release name a commit outside the branch, or a
            // tag that is not annotated, or a tag the remote disagrees with".
            // It held on 2026-10-07 — 53 release tags, all annotated, all
            // ancestors of `main` — but nothing was reading it, so it was a
            // sentence rather than a property. Each of its four rows has a
            // falsification in tests/release_authority_drift.py, including two
            // that need a real remote and get a local bare repository over
            // `file://` rather than a network.
            //
            // It is here, in preflight, for the same reason the skill check is:
            // a release that discovers at the publish stage that its own tag is
            // untrustworthy has already created a Release other people can fetch.
            sh("python3 scripts/check-release-authority.py")
            // `dist plan` is the exact same code path the release CI would
            // run, minus the compilation. It resolves the tag, the targets
            // and the artifact list from the real configuration, so a
            // config that cannot produce a release fails in seconds here
            // rather than after the build.
            sh("dist plan --output-format=json > /dev/null")
        }

        // The tag has to exist and has to point at the commit being released.
        // Checked rather than assumed, because `dist` reads the version from
        // the workspace `Cargo.toml` and the tag from git, and nothing makes
        // those two agree.
        stage("tag") {
            sh("scripts/release-tag-check.sh")
        }

        // The build. Slow by construction: `--profile=dist` is a release build
        // with thin LTO, and `codegen-units = 1` in the inherited release
        // profile makes it slower still. That is the cost of shipping the
        // binary the pipeline tested rather than a differently-tuned one.
        stage("build") {
            timeout(time = 60, unit = "MINUTES") {
                sh("dist build")
            }
            // `dist build` does not write the manifest. Only `dist manifest`
            // does, and the manifest is the list of what the release is
            // supposed to contain — which is the thing the next stage needs
            // in order to check that the build actually produced it. A
            // verifier that regenerated the manifest itself would be
            // deriving its own expectations from the same tool that built
            // the artifacts, so the manifest is produced here, separately,
            // and the next stage only reads it.
            //
            // The redirect writes to a temp path and renames: dist *reads*
            // this same file as its previous-run input, and truncating it
            // in place races the read — an empty file is a parse failure,
            // and a diagnostic JSON is what lands when dist notices. Same
            // defect class the publish script's own header describes.
            sh("mkdir -p target/distrib")
            sh("dist manifest --output-format=json --artifacts=all > target/distrib/dist-manifest.json.tmp && mv target/distrib/dist-manifest.json.tmp target/distrib/dist-manifest.json")
        }

        // Make the archives byte-reproducible before anything pins them:
        // dist embeds packaging-time mtimes (measured, backlog
        // bl-bl-01M3YN9BHE000387XAKRC47X00; SOURCE_DATE_EPOCH is ignored),
        // so the archives are repacked deterministically against the
        // release commit's timestamp, with checksums and sha256.sum kept
        // coherent.
        //
        // This stage used to run *after* verify-artifacts, so the gate
        // verified bytes that this stage then replaced — its own comment
        // claimed "Verify-artifacts then checks the normalized bytes",
        // which the stage order made false. The order is now normalize,
        // repair, then verify, so what the gate checks is what gets signed
        // and published.
        stage("normalize") {
            sh("scripts/normalize-release-archives.sh")
            // dist bakes each archive's sha256 into the installer, at build
            // time. Normalization rewrote the archive afterwards, so that
            // constant describes bytes the release does not ship and every
            // install dies at `ERROR: checksum mismatch`. Six consecutive
            // releases (v0.31.0 … v0.36.0) shipped exactly that, and every
            // checksum gate passed, because they all compared checksums against
            // files in target/distrib and none of them opened the installer.
            //
            // It runs here rather than inside normalize because normalize's
            // declared touchpoints are the archive, its sidecar and its
            // sha256.sum line — adding a fourth silently to a script whose
            // header enumerates three is how the omission happened in the first
            // place. As its own stage it is visible in the run, and
            // verify-release-artifacts.py checks the result rather than
            // trusting the stage to have done its job.
            sh("python3 scripts/repair-installer-checksums.py")
        }

        // The artifacts are only worth uploading if they are internally
        // consistent, and "consistent" here means three separate things that
        // can each be wrong on their own: every archive the manifest promises
        // exists, every checksum verifies against the bytes actually built, and
        // no archive is empty. A release that fails any of these is a release
        // whose installer hands users a truncated download.
        stage("verify-artifacts") {
            sh("scripts/verify-release-artifacts.py")
            // The product boundary, now against real bytes rather than a
            // plan. The stage above asks "are the checksums right for these
            // files"; this one asks "are these the right files", and the
            // two are not substitutes — a tarball containing exactly the
            // right binaries plus one forbidden one has perfect checksums.
            sh("python3 packaging/stage-bundle.py --check")
            sh("python3 tests/distribution_bundle.py")
        }

        // The product boundary has to be inside the signed authority before the
        // sign stage runs. `dist` does not know distribution/manifest.toml
        // exists, so `sha256.sum` did not cover it, and the installer reads the
        // manifest to decide what to install — meaning the signature could be
        // perfectly valid over a set of bytes while the boundary deciding what
        // ships was not among them. This stage publishes the manifest into the
        // release directory and writes its digest into `sha256.sum`; the next
        // stage signs the result.
        stage("pin-manifest") {
            sh("python3 scripts/pin-manifest-into-checksums.py")
        }

        // Sign before upload. sha256.sum (which pins every artifact by
        // digest) and each archive get a minisign signature; the public key
        // is staged so a verifier can check without trusting this repo. The
        // stage refuses to run without a key: an unsigned artifact set must
        // fail loudly here rather than publish quietly.
        stage("sign") {
            sh("scripts/sign-release-artifacts.sh")
        }

        // Uploading is a separate, explicit step rather than part of the build.
        // `dist build` writing files into target/distrib is reversible;
        // creating a GitHub Release that other people can already see is not,
        // and the two should not share a failure domain. Nothing above this
        // line touches the network.
        stage("publish") {
            sh("scripts/publish-release.sh")
        }

        // The documented install, run as the document writes it.
        //
        // This is the last stage because it is the only one that consumes the
        // published Release rather than the local build, so before publish it
        // would be testing the previous release and calling it this one.
        //
        // It exists because five defects in one cycle had the same shape — a
        // gate exercised a component and the command a person actually types
        // was executed by nothing. Six releases shipped an installer that
        // refused its own archive, and `scripts/install.sh` cannot be run by
        // pipe at all because it locates `install.py` through `$0`, which is
        // `sh` when the script arrives on stdin. The 46-check provenance
        // campaign invoked `install.py` directly with its own fixtures and
        // never noticed.
        //
        // It reads the command out of README.md rather than being handed one.
        // A gate that hardcodes the command it runs is a gate about the
        // hardcoded command, and when the README moves the gate would go on
        // testing yesterday's entry point.
        stage("documented-install") {
            timeout(time = 30, unit = "MINUTES") {
                sh("python3 scripts/check-documented-install.py")
            }
        }
    }
}
