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

val repo = System.getProperty("user.dir")

pipeline {
    stages {
        // The same prohibition as the gates run, repeated because this file
        // runs separately and a stage that is only in one of the two files is
        // a stage that can be missing exactly when someone is in a hurry.
        stage("ci-policy") {
            dir(repo) {
                sh("scripts/ci-policy.sh")
            }
        }

        // Everything cheap, before anything expensive.
        stage("preflight") {
            dir(repo) {
                sh("python3 scripts/check-release-config.py")
                sh("python3 scripts/check-gate-status.py")
                // `dist plan` is the exact same code path the release CI would
                // run, minus the compilation. It resolves the tag, the targets
                // and the artifact list from the real configuration, so a
                // config that cannot produce a release fails in seconds here
                // rather than after the build.
                sh("dist plan --output-format=json > /dev/null")
            }
        }

        // The tag has to exist and has to point at the commit being released.
        // Checked rather than assumed, because `dist` reads the version from
        // the workspace `Cargo.toml` and the tag from git, and nothing makes
        // those two agree.
        stage("tag") {
            dir(repo) {
                sh("scripts/release-tag-check.sh")
            }
        }

        // The build. Slow by construction: `--profile=dist` is a release build
        // with thin LTO, and `codegen-units = 1` in the inherited release
        // profile makes it slower still. That is the cost of shipping the
        // binary the pipeline tested rather than a differently-tuned one.
        stage("build") {
            dir(repo) {
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
        }

        // The artifacts are only worth uploading if they are internally
        // consistent, and "consistent" here means three separate things that
        // can each be wrong on their own: every archive the manifest promises
        // exists, every checksum verifies against the bytes actually built, and
        // no archive is empty. A release that fails any of these is a release
        // whose installer hands users a truncated download.
        stage("verify-artifacts") {
            dir(repo) {
                sh("scripts/verify-release-artifacts.py")
                // The product boundary, now against real bytes rather than a
                // plan. The stage above asks "are the checksums right for these
                // files"; this one asks "are these the right files", and the
                // two are not substitutes — a tarball containing exactly the
                // right binaries plus one forbidden one has perfect checksums.
                sh("python3 packaging/stage-bundle.py --check")
                sh("python3 tests/distribution_bundle.py")
            }
        }

        // Sign before upload. sha256.sum (which pins every artifact by
        // digest) and each archive get a minisign signature; the public key
        // is staged so a verifier can check without trusting this repo. The
        // stage refuses to run without a key: an unsigned artifact set must
        // fail loudly here rather than publish quietly.
        stage("sign") {
            dir(repo) {
                sh("scripts/sign-release-artifacts.sh")
            }
        }

        // Uploading is a separate, explicit step rather than part of the build.
        // `dist build` writing files into target/distrib is reversible;
        // creating a GitHub Release that other people can already see is not,
        // and the two should not share a failure domain. Nothing above this
        // line touches the network.
        stage("publish") {
            dir(repo) {
                sh("scripts/publish-release.sh")
            }
        }
    }
}
