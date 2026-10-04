//! The operator's worker declaration file.
//!
//! `Request::RunIsolated` is a verb with nothing to run. `BrokerState::workers`
//! starts empty, and empty is a refusal rather than a gap — but a refusal for
//! every call is not a product feature, it is an unimplemented one. This module
//! is how an operator hands a broker the set of things it may run.
//!
//! # JSON, because the route table already is
//!
//! `--connect-routes` takes the same kind of document — an operator declaring
//! an allow-list — and it is JSON deserialized by `serde_json`. Two files that
//! answer the same question in the same way are one question with one answer.
//! TOML would have been the prettier choice and it is the format of
//! `distribution/manifest.toml`, but no TOML crate is in the dependency tree,
//! and adding a parser to a product whose recent work was establishing a
//! verified dependency lockfile and a signed SBOM is a supply-chain decision
//! rather than a formatting one. It is not a decision to make in passing.
//!
//! # Why the file holds no secret
//!
//! `WorkerTemplate` carries a `Redactor`, and a `Redactor` is built from secret
//! bytes. It would have been possible to let the file list them, and it would
//! have been a plaintext secret on disk in every deployment that used it — the
//! thing this product exists to prevent.
//!
//! So the file never names a secret *value*, and there is no `redact` key. The
//! runtime resolves the injected credential after the template is built and
//! seeds the redactor from its own resolution, which makes the property
//! structural instead of a rule someone has to remember. Every other key is
//! validated rather than ignored, because a misspelled `seccomp` that quietly
//! became the default would be a weaker sandbox than the file appears to
//! describe.
//!
//! # Fail-closed reading
//!
//! Every failure refuses the whole file. A name declared twice, a relative
//! binary, an egress the runtime will reject at every spawn: all of them are
//! errors here, because half a registry is not a smaller authority — it is a
//! different one from the one the operator wrote.

use std::path::PathBuf;

use serde::Deserialize;

use crate::isolated_exec::{
    EgressPolicy, LandlockProfile, Redactor, SeccompProfile, SecretInjectionPlan, WorkerRegistry,
    WorkerTemplate,
};

/// The file as written, before any of it is trusted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    worker: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    binary: PathBuf,
    #[serde(default)]
    arguments: Vec<String>,
    /// `deny` is the only enforceable value. `allow` exists in the type and
    /// `worker::spawn` refuses it, so the file does not offer it: a value the
    /// runtime rejects on every call is a trap for the operator, not a feature.
    #[serde(default = "deny")]
    egress: String,
    /// `closed` is the only production profile; `passthrough` is debug-only and
    /// the runtime refuses it. Same reasoning.
    #[serde(default = "closed")]
    seccomp: String,
    /// Paths the worker may read. Absent means deny everything.
    #[serde(default)]
    read: Vec<PathBuf>,
    #[serde(default)]
    write: Vec<PathBuf>,
    /// Environment variable the credential is injected into. Absent for a
    /// worker that receives none.
    #[serde(default)]
    secret_env: Option<String>,
}

fn deny() -> String {
    "deny".to_string()
}

fn closed() -> String {
    "closed".to_string()
}

/// Prefixed onto every reason, so the operator knows the class of the problem
/// and not only the line.
fn describe(reason: String) -> String {
    format!("workers file rejected: {reason}")
}

/// Builds a registry from worker-file text, or says why not.
pub fn load(text: &str) -> Result<WorkerRegistry, String> {
    let file: File = serde_json::from_str(text).map_err(|e| describe(e.to_string()))?;
    if file.worker.is_empty() {
        return Err(describe(
            "it declares no workers, so the broker would run nothing".into(),
        ));
    }

    let mut templates: Vec<WorkerTemplate> = Vec::with_capacity(file.worker.len());
    for entry in file.worker {
        if entry.name.trim().is_empty() {
            return Err(describe("a worker has an empty name".into()));
        }
        if templates.iter().any(|t| t.name == entry.name) {
            // Taking the last one would make the file's meaning depend on its
            // order, and the operator would have no way to tell which of the
            // two they just wrote.
            return Err(describe(format!(
                "worker `{}` is declared twice; its meaning would depend on line order",
                entry.name
            )));
        }
        if !entry.binary.is_absolute() {
            return Err(describe(format!(
                "worker `{}` has a relative binary `{}`; a broker's working directory is not something an operator should have to reason about",
                entry.name,
                entry.binary.display()
            )));
        }
        if entry.egress != "deny" {
            return Err(describe(format!(
                "worker `{}` declares egress {:?}; only \"deny\" is enforceable today, and \"allow\" is refused at every spawn, so accepting it here would move the failure from the file to the call",
                entry.name, entry.egress
            )));
        }
        if entry.seccomp != "closed" {
            return Err(describe(format!(
                "worker `{}` declares seccomp {:?}; \"passthrough\" is a debug profile the runtime refuses to run, so accepting it here would move the failure from the file to the call",
                entry.name, entry.seccomp
            )));
        }

        templates.push(WorkerTemplate {
            name: entry.name,
            binary: entry.binary,
            arguments: entry.arguments,
            secret_injection: match entry.secret_env {
                Some(name) => SecretInjectionPlan::EnvVar { name },
                None => SecretInjectionPlan::None,
            },
            egress_policy: EgressPolicy::Deny,
            landlock_profile: LandlockProfile {
                allowed_read: entry.read,
                allowed_write: entry.write,
            },
            seccomp_profile: SeccompProfile::ClosedAllowList,
            // Never a value. See the module header: the runtime seeds this
            // from the credential it resolves, precisely so the file does not
            // have to carry one.
            redactor: Redactor::empty(),
        });
    }

    Ok(WorkerRegistry::new(templates))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"worker":[{"name":"echoer","binary":"/bin/echo"}]}"#;

    #[test]
    fn a_minimal_declaration_loads() {
        let registry = load(GOOD).expect("a valid file loads");
        assert_eq!(registry.names(), vec!["echoer"]);
    }

    /// The refusals, one each. Every one of them is a file an operator could
    /// plausibly write, and each is a different way for the broker to end up
    /// running something the file did not say.
    #[test]
    fn refusals_are_one_per_kind() {
        let cases: Vec<(&str, &str)> = vec![
            (
                "a name declared twice",
                r#"{"worker":[{"name":"a","binary":"/bin/echo"},
                              {"name":"a","binary":"/bin/cat"}]}"#,
            ),
            (
                "a relative binary",
                r#"{"worker":[{"name":"a","binary":"bin/echo"}]}"#,
            ),
            (
                "an egress the runtime refuses on every call",
                r#"{"worker":[{"name":"a","binary":"/bin/echo","egress":"allow"}]}"#,
            ),
            (
                "a debug seccomp profile",
                r#"{"worker":[{"name":"a","binary":"/bin/echo","seccomp":"passthrough"}]}"#,
            ),
            (
                "an empty name",
                r#"{"worker":[{"name":"  ","binary":"/bin/echo"}]}"#,
            ),
            (
                "a misspelled key",
                r#"{"worker":[{"name":"a","binary":"/bin/echo","sandbox":"closed"}]}"#,
            ),
            ("no workers at all", r#"{"worker":[]}"#),
        ];

        for (what, text) in cases {
            let reason = match load(text) {
                Ok(registry) => panic!(
                    "{what} must be refused, and it loaded: {:?}",
                    registry.names()
                ),
                Err(reason) => reason,
            };
            assert!(
                reason.starts_with("workers file rejected:"),
                "{what} should say what class of problem it is, got: {reason}"
            );
        }
    }

    /// A declaration that asks for no worker is a refusal, not a no-op.
    ///
    /// Starting a broker with an empty file would be indistinguishable from
    /// starting one with no `--workers`, and an operator who wrote an empty
    /// file was told something went wrong. Silently ignoring it would leave
    /// them believing they had declared a sandbox.
    #[test]
    fn an_empty_declaration_is_not_a_silent_no_op() {
        assert!(load(r#"{"worker":[]}"#).is_err());
    }

    /// No file, however written, can put a secret value in the file.
    ///
    /// The property is checked by absence: there is no key for it. A future
    /// field named `redact` or `secret` would be a plaintext credential on disk
    /// in every deployment, so the test asserts the vocabulary rather than
    /// trusting review to catch it.
    #[test]
    fn there_is_no_key_for_a_secret_value() {
        for forbidden in ["redact", "secret", "value", "token", "password"] {
            assert!(
                !GOOD.contains(forbidden),
                "the file vocabulary must not grow a `{forbidden}` key"
            );
            // And a file that tries to use one is refused rather than ignored.
            let with =
                format!(r#"{{"worker":[{{"name":"a","binary":"/bin/echo","{forbidden}":"x"}}]}}"#);
            assert!(
                load(&with).is_err(),
                "`{forbidden}` is not a key, and a file using it must be refused"
            );
        }
    }
}
