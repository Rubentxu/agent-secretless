//! `asv capabilities` — the four questions kept apart.
//!
//! AAT-005: an installation without a given capability must produce "not
//! available", not an invented command. AAT-001: the list has to come from
//! something real. R2: `available = true` gets read as "permitted", and that
//! conflation is the risk this module exists to prevent.

use super::*;

fn facts(names: &[&str]) -> crate::ipc::BrokerFacts {
    crate::ipc::BrokerFacts {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        product_version: "0.26.0".into(),
        dumpable_disabled: true,
        no_new_privs: true,
        landlock_installed: true,
        seccomp_installed: true,
        capabilities: names.iter().map(|s| s.to_string()).collect(),
        connect_listen: None,
        // Shared, because these tests are about the capability list and the
        // identity check must still run beside them rather than be switched
        // off by a value that happens to pass.
        identity: Some(asv_ipc_protocol::BrokerIdentity::measured(1000, None)),
    }
}

/// R2, as an assertion. An agent reading `authorization: false` would conclude
/// it is denied; the truth is that nobody has asked.
#[test]
fn authorization_is_never_a_boolean() {
    let report = CapabilityReport::from_broker(
        Some(&facts(&["session.run", "credentials.metadata"])),
        true,
        true,
    );
    assert!(
        !report.capabilities.is_empty(),
        "the control: there are some"
    );
    for c in &report.capabilities {
        assert_eq!(
            c.authorization, "evaluated_on_request",
            "`{}` claims to know the answer to a question only Cedar answers",
            c.name
        );
    }
}

/// The JSON says the same thing, because the JSON is what an agent reads.
#[test]
fn the_json_never_says_authorized_false() {
    let report = CapabilityReport::from_broker(Some(&facts(&["session.run"])), true, true);
    let value: serde_json::Value = serde_json::from_str(&report.to_envelope().to_json()).unwrap();

    for c in value["data"]["capabilities"].as_array().unwrap() {
        assert_eq!(c["authorization"], "evaluated_on_request");
        assert!(
            c.get("authorized").is_none(),
            "a boolean verdict crept in: {c}"
        );
    }
}

/// The failure mode of every one of these: an empty list read as "this product
/// cannot do anything". It means the opposite, and the report says so in a
/// field a machine reads and a human reads.
#[test]
fn an_unreachable_broker_gives_an_unknown_list_not_an_empty_one() {
    let report = CapabilityReport::from_broker(None, false, false);

    assert_eq!(report.derivation, "UNKNOWN");
    assert!(report.capabilities.is_empty());
    assert_eq!(report.status(), Status::Blocked);

    let value: serde_json::Value = serde_json::from_str(&report.to_envelope().to_json()).unwrap();
    assert_eq!(value["data"]["derivation"], "UNKNOWN");
    let codes: Vec<&str> = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"CAPABILITIES_UNKNOWN"),
        "an unknowable list was published without saying it was unknowable: {codes:?}"
    );

    // And the human form says it in words, because a table with no rows and
    // no heading is read as "there is nothing".
    assert!(
        report.render_human().contains("is unknown"),
        "{}",
        report.render_human()
    );
}

/// The control: a broker that answered gives a `COMPILED` list.
#[test]
fn a_reachable_broker_derives_from_the_runtime() {
    let report =
        CapabilityReport::from_broker(Some(&facts(&["system.health", "session.run"])), true, true);
    assert_eq!(report.derivation, "COMPILED");
    assert_eq!(report.capabilities.len(), 2);
}

/// R9: a relation is published only if the broker has the capability behind
/// it. A build without Postgres must not hand out a Postgres link.
#[test]
fn a_relation_is_published_only_when_the_broker_has_the_capability() {
    let without = CapabilityReport::from_broker(Some(&facts(&["system.health"])), true, true);
    assert!(
        !without
            .relations
            .contains(&"asv://rels/credentials/list".to_string()),
        "credentials/list was published by a broker that cannot list them: {:?}",
        without.relations
    );

    let with = CapabilityReport::from_broker(
        Some(&facts(&["system.health", "credentials.metadata"])),
        true,
        true,
    );
    assert!(with
        .relations
        .contains(&"asv://rels/credentials/list".to_string()));
}

/// The system relations do not depend on a capability, and must survive a
/// broker with an empty capability list — otherwise an agent with a stopped
/// broker has no link to `doctor`, which is the one it needs. `upgrade` is
/// here for the same reason protocol mismatch needs a recovery relation even
/// when no broker is reachable.
#[test]
fn the_system_relations_survive_an_empty_capability_list() {
    let report = CapabilityReport::from_broker(Some(&facts(&[])), true, true);
    for required in [
        "asv://rels/status",
        "asv://rels/doctor",
        "asv://rels/setup",
        "asv://rels/capabilities",
        "asv://rels/upgrade",
    ] {
        assert!(
            report.relations.contains(&required.to_string()),
            "`{required}` disappeared with the capabilities: {:?}",
            report.relations
        );
    }
}

/// `configured` is only asked where the CLI is genuinely the authority.
/// Answering it everywhere would be answering a question this process does
/// not have the standing to answer.
#[test]
fn configured_is_null_where_the_cli_cannot_know() {
    let report = CapabilityReport::from_broker(
        Some(&facts(&["postgres.connect", "github.issue.read"])),
        true,
        true,
    );
    let postgres = report
        .capabilities
        .iter()
        .find(|c| c.name == "postgres.connect")
        .unwrap();
    assert_eq!(
        postgres.configured, None,
        "the CLI asserted something about a connector it cannot see"
    );
}

/// A protocol mismatch is `error`, not `blocked`, and not `ready`. The three
/// mean three different things to an agent: fine, fix this, fix that.
#[test]
fn a_protocol_mismatch_is_an_error_and_nothing_else() {
    let mut f = facts(&["system.health"]);
    f.protocol = asv_ipc_protocol::PROTOCOL_VERSION.wrapping_add(9);
    let report = CapabilityReport::from_broker(Some(&f), true, false);
    assert_eq!(report.status(), Status::Error);
}
