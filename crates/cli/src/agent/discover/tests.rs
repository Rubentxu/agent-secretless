//! `asv agent discover` — the entry point, and the decision table behind it.
//!
//! AAT-001 (cold discovery) and AAT-002 (broker absent) are checked here
//! against the document an agent actually receives, not against the code that
//! produces it. AAT-008 (schema mismatch) is checked by refusing to serve a
//! schema this build does not implement.

use super::*;
use crate::tests_support::TempTree;

// --- the decision table --------------------------------------------------

/// Every reachable combination, and the code it produces. One table, so that
/// adding a state means editing this rather than discovering an unhandled
/// pair later.
#[test]
fn every_reachable_state_maps_to_a_stable_code() {
    let cases = [
        // (reachable, compatible, installed, facts, status, code)
        (
            false,
            false,
            false,
            false,
            Status::Blocked,
            Some(code::SETUP_REQUIRED),
        ),
        (
            false,
            false,
            true,
            false,
            Status::Blocked,
            Some(code::BROKER_UNAVAILABLE),
        ),
        (
            true,
            false,
            true,
            true,
            Status::Error,
            Some(code::PROTOCOL_MISMATCH),
        ),
        // Reachable and in-protocol but will not describe itself: treated as
        // incompatible, because a document that silently omits the broker's
        // capabilities is the R9 failure wearing a thinner shape.
        (
            true,
            true,
            true,
            false,
            Status::Error,
            Some(code::PROTOCOL_MISMATCH),
        ),
        (true, true, true, true, Status::Ready, None),
    ];

    for (reachable, compatible, installed, facts, expected_status, expected_code) in cases {
        let (status, got_code) = classify(reachable, compatible, installed, facts);
        let label = format!("reachable={reachable} compatible={compatible} facts={facts}");
        assert_eq!(status, expected_status, "{label}");
        assert_eq!(got_code.as_deref(), expected_code, "{label}");
    }
}

/// A stopped broker and an un-setup installation are both `blocked` and are
/// told apart by the code, because the next action differs: one is
/// `asv setup`, the other is starting a service.
#[test]
fn the_two_blocked_states_are_told_apart_by_code() {
    let (_, unset) = classify(false, false, false, false);
    let (_, installed) = classify(false, false, true, false);
    assert_eq!(unset.as_deref(), Some(code::SETUP_REQUIRED));
    assert_eq!(installed.as_deref(), Some(code::BROKER_UNAVAILABLE));
    assert_ne!(unset, installed);
}

/// AAT-002's third clause: the document must not tell the agent to run the
/// private broker. It is not on PATH, and a user should never need to name it.
#[test]
fn the_document_never_points_at_the_private_broker() {
    for socket_state in ["absent", "stale"] {
        let value = document_for(false, socket_state);
        let rendered = serde_json::to_string(&value).unwrap();
        assert!(
            !rendered.contains("asv-brokerd"),
            "the document names the private broker: {rendered}"
        );
        // And positively: the published links are the two that lead somewhere.
        let rels: Vec<&str> = value["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["rel"].as_str().unwrap())
            .collect();
        assert_eq!(
            rels,
            ["asv://rels/doctor", "asv://rels/setup"],
            "{socket_state}"
        );
    }
}

/// AAT-002's fourth clause: the announced link is one the agent can run.
#[test]
fn every_announced_link_is_runnable() {
    use clap::CommandFactory;
    for reachable in [false, true] {
        let value = document_for(reachable, "absent");
        for link in value["links"].as_array().unwrap() {
            let program = link["invoke"]["program"].as_str().unwrap();
            let argv: Vec<&str> = link["invoke"]["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            // The program is asserted, not just the arguments. The first
            // version of this test only checked that the argv parsed, and a
            // mutation rewriting `program` to `asv-brokerd` passed it —
            // clap takes the binary name as the first element and does not
            // care what it is called. AAT-002 is about which program an agent
            // is told to run, so the program is the assertion.
            assert_eq!(
                program, "asv",
                "a link tells the agent to run `{program}`, not `asv`"
            );
            assert!(
                !argv.iter().any(|a| a.contains("asv-brokerd")),
                "a link tells the agent to run the private broker: {argv:?}"
            );

            let mut args = vec![program];
            args.extend(argv);
            assert!(
                crate::Cli::command()
                    .try_get_matches_from(args.clone())
                    .is_ok(),
                "`asv {}` is announced and is not a command",
                args.join(" ")
            );
        }
    }
}

// --- the document itself -------------------------------------------------

/// Builds the document the command emits, for a socket in a given state.
fn document_for(reachable: bool, socket_state: &str) -> serde_json::Value {
    let dir = TempTree::new("discover");
    let socket = dir.sub("broker.sock");
    if reachable && socket_state == "live" {
        spawn_broker(&socket, asv_ipc_protocol::PROTOCOL_VERSION);
    } else if reachable {
        // A socket that answers, but not as a broker.
        spawn_broker(&socket, asv_ipc_protocol::PROTOCOL_VERSION.wrapping_add(5));
    }

    let discovery = discover(&socket, false);
    serde_json::from_str(&discovery.to_envelope().to_json()).expect("the document parses")
}

/// A real broker-shaped peer: a `UnixListener` answering `Ping` and
/// `AgentInfo`, with a real `Pong` and a real `BrokerInfo` on the wire.
///
/// Built as a peer rather than as an enum value because the thing being tested
/// is the round trip — a `discover` that reads the socket and then decodes the
/// answer. Constructing `SocketOutcome::SelfReported` by hand would test the
/// decoding and not the asking.
fn spawn_broker(socket: &std::path::Path, protocol: u16) {
    use std::os::unix::net::UnixListener;
    let path = socket.to_path_buf();
    let listener = UnixListener::bind(&path).expect("bind");
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // Read until the JSON parses, not once. A single `read` on a Unix
            // stream can return a partial message, and the first version of
            // this peer did exactly that — so `AgentInfo` never arrived, the
            // discovery reported `Error`, and the failure pointed at the
            // product instead of at the test harness that dropped half a
            // message on the floor.
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            let request = loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buffer.extend_from_slice(&chunk[..n]);
                if let Ok(request) = serde_json::from_slice::<asv_ipc_protocol::Request>(&buffer) {
                    break request;
                }
            };
            let response = match request {
                asv_ipc_protocol::Request::AgentInfo { .. } => {
                    asv_ipc_protocol::Response::BrokerInfo {
                        protocol,
                        product_version: "0.26.0-test".into(),
                        dumpable_disabled: true,
                        no_new_privs: true,
                        landlock_installed: true,
                        seccomp_installed: true,
                        cgroup_v2: true,
                        // No listener in this fixture. Stated rather than left
                        // implicit so a future test that needs one says so.
                        connect_listen: None,
                        capabilities: vec![
                            "credentials.metadata".into(),
                            "session.run".into(),
                            "system.health".into(),
                        ],
                    }
                }
                _ => asv_ipc_protocol::Response::Pong { protocol },
            };
            let _ = stream.write_all(&serde_json::to_vec(&response).unwrap());
        }
    });
}

/// AAT-001: an agent that knows only this command gets a usable document.
///
/// The exit criterion for DX2, checked end to end over a real socket.
#[test]
fn cold_discovery_reaches_an_operation_from_one_command() {
    let dir = TempTree::new("cold");
    let socket = dir.sub("broker.sock");
    spawn_broker(&socket, asv_ipc_protocol::PROTOCOL_VERSION);

    let discovery = discover(&socket, true);
    assert_eq!(discovery.status, Status::Ready);
    assert_eq!(
        discovery.code, None,
        "a healthy install must carry no error"
    );

    let value: serde_json::Value =
        serde_json::from_str(&discovery.to_envelope().to_json()).unwrap();

    assert_eq!(value["schema"], "asv.agent/v1");
    assert_eq!(value["status"], "ready");
    assert_eq!(value["data"]["broker"]["reachable"], true);
    assert_eq!(value["data"]["broker"]["version"], "0.26.0-test");
    assert_eq!(value["data"]["capability_derivation"], "COMPILED");

    // The hardening the broker reported came back as measured, not unknown.
    assert_eq!(
        value["data"]["broker"]["hardening"]["dumpable_disabled"],
        true
    );

    // And there is a link to a real operation.
    let rels: Vec<&str> = value["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["rel"].as_str().unwrap())
        .collect();
    for needed in [
        "asv://rels/doctor",
        "asv://rels/setup",
        "asv://rels/capabilities",
        "asv://rels/credentials/list",
        "asv://rels/session/run",
    ] {
        assert!(rels.contains(&needed), "no route to {needed}: {rels:?}");
    }
}

/// AAT-008: a broker from a different protocol is not described as healthy,
/// and nothing is changed on the way to finding that out.
#[test]
fn a_protocol_mismatch_fails_closed() {
    let dir = TempTree::new("mismatch");
    let socket = dir.sub("broker.sock");
    spawn_broker(&socket, asv_ipc_protocol::PROTOCOL_VERSION.wrapping_add(5));

    let discovery = discover(&socket, true);
    assert_eq!(discovery.status, Status::Error);
    assert_eq!(discovery.code.as_deref(), Some(code::PROTOCOL_MISMATCH));

    let value: serde_json::Value =
        serde_json::from_str(&discovery.to_envelope().to_json()).unwrap();
    assert_eq!(value["data"]["broker"]["reachable"], true);
    assert_eq!(value["data"]["broker"]["compatible"], false);
    // Fail closed on the *operation* links. Following
    // `credentials/list` against a peer whose protocol is unknown would mean
    // guessing what the answer means, and AAT-008 says not to.
    //
    // An earlier version of this test asserted that *no* link is published,
    // and it was wrong. AAT-008 also asks for "diagnóstico/upgrade de forma no
    // destructiva", and `doctor` is how that diagnosis happens — refusing to
    // name the command that explains the mismatch is failing closed in the
    // direction that leaves the user with nothing.
    let rels: Vec<&str> = value["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["rel"].as_str().unwrap())
        .collect();
    for diagnostic in ["asv://rels/doctor", "asv://rels/setup", "asv://rels/status"] {
        assert!(
            rels.contains(&diagnostic),
            "a mismatched broker was not offered {diagnostic}: {rels:?}"
        );
    }
    for operation in ["asv://rels/credentials/list", "asv://rels/session/run"] {
        assert!(
            !rels.contains(&operation),
            "{operation} was published against a peer whose protocol is unknown"
        );
    }
}

/// The schema string is what an unknown consumer refuses on, so it is pinned
/// here as well as in `schema.rs` — this is the document DX2 promises.
#[test]
fn the_discovery_document_serves_the_promised_schema() {
    let dir = TempTree::new("schema");
    let discovery = discover(&dir.sub("nope.sock"), false);
    let value: serde_json::Value =
        serde_json::from_str(&discovery.to_envelope().to_json()).unwrap();
    assert_eq!(value["schema"], "asv.agent/v1");
    assert!(value.get("links").is_some());
    assert!(value.get("warnings").is_some());
    assert!(value.get("data").is_some());
}

/// AAT-007: a hostile argument stays one element of `argv`.
///
/// The document never carries a shell string, so this is structural rather
/// than behavioural — and the test is what keeps it structural, because the
/// day someone changes `argv` to a joined string the type of
/// [`AgentInvoke`](crate::agent::relations::AgentInvoke) changes too.
#[test]
fn a_hostile_argument_cannot_escape_argv() {
    use crate::agent::relations::{AgentInvoke, AgentLink, Safety};
    let hostile = "repo name; rm -rf / $(whoami) \"quoted\"\nnewline";

    let link = AgentLink {
        rel: "asv://rels/session/run".into(),
        operation: "session.run".into(),
        invoke: AgentInvoke {
            program: "asv".into(),
            argv: vec!["run".into(), "--".into(), hostile.into()],
        },
        safety: Safety::BoundedExecution,
        requires_human: false,
        description: None,
    };

    // Three elements, and the last one is the whole string.
    assert_eq!(link.invoke.argv.len(), 3);
    assert_eq!(link.invoke.argv[2], hostile);

    // It survives a round trip without becoming two elements.
    let json = serde_json::to_string(&link).unwrap();
    let back: AgentLink = serde_json::from_str(&json).unwrap();
    assert_eq!(back.invoke.argv.len(), 3);
    assert_eq!(back.invoke.argv[2], hostile);

    // And there is no field anywhere in the document that could hold a
    // command line for a shell to run.
    assert!(
        !json.contains("sh"),
        "the serialized link mentions a shell: {json}"
    );
}
