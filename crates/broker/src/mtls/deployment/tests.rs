//! Rows for [`MtlsDeployment`] — the operator's declaration, and the
//! resolution from a destination to the identity it was granted.
//!
//! The rows are unit rows on purpose. The chain that matters — a declaration
//! resolving to a `ClientIdentity`, attached to a `Bridge`, completing a
//! handshake — is measured in `tls_bridge/client_auth.rs`, where the
//! destination is real. What is measured here is the part a handshake cannot
//! see: which destination an identity comes out for, and what happens to a
//! declaration that is ambiguous or misspelled.

use std::time::{Duration, Instant};

use super::super::deployment::{ClientBinding, DeploymentError, MtlsDeployment};
use super::super::issue::ClientCertError;
use crate::tls_bridge::SessionCa;

const HOUR: Duration = Duration::from_secs(3600);
const HOST: &str = "internal.svc.example";

fn binding(identity: &str, destination: &str) -> ClientBinding {
    ClientBinding::new(identity, destination, HOUR).expect("a canonical pair")
}

fn ca() -> SessionCa {
    SessionCa::new("s-r2e3", 31, HOUR)
}

/// **Mutation: return `Some` for every destination** — this row goes red, and
/// the one after it is the control for it.
#[test]
fn un_destino_declarado_produce_una_identidad_para_ese_destino() {
    let deployment = MtlsDeployment::new(vec![binding("svc-a.internal", HOST)])
        .expect("one destination, one identity");
    let ca = ca();

    let identity = deployment
        .identity_for(&ca, HOST, Instant::now())
        .expect("issuance")
        .expect("the destination is declared");
    assert_eq!(identity.identity(), "svc-a.internal");
    assert_eq!(identity.bound_host(), HOST);
}

/// **Mutation: mint an identity for whichever host was asked for** — this row
/// goes red, and it is the control for the row above: either alone is
/// satisfied by a deployment that invents an identity on demand, which is the
/// shape that hands a client certificate to a host nobody declared.
#[test]
fn un_destino_sin_declaracion_no_produce_identidad() {
    let deployment = MtlsDeployment::new(vec![binding("svc-a.internal", HOST)]).expect("ok");
    let ca = ca();

    for host in [
        "other.svc.example",
        "internal.svc.example.evil.test",
        "svc.example",
        "127.0.0.1",
    ] {
        assert!(
            deployment
                .identity_for(&ca, host, Instant::now())
                .expect("no error")
                .is_none(),
            "{host} was not declared and must not receive an identity"
        );
    }
}

/// **Mutation: resolve by first match, or by last match, instead of refusing a
/// repeated destination** — this row goes red.
///
/// An operator who declares the same destination twice has made a mistake that
/// no single line of the declaration reveals, so this is the one error in this
/// module that only the whole list can produce.
#[test]
fn un_destino_declarado_dos_veces_se_rechaza() {
    let refusal = MtlsDeployment::new(vec![
        binding("svc-a.internal", HOST),
        binding("svc-b.internal", HOST),
    ])
    .expect_err("a destination has one identity or none");

    assert_eq!(
        refusal,
        DeploymentError::DuplicateDestination {
            destination: HOST.to_string(),
            first: "svc-a.internal".to_string(),
            second: "svc-b.internal".to_string(),
        }
    );
}

/// **Mutation: compare the declared destination by suffix** — a declaration
/// for `svc.example` would then mint an identity for `other.svc.example`.
#[test]
fn la_resolucion_es_exacta_y_no_por_sufijo() {
    let deployment =
        MtlsDeployment::new(vec![binding("svc-a.internal", "svc.example")]).expect("ok");
    let ca = ca();

    assert!(deployment.declares("svc.example"));
    assert!(!deployment.declares("other.svc.example"));
    assert!(!deployment.declares("svc.example.evil.test"));
    assert!(deployment
        .identity_for(&ca, "other.svc.example", Instant::now())
        .expect("no error")
        .is_none());
}

/// **Mutation: resolve the incoming host without canonicalizing it** — the
/// declaration holds `internal.svc.example`, the route names the same host in
/// a different case, and the identity silently stops existing.
#[test]
fn el_host_se_canonicaliza_antes_de_resolver() {
    let deployment = MtlsDeployment::new(vec![binding("svc-a.internal", HOST)]).expect("ok");
    let ca = ca();

    for spelling in ["INTERNAL.SVC.EXAMPLE", "internal.svc.example."] {
        assert!(
            deployment
                .identity_for(&ca, spelling, Instant::now())
                .expect("no error")
                .is_some(),
            "{spelling:?} names the declared host and must resolve"
        );
    }
}

/// **Mutation: canonicalize in the binding but not in the request, or the
/// reverse** — declared and asked spellings drift apart and every request is
/// refused with a name mismatch that reads like a routing problem.
///
/// Not falsable with a one-line mutation in this module: `Authority` has no
/// public constructor from a raw string, so "canonicalize nothing" is a change
/// of the field's type rather than of a line. The campaign declares it and the
/// positive half above is what keeps the canonicalization honest.
#[test]
fn un_nombre_no_canonico_no_se_declara() {
    for bad in [
        "*.svc.example",
        "svc-a.internal:443",
        "user@svc-a.internal",
        "",
        "svc a.internal",
    ] {
        assert!(
            ClientBinding::new("svc-a.internal", bad, HOUR).is_err(),
            "{bad:?} is not a destination"
        );
    }
    for bad in ["*.internal", "svc a.internal", "svc-a.internal:443"] {
        assert!(
            ClientBinding::new(bad, HOST, HOUR).is_err(),
            "{bad:?} is not a name a certificate can carry"
        );
    }
}

/// **Mutation: check the floor in the declaration instead of in the issuer, or
/// drop it** — this row pins where the rule lives, not that it exists. The
/// refusal comes from `ClientCertError`, which is what says "you asked for
/// too little", and a declaration that silently clamped would hide that from
/// whoever wrote the file.
#[test]
fn el_plazo_lo_manda_el_emisor_y_no_la_declaracion() {
    let ca = ca();
    let deployment = MtlsDeployment::new(vec![ClientBinding::new(
        "svc-a.internal",
        HOST,
        Duration::from_secs(1),
    )
    .expect("a canonical pair")])
    .expect("the declaration itself is well formed");

    let refusal = deployment
        .identity_for(&ca, HOST, Instant::now())
        .expect_err("one second is below the issuer's floor");
    assert!(
        matches!(refusal, ClientCertError::GrantTtlTooShort { .. }),
        "the issuer owns the floor, got {refusal:?}"
    );
}

/// **Mutation: key the rotation on something other than the declaration** —
///
/// the point of the row is that rotation is a whole-value replacement with no
/// state carried across, so there is nothing that can be half-rotated.
#[test]
fn rotar_es_cambiar_la_declaracion() {
    let ca = ca();
    let before = MtlsDeployment::new(vec![binding("svc-a.internal", HOST)]).expect("ok");
    let after = MtlsDeployment::new(vec![binding("svc-b.internal", HOST)]).expect("ok");

    let first = before
        .identity_for(&ca, HOST, Instant::now())
        .expect("no error")
        .expect("declared");
    let second = after
        .identity_for(&ca, HOST, Instant::now())
        .expect("no error")
        .expect("still declared, under a new name");

    assert_eq!(first.identity(), "svc-a.internal");
    assert_eq!(second.identity(), "svc-b.internal");
    // Same destination, different name, and neither deployment knows the other
    // exists. There is no in-place mutation to get half-applied.
    //
    // The comparison is on the name and not on the two identities, because
    // `ClientIdentity` has no `PartialEq` and is not going to get one: an
    // equality on a type holding a private key is a comparison of two
    // private keys, and a test that leaned on it would be the first thing in
    // the repository to compare key material.
    assert_eq!(first.bound_host(), second.bound_host());
    assert_ne!(first.identity(), second.identity());
}

/// **Mutation: default a missing declaration to a permissive one** — a bridge
/// that was never configured would start authenticating.
#[test]
fn una_declaracion_vacia_no_declara_nada() {
    let deployment = MtlsDeployment::empty();

    assert!(deployment.is_empty());
    assert_eq!(deployment.len(), 0);
    assert!(!deployment.declares(HOST));
    assert!(deployment
        .identity_for(&ca(), HOST, Instant::now())
        .expect("no error")
        .is_none());
}

/// **Mutation: drop the duplicate check for a destination that differs only in
/// spelling** — two declarations that are the same destination, admitted
/// together, and resolved by whichever came first.
#[test]
fn un_destino_repetido_con_otra_ortografia_tambien_se_rechaza() {
    let refusal = MtlsDeployment::new(vec![
        binding("svc-a.internal", HOST),
        binding("svc-b.internal", "INTERNAL.SVC.EXAMPLE"),
    ])
    .expect_err("the same destination twice, whatever the spelling");

    match refusal {
        DeploymentError::DuplicateDestination { destination, .. } => {
            assert_eq!(destination, HOST, "reported in canonical form")
        }
        other => panic!("expected a duplicate, got {other:?}"),
    }
}
