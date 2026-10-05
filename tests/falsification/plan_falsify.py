#!/usr/bin/env python3
"""Falsification for the npm plan stage (R3.A.2).

`plan` produces advice, and advice has a failure mode code does not: it can be
**confidently wrong**. So the mutations here are grouped by the way a plan goes
wrong rather than by the function they touch:

* **posture** -- a strategy ASV cannot deliver, or a ranking that puts the worst
  option first. Both are the same class of damage: an operator follows the plan.
* **binding** -- resolving what should be left ambiguous, or dropping an entry
  whose answer was "nothing". Both make the plan read as complete.
* **identity** -- §6: a plan that survives a changed file is worse than no
  plan, because it looks like an answer.
* **leak** -- a plan has nowhere to put a credential, and a field added by a
  well-meaning change would turn it into a place secrets travel.

Two mutations in this file are worth naming before the run. The first version
of the ordering mutation edited `Posture::ALL` and the row went green, because
the row compares the strategies against that same constant: changing the
constant changed both sides of the comparison. The mutation that actually
attacks the property reverses the order the strategies are *built* in, and the
row pins the build order against the declaration order. A row written against a
constant it also lets the mutation edit is not a row.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

PLAN = f.REPO / "crates/integrations/src/plan.rs"

# --- posture ---------------------------------------------------------------

POSTURE = [
    (
        # The order is the recommendation. Reversing it makes the strongest
        # posture last, and an operator reading top-down picks the worst thing
        # the plan offers while believing they picked the best.
        #
        # Deliberately *not* a mutation of `Posture::ALL`: the row compares the
        # built order against that constant, so editing both sides of a
        # comparison proves nothing. This edits only the side the code produces.
        "build the strategies weakest first",
        "    out\n}",
        "    out.reverse();\n    out\n}",
        "strategies_are_ordered_strongest_first",
    ),
    (
        # `NonExportable` is the default and the common path. Offering raw
        # exposure for it is offering a step `adopt` cannot carry out, and the
        # operator finds out only after they have decided what to adopt.
        "write a non-exportable credential out anyway",
        "    if exportability != Exportability::NonExportable {",
        "    if true {",
        "a_non_exportable_credential_is_never_offered_raw_exposure",
    ),
    (
        # A static token written to a file and deleted afterwards is not a
        # short-lived credential. Offering it renames the risk.
        "call a static token short-lived",
        "    if kind == CredentialKind::OAuth2 {",
        "    if true {",
        "a_static_token_is_never_offered_short_lived_exposure",
    ),
    (
        # The other half of the guard, so the row above cannot pass by removing
        # the whole strategy.
        "deny short-lived exposure to the one credential that can mint",
        "    if kind == CredentialKind::OAuth2 {",
        "    if kind != CredentialKind::OAuth2 {",
        "an_oauth2_credential_is_offered_short_lived_exposure",
    ),
]

# --- binding ---------------------------------------------------------------

BINDING = [
    (
        # A database password can only ever authenticate against a database.
        # Without this check the plan offers it as a registry credential, which
        # is the mistake `CredentialClass` exists to make a type error.
        "let a database credential serve a registry",
        "        if CredentialClass::from_kind(metadata.kind) == CredentialClass::Database {",
        "        if false {",
        "a_database_credential_cannot_serve_a_registry",
    ),
    (
        # Two bearer tokens, and the inventory says nothing about which is the
        # registry one. Choosing the first is a coin flip dressed as a decision.
        "resolve an ambiguity by taking the first candidate",
        """        _ => Binding::Ambiguous {
            candidates: usable
                .iter()
                .map(|metadata| BindingCandidate {
                    credential: metadata.id,
                    label: metadata.label.clone(),
                    kind: metadata.kind,
                })
                .collect(),
        },""",
        """        _ => Binding::Bound {
            credential: usable[0].id,
            label: usable[0].label.clone(),
            kind: usable[0].kind,
            exportability: usable[0].exportability,
        },""",
        "two_usable_credentials_are_reported_rather_than_one_chosen",
    ),
    (
        # Tidy-up that costs the whole point: an entry with no strategies looks
        # like noise, so it goes. What it actually does is make a configured
        # selector invisible in the one report that says it was found.
        "drop the entries that could not be bound",
        """    let entries = discovery
        .files
        .iter()
        .flat_map(|file| plan_file(file, inventory))
        .collect();""",
        """    let entries: Vec<PlanEntry> = discovery
        .files
        .iter()
        .flat_map(|file| plan_file(file, inventory))
        .filter(|entry| !entry.strategies.is_empty())
        .collect();""",
        "a_selector_with_no_credential_is_reported_rather_than_dropped",
    ),
    (
        # "No strategies because you have nothing stored" and "no strategies
        # because the one credential you have is the wrong shape" are different
        # facts. A hardcoded zero renders both as an empty list.
        "report an inventory size that was never counted",
        "            entries,\n            inventory_size,",
        "            entries,\n            inventory_size: 0,",
        "the_plan_reports_the_inventory_it_was_given",
    ),
    (
        # An email address is a contact field. Treating it as a credential means
        # counting something the operator does not have to adopt, and offering
        # to protect it.
        "treat an email selector as a credential",
        "        AuthField::Email => None,",
        "        AuthField::Email => Some(pair(Operation::Read, Operation::Publish)),",
        "an_email_is_not_a_credential_and_gets_no_strategy",
    ),
    (
        # A typo npm ignores entirely. Reporting it as a credential invents a
        # credential the operator does not have.
        "treat a misspelled field as a credential",
        "        AuthField::Unrecognised(_) => None,",
        "        AuthField::Unrecognised(_) => Some(pair(Operation::Read, Operation::Publish)),",
        "a_misspelled_auth_field_is_not_a_credential",
    ),
    (
        # `plan` does not model publishing with a client certificate. Claiming
        # it puts an operation in a plan `adopt` cannot carry out.
        "claim publish under a client certificate",
        "        AuthField::CertFile | AuthField::KeyFile => Some(BTreeSet::from([Operation::Read])),",
        "        AuthField::CertFile | AuthField::KeyFile => {\n            Some(pair(Operation::Read, Operation::Publish))\n        }",
        "a_client_certificate_is_read_only",
    ),
    (
        # §7: the binding is credential + audience + operations. Drop the
        # operations from the document and it degenerates into a label, which is
        # the thing the design doc names as what not to store.
        "leave the operations out of the reported entry",
        "    pub operations: BTreeSet<Operation>,",
        "    #[serde(skip)]\n    pub operations: BTreeSet<Operation>,",
        "the_entry_names_credential_audience_and_operations",
    ),
]

# --- identity (§6) ---------------------------------------------------------

IDENTITY = [
    (
        # The claim is: a plan is a promise about specific bytes at a specific
        # inode under a specific mode. If nothing checks, the promise is
        # decorative and `execute` proceeds against a file nobody planned.
        "accept any configuration at revalidation time",
        """            let drift = entry.fingerprint.drift_from(&now);
            if !drift.is_empty() {""",
        """            let drift = Vec::new();
            if !drift.is_empty() {""",
        "a_changed_configuration_refuses_the_plan",
    ),
    (
        # Two files with identical bytes have identical digests, so a digest-only
        # comparison lets a file swapped for an identical copy pass — and the
        # swap is the attack, since the bytes are the same by construction.
        "compare the file's identity by digest alone",
        "            let drift = entry.fingerprint.drift_from(&now);",
        "            let drift = if entry.fingerprint.matches(&now) { Vec::new() } else { vec![Drift::Contents] };",
        "a_replaced_file_is_caught_not_only_by_the_digest",
    ),
    (
        # A vanished file is not an unchanged file. Reporting success here is
        # the worst of the three outcomes: the plan survives the configuration
        # disappearing.
        "skip the files that cannot be read",
        """            let now = policy.fingerprint(&entry.file).map_err(|source| PlanError::Unreadable {
                path: entry.file.clone(),
                message: source.to_string(),
            })?;""",
        """            let Ok(now) = policy.fingerprint(&entry.file) else { continue };""",
        "an_unreadable_file_refuses_the_plan",
    ),
]

# --- invented --------------------------------------------------------------
#
# **There is deliberately no `leak` bucket here, and the reason is the finding.**
#
# The first version carried a credential value into `PlanEntry` and the row
# stayed green. Investigating it produced a better answer than a red row: *no
# mutation in this file can make the plan leak*, because the plan's two inputs —
# `NpmDiscovery` and `&[CredentialMetadata]` — contain no secret for it to carry.
# The parse result records a value's *length*, and the inventory records a label,
# a kind and an exportability. There is nothing to forward.
#
# That makes the property **structural rather than behavioural**, so it is not
# mutation-falsifiable at this layer, and a mutation that cannot be written is
# not evidence either way. The claim is instead split across the two places it
# can actually be measured:
#
#   * that the inputs carry none — measured in `npm_discover_falsify.py`, whose
#     `leak` bucket turns the parse result red when a value is added to it;
#   * that the output carries none — measured by
#     `the_serialised_plan_contains_no_credential`, which runs against a real
#     fixture with a real token rather than a synthetic string.
#
# What is left for this file is the risk that *is* demonstrable here, and it is
# a plan's characteristic failure: **saying something it was not told.** A plan
# that names an audience its selector did not carry, or a length its file did not
# have, is confidently wrong in the same way a leaking one is, and unlike the
# leak it is reachable from here.

INVENTED = [
    (
        # The audience is the one thing that makes a plan specific to a
        # registry. A plan that reported the public registry for every selector
        # would look right on the overwhelmingly common case and be wrong on
        # exactly the case an operator ran `plan` to find out about.
        "name an audience the selector never carried",
        "        audience: selector.registry.audience.to_string(),",
        '        audience: "registry.npmjs.org".to_string(),',
        "an_entry_reports_the_audience_and_length_its_selector_carried",
    ),
    (
        # Collapsing three states into two — "nothing to bind" and "several
        # could" both rendered as a list — is the kind of tidy-up that makes a
        # plan read as complete. An empty candidate list says "we looked" and
        # reports nothing, which is the ambiguity this whole stage removes.
        "render an unbound selector as an empty candidate list",
        """        0 => Binding::Unbound {
            reason: if excluded.is_empty() {
                UnboundReason::NoUsableCredential {
                    inventory_size: inventory.len(),
                }
            } else {
                UnboundReason::EveryCandidateExcluded { excluded }
            },
        },""",
        "        0 => Binding::Ambiguous { candidates: Vec::new() },",
        "a_selector_with_no_credential_is_reported_rather_than_dropped",
    ),
    (
        # A length is what the plan reports *instead of* the value, and it is
        # also what tells an operator the credential is present and non-empty.
        # Zeroing it makes an empty selector and a 34-byte token identical,
        # which is the one ambiguity a credential report cannot have.
        "report a length the file did not have",
        "        value_len: selector.value_len,",
        "        value_len: 0,",
        "an_entry_reports_the_audience_and_length_its_selector_carried",
    ),
]

BUCKETS = {
    "posture": POSTURE,
    "binding": BINDING,
    "identity": IDENTITY,
    "invented": INVENTED,
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "posture"
    f.PACKAGE = "asv-integrations"
    f.CARGO_TARGET = "--lib"
    # `--exact` matches the full test path, so the module prefix is part of the
    # name rather than decoration. An empty prefix made every mutation `no-run`,
    # which the harness correctly reported as measuring nothing.
    f.TEST_PREFIX = "plan::tests::"
    f.STS = PLAN
    mutations = BUCKETS[mode]
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())