#!/usr/bin/env python3
"""Falsifying the intent chain, in the four files it spans.

`r4b1_intent_chain.rs` and the 250-odd rows in `crates/domain` and
`crates/integrations` assert that a plan bound to an intent notices when the
world moves under it, and — since R4.B.2 — that the receipt names the credential
the execution would spend. Until this harness existed they were rows that passed,
which is the weakest thing a row can be: a row nobody has tried to break
measures nothing about whether it can fail.

Seven buckets, run one per invocation like every other harness here:

    python3 intent_falsify.py binding    # whose word the binding records
    python3 intent_falsify.py digest     # what goes into the config digest
    python3 intent_falsify.py tool       # how the executable is resolved
    python3 intent_falsify.py invalid    # which drift the check reaches
    python3 intent_falsify.py chain      # the wiring, through the real binary
    python3 intent_falsify.py stake      # what the receipt says is at stake
    python3 intent_falsify.py inventory  # the real inventory, against a broker
    python3 intent_falsify.py permit     # the branch where the operation runs
    python3 intent_falsify.py policy     # which policy says so

**`stake` and `inventory` are R4.B.2's, and `inventory` found a bug the whole
previous campaign could not see.**

`chain` mutates the CLI and points at `r4b1_intent_chain.rs`, which runs with
`--no-vault` because it has no broker — so every mutation it could express was
measured against a chain that never asked what credentials existed. A row can
only falsify a mutation when the fixture reaches the code being mutated, and
that fixture did not. `inventory` points at `r4b2_bound_execute.rs`, which
starts a real `asv-brokerd` over a real vault, and the first mutation it was
given — restoring the empty inventory R4.B.1 shipped — took the live path where
the other could not.

What it turned up was worse than an unreached mutation: `--session` was
mandatory, the broker pins a session to the PID that opened it, and so nothing
an operator could type had ever authorized anything. Every row in the block
passed anyway, because a refusal nobody reads is not a failing row.

**Three of these mutations exist because a row here was wrong and this campaign
is what showed it.**

`digest` shipped a length-prefix mutation that survived: the collision row it
was supposed to kill used a shift that did not actually collide, so it passed
with the prefix deleted. The row is now built from a pair that hashes
identically once the prefix is gone, and the mutation kills five rows.

`digest` also shipped an order mutation that survived, twice. The row used two
entries, and reversing a two-element list happens to produce the sorted order
— so it passed with `sort_by` deleted. It is now three entries on three paths.
Both of those were found by running this file, not by reading it.

**Every mutation here is checked for having applied before its result is
reported.** A mutation whose search text does not match — because `cargo fmt`
reflowed the line, or a previous campaign left the file different — is a
no-op, and a no-op in this framework used to read as a pass. `sts_falsify.py`
grew an `apply` guard for exactly this reason and it is worth restating: the
most dangerous outcome in a falsification campaign is a green that measures
nothing.
"""

import sys
from pathlib import Path

import sts_falsify as f

INTENT = f.REPO / "crates/domain/src/intent.rs"
PLAN = f.REPO / "crates/integrations/src/plan.rs"
TOOL = f.REPO / "crates/integrations/src/tool.rs"
EXECUTE = f.REPO / "crates/integrations/src/execute.rs"

# --- binding ---------------------------------------------------------------
# The binding must record the *plan's* tool. Copying the intent's claim is the
# failure the whole module exists to prevent: at execution time the claim would
# be compared against what execution resolved, and one half of that comparison
# would be the caller's own assertion.
BINDING = [
    (
        "copy the intent's tool into the binding instead of the plan's",
        """            tool: self.tool.clone(),""",
        """            tool: intent.tool.clone(),""",
        "a_tool_agnostic_intent_does_not_make_the_binding_tool_agnostic",
    ),
    (
        "drop the tool from the binding entirely, making every plan tool-agnostic",
        """            tool: self.tool.clone(),""",
        """            tool: None,""",
        "a_tool_agnostic_intent_does_not_make_the_binding_tool_agnostic",
    ),
    (
        # The check and the record are two different promises, and this one
        # only breaks the *check*. A binding built from a false claim is still
        # refused, so this kills a row the copy-the-intent mutation cannot:
        # the plan would bind an intent naming an executable it never resolved.
        "skip the tool comparison at bind time",
        """        if let (Some(claimed), Some(planned)) = (&intent.tool, &self.tool) {""",
        """        if let (Some(claimed), Some(planned)) = (&intent.tool, &self.tool) && false {""",
        "an_intent_claiming_a_different_tool_is_refused_at_bind_time",
    ),
    (
        "skip the drift check at bind time, binding an intent the world contradicts",
        """        match &intent.config_fingerprint {
            Some(claimed) if *claimed != config_digest => {""",
        """        match &intent.config_fingerprint {
            Some(_claimed) if false => {""",
        "an_intent_naming_a_different_configuration_is_refused_at_bind_time",
    ),
]

# --- digest ----------------------------------------------------------------
# `field_into` is the only thing standing between two configurations and one
# digest. Without the length prefix the stream is `name || value || …`, and a
# byte can be shifted across a value boundary to make two different plans hash
# the same.
LENGTH_PREFIX = """    hasher.update((name.len() as u32).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);"""

DIGEST = [
    (
        "hash the fields without a length prefix",
        LENGTH_PREFIX,
        "    let _ = (name, value);",
        "two_different_configurations_cannot_produce_the_same_digest",
    ),
    (
        "do not sort entries before hashing, so entry order decides the digest",
        """        ordered.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.selector.to_string().cmp(&b.selector.to_string()))
        });""",
        "",
        "the_configuration_digest_does_not_depend_on_entry_order",
    ),
    (
        "leave the family out of the hash, so a digest travels between families",
        """        field_into(&mut hasher, b"family", self.family.as_bytes());""",
        "",
        "a_digest_does_not_travel_between_families",
    ),
    (
        "skip the file owner, which `revalidate` does compare",
        """            field_into(&mut hasher, b"uid", &f.owner_uid.to_be_bytes());""",
        "",
        "every_fingerprint_dimension_changes_the_configuration_digest",
    ),
    (
        "skip the resolved path, so a symlink retargeted elsewhere keeps its digest",
        """            field_into(
                &mut hasher,
                b"resolved",
                f.resolved_path.as_os_str().as_encoded_bytes(),
            );""",
        "",
        "every_fingerprint_dimension_changes_the_configuration_digest",
    ),
]

# --- tool ------------------------------------------------------------------
# The resolver refuses an executable others can replace, refuses the whole
# search if it finds nothing, and follows a symlink to the file that runs.
TOOL_MUTATIONS = [
    (
        "accept an executable writable by group or other",
        """    if meta.mode() & UNTRUSTED_WRITE_BITS != 0 {
        return CandidateOutcome::UntrustedWritable { mode: meta.mode() };
    }""",
        "",
        "an_executable_writable_by_group_or_other_is_refused",
    ),
    (
        "search the whole PATH and keep the last match instead of the first",
        """        if chosen.is_some() {
            // First match wins, exactly as the shell and `execvp` do it. The
            // remaining directories are not consulted, which is why they are
            // not reported either: reporting a directory as "searched" when
            // the search had already stopped would be a lie about the search.
            break;
        }""",
        "",
        "the_first_directory_holding_the_command_wins",
    ),
    (
        "hash only the first chunk of a large executable",
        """        hasher.update(&buffer[..read]);""",
        """        hasher.update(&buffer[..read]);
        break;""",
        "a_file_larger_than_the_read_buffer_is_hashed_whole",
    ),
]

# --- invalidation ----------------------------------------------------------
# Every variant of `PlanInvalidation` is reachable, and expiry outranks drift.
# A check that answers "true" for an expired request is a check that passes on
# a dead credential.
INVALID = [
    (
        "check the world before the clock, so a drifted world hides the expiry",
        """        if now_unix >= expires_at_unix {
            return Err(PlanInvalidation::Expired {
                expires_at_unix,
                now_unix,
            });
        }""",
        "",
        "expiry_is_reported_before_any_drift",
    ),
    (
        "make a tool match on its digest alone, so a hijack at another path passes",
        """        self.digest == other.digest && self.path == other.path""",
        """        self.digest == other.digest""",
        "a_tool_matches_only_on_both_path_and_bytes",
    ),
    (
        "accept any `sha256:`-looking string as a digest",
        """    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))""",
        """    !hex.is_empty()""",
        "a_malformed_tool_digest_is_refused",
    ),
]

# --- chain -----------------------------------------------------------------
# Through the product surface. The receipt is the artefact; a chain that
# computed the right answer and wrote a receipt that could not be re-checked
# would have delivered nothing an operator can use later.
CHAIN = [
    (
        "re-resolve the tool the way the plan did, so the world cannot move",
        """    let observed_tool = match asv_integrations::resolve_tool(tool_command, &path_var) {""",
        """    let observed_tool = match Ok::<_, std::io::Error>(planned_tool.clone()) {""",
        "the_npm_chain_runs_every_stage_and_writes_a_receipt",
    ),
]

# **There is deliberately no mutation for "the second resolution is fresh".**
#
# It is the property the whole block rests on, and this campaign cannot falsify
# it from here — and saying so is worth more than an entry that always survives
# and teaches the reader to skim past the survivors.
#
# `observed_tool = planned_tool.clone()` in the CLI is indistinguishable from
# the real thing in a single invocation: both calls read the same `PATH` micro-
# seconds apart and nothing can change in between, so the two JSON blocks are
# byte-identical either way. The row one would point at,
# `a_hijacked_npm_invalidates_a_real_bound_plan`, is worse — it calls
# `asv_integrations::decide` **in process** and never reads `main.rs` at all, so
# no CLI mutation can reach it. That is a bucket pointed at a target that does
# not contain its row, which is the `no-run` failure this framework exists to
# make loud.
#
# What covers it instead: the drift rows drive `decide` with a world that really
# moves, and the CLI rows cover the wiring. Between them the second resolution
# is exercised; neither alone would be enough, and no row here can stand in for
# a swap that lands mid-invocation.

# --- stake ----------------------------------------------------------------
# What the receipt says is at stake. R4.B.2 added the inventory to `execute`
# and the accessors that count what it bound, and every one of these is a
# question a reader of a receipt has to be able to ask without counting `Binding`
# arms by hand.
#
# **The empty case is the easy one and these rows are not about it.** A receipt
# that reports nothing bound is right by default; the mutation that would break
# it is `Vec::new()`, and that one lives in the CLI bucket below because that is
# where the change to undo lives.
STAKE = [
    (
        # The row this mutation is aimed at is about *ambiguity*, not about
        # emptiness: two bearer tokens, one selector, and nothing in the
        # inventory that could say which is the registry one. `entries` is
        # non-empty there, so an emptiness test reports a decided spend for a
        # binding that `plan` deliberately refused to make.
        "ask whether the plan had any entries rather than whether anything bound",
        """    pub fn bound_anything(&self) -> bool {
        self.bound_count() > 0
    }""",
        """    pub fn bound_anything(&self) -> bool {
        !self.plan.entries.is_empty()
    }""",
        "an_ambiguous_binding_is_not_reported_as_a_spend",
    ),
    (
        "count every selector as bound, whatever its binding says",
        """            .filter(|entry| matches!(entry.binding, crate::plan::Binding::Bound { .. }))""",
        """            .filter(|_entry| true)""",
        "a_selector_nothing_could_serve_is_counted_as_unbound_not_absent",
    ),
    (
        "report nothing unbound, so the two counts stop adding up to the selectors",
        """    pub fn unbound_count(&self) -> usize {
        self.plan.entries.len().saturating_sub(self.bound_count())
    }""",
        """    pub fn unbound_count(&self) -> usize {
        0
    }""",
        "the_two_counts_always_add_up_to_the_selectors",
    ),
    (
        "report nothing as at stake, however much the plan bound",
        """                crate::plan::Binding::Bound { credential, .. } => Some(*credential),
                _ => None,""",
        """                _ => None,""",
        "a_bound_plan_names_the_credential_the_execution_would_spend",
    ),
    (
        # The structural one. A receipt that does not carry its plan cannot name
        # a credential, cannot be re-checked, and cannot distinguish "bound
        # nothing" from "there was nothing to bind" — which is the whole of what
        # R4.B.2 added.
        "build the receipt over an empty plan instead of the one it was checked against",
        "            plan: plan.clone(),",
        '            plan: crate::plan::IntegrationPlan::new("npm", Vec::new(), 0),',
        "the_receipt_carries_the_plan_it_was_checked_against",
    ),
]

# --- inventory ------------------------------------------------------------
# Through the product surface, against a **live broker**. R4.B.1 shipped this
# command planning against `Vec::new()` on purpose, and R4.B.2's whole content is
# the difference — so the mutation that reverts it belongs here and nowhere
# else.
#
# These point at `r4b2_bound_execute.rs` rather than at `r4b1_intent_chain.rs`,
# because a row can only falsify a mutation when the fixture reaches the code
# being mutated: R4.B.1's rows all run with `--no-vault` precisely because they
# have no broker, so an inventory mutation there would be measured against a
# chain that never asked.
INVENTORY = [
    (
        "plan against an empty inventory without being asked to, as R4.B.1 shipped",
        """    let inventory: Vec<asv_domain::CredentialMetadata> = if no_vault {""",
        """    let inventory: Vec<asv_domain::CredentialMetadata> = if true {""",
        "an_execution_over_a_live_vault_names_the_credential_it_would_spend",
    ),
    (
        # Found by running this command against a broker that was actually
        # there. The summary was true, protocol-shaped, and useless: the broker
        # had said *why* and the receipt dropped it, so an operator reading
        # "the broker answered Error" went looking for a protocol fault instead
        # of reading the session check that refused them.
        "summarise the broker's refusal instead of carrying it",
        """            reason: format!("the broker refused the authorization: {message}"),""",
        """            reason: format!("the broker answered Error to an authorization request"),""",
        "a_session_from_another_process_is_refused_with_the_brokers_own_reason",
    ),
    (
        # The bug this bucket found by accident: `--session` was mandatory, the
        # broker pins a session to a PID, and so nothing an operator could type
        # ever authorized anything. Reverting to the mandatory flag makes every
        # row in the file still pass except the one about the session, which is
        # why that row exists.
        "never open a session, and let the authorization answer for the absence",
        """        None => match call(
            socket,
            &Request::CreateSession {
                workspace: workspace.to_string(),
            },
        ) {
            Ok(Response::SessionCreated { session, .. }) => Some(session.to_string()),""",
        """        None => match call(socket, &Request::ListCredentialMetadata) {
            Ok(Response::CredentialMetadata { .. }) => Some("unopened".into()),""",
        "an_execution_authorizes_under_a_session_it_opened_itself",
    ),
]

# --- permit ----------------------------------------------------------------
# The branch R4.B.2 deliberately never took: an execution that is *permitted*.
# Everything R4.B.2 asserted is true on the denied path, and a property that has
# only ever been observed on one branch has not been observed at all.
#
# A negative row cannot be mutated into failing, and `npm_cannot_be_permitted_by_
# any_policy_the_schema_accepts` is one: it goes red when the code starts
# permitting npm, which is a mutation that would have to add a permit somewhere
# rather than remove one. So this bucket aims at the rows that carry weight.
PERMIT = [
    (
        # The receipt would say "executed" for anything the broker did not
        # refuse, which is the failure this row was written to catch: a
        # permitted execution is the branch where an operator is about to spend
        # a credential, so being wrong about it in the optimistic direction is
        # the one direction that matters.
        "execute anything the broker permitted",
        "        AuthorizationVerdict::Permit { .. } => ExecuteOutcome::Executed,",
        """        AuthorizationVerdict::Permit { .. } => ExecuteOutcome::Unauthorized {
            reason: "executed anyway".into(),
            reason_code: "Mutation".into(),
        },""",
        "a_permitted_execution_names_the_credential_it_would_spend",
    ),
]

# --- policy ----------------------------------------------------------------
# Which policy decided. Found by running the broker with `--policy` rather than
# by reading it: `PolicyEngine::result` wrote one constant for every decision it
# ever produced, so a receipt told an operator that the built-in text had
# authorised an operation their own policy file had authorised.
POLICY = [
    (
        # The load side: a delivered policy that announces itself as the built-in.
        "name every policy after the built-in one, whatever was delivered",
        "            policy_name: policy_name.to_string(),",
        "            policy_name: DEFAULT_POLICY_NAME.to_string(),",
        "the_receipt_names_the_policy_that_decided_rather_than_the_built_in",
    ),
    (
        # The report side, kept as a separate mutation because the two fail
        # differently: this one leaves the engine honest and the receipt lying.
        "report the built-in name regardless of what the engine carries",
        "            rule: self.policy_name.clone(),",
        '            rule: "m3-default-policy".into(),',
        "the_receipt_names_the_policy_that_decided_rather_than_the_built_in",
    ),
]

# One target per bucket, because the rows live in three different places, and a
# bucket pointed at a target that does not contain its row produces `no-run`.
#
# `binding`, `digest`, `tool` and `invalid` are properties of the library the
# CLI is built on, and the rows that state them precisely live in the crates'
# own test modules. `chain` is the wiring, and only a vertical can see it.
CLI = f.REPO / "crates/cli/src/main.rs"
LIB_PKG, LIB_TGT = "asv-integrations", "--lib"
DOMAIN_PKG, DOMAIN_TGT = "asv-domain", "--lib"
CHAIN_PKG, CHAIN_TGT = "asv-broker", "--test r4b1_intent_chain"
BOUND_PKG, BOUND_TGT = "asv-broker", "--test r4b2_bound_execute"
PERMIT_PKG, PERMIT_TGT = "asv-broker", "--test r4b3_permitted_execute"
POLICY_SRC = f.REPO / "crates/policy/src/lib.rs"

BUCKETS = {
    "binding": (LIB_PKG, LIB_TGT, "plan::tests::", PLAN, BINDING),
    "digest": (LIB_PKG, LIB_TGT, "plan::tests::", PLAN, DIGEST),
    "tool": (LIB_PKG, LIB_TGT, "tool::tests::", TOOL, TOOL_MUTATIONS),
    "invalid": (DOMAIN_PKG, DOMAIN_TGT, "intent::tests::", INTENT, INVALID),
    "chain": (CHAIN_PKG, CHAIN_TGT, "", CLI, CHAIN),
    "stake": (LIB_PKG, LIB_TGT, "execute::tests::", EXECUTE, STAKE),
    "inventory": (BOUND_PKG, BOUND_TGT, "", CLI, INVENTORY),
    "permit": (PERMIT_PKG, PERMIT_TGT, "", EXECUTE, PERMIT),
    "policy": (PERMIT_PKG, PERMIT_TGT, "", POLICY_SRC, POLICY),
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "binding"
    package, target, prefix, source, mutations = BUCKETS[mode]
    f.PACKAGE = package
    f.CARGO_TARGET = target
    f.TEST_PREFIX = prefix
    f.STS = source
    f.BUCKET_COUNT_LABEL = "nine"
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {source.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    raise SystemExit(main())