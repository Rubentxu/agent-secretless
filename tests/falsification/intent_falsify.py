#!/usr/bin/env python3
"""Falsifying R4.B.1's intent chain, in the four files it spans.

`r4b1_intent_chain.rs` and the 240-odd rows in `crates/domain` and
`crates/integrations` assert that a plan bound to an intent notices when the
world moves under it. Until this harness existed they were rows that passed,
which is the weakest thing a row can be: a row nobody has tried to break
measures nothing about whether it can fail.

Five buckets, run one per invocation like every other harness here:

    python3 intent_falsify.py binding   # whose word the binding records
    python3 intent_falsify.py digest    # what goes into the config digest
    python3 intent_falsify.py tool      # how the executable is resolved
    python3 intent_falsify.py invalid   # which drift the check reaches
    python3 intent_falsify.py chain     # the wiring, through the real binary

**Two of these mutations exist because a row here was wrong and this campaign
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

BUCKETS = {
    "binding": (LIB_PKG, LIB_TGT, "plan::tests::", PLAN, BINDING),
    "digest": (LIB_PKG, LIB_TGT, "plan::tests::", PLAN, DIGEST),
    "tool": (LIB_PKG, LIB_TGT, "tool::tests::", TOOL, TOOL_MUTATIONS),
    "invalid": (DOMAIN_PKG, DOMAIN_TGT, "intent::tests::", INTENT, INVALID),
    "chain": (CHAIN_PKG, CHAIN_TGT, "", CLI, CHAIN),
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "binding"
    package, target, prefix, source, mutations = BUCKETS[mode]
    f.PACKAGE = package
    f.CARGO_TARGET = target
    f.TEST_PREFIX = prefix
    f.STS = source
    f.BUCKET_COUNT_LABEL = "five"
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {source.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    raise SystemExit(main())