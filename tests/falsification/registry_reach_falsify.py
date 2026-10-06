#!/usr/bin/env python3
"""Falsification for R2.F.3c: the advertisement and the relation surface.

This increment fixed two defects that had the same shape -- *built and not
announced*. `PullManifest` and `PullBlob` were dispatched, tested and
falsified, and `selfreport` did not advertise them; and the relation vocabulary
learned about the verbs only by being extended. A feature nobody is told about
is not reachable, which is R1's lesson applied to discovery rather than to
execution.

**Two files are covered and two are declared uncovered, and the reason is the
same in both cases.**

Covered: `crates/broker/src/selfreport.rs` and
`crates/cli/src/agent/relations.rs`. Both are exercised by in-process tests, so
a mutation costs one `cargo test` and nothing else.

Not covered: `crates/cli/src/main.rs` (`run_registry`) and
`crates/broker/src/main.rs` (the `--registries` flag). The rows that cover them
live in `crates/broker/tests/r2f_cli_reachability.rs`, which spawns the real
`asv` and `asv-brokerd`. `asv_broker::binary::locate` **panics** when the binary
on disk is older than the source -- a deliberate guard against measuring a stale
binary -- so a mutation to either file makes every row in that file fail on the
locator rather than on the property. A campaign that reported those as "red"
would be claiming falsifications it never ran.

They are not left without evidence, and the substitute is a paired-row argument
rather than a mutation: `a_declaration_file_reaches_the_daemon` and
`a_deployment_with_no_declaration_file_declares_nothing` issue the *same*
request against the *same* vault with the *same* binaries and differ only in
whether `--registries` was passed, and they assert opposite things about the
resulting message. Delete the flag and the pair stops agreeing.

**Each mutation names its own cargo target**, because a source file is not read
by one test binary. `selfreport.rs` is exercised by the broker's *lib* tests and
by the registry vertical's integration test, and the first version of this
harness carried the target at phase level: with `--lib`, the two mutations aimed
at the integration rows reported `no-run`, because cargo matched zero tests. That
is the outcome this harness exists to keep visible -- a row that never ran is not
a row that passed.

**The mutation to read first is `PullManifest` classified as plumbing.** It is
the exact shape of the defect this increment was born from, and it demonstrates
the fix works: with the sample containing both variants,
`every_advertised_capability_is_handled` goes red, because
`registry.manifest.read` is advertised and no request in the sample answers to
it. That row could not have caught the original defect -- the sample did not
contain the variants -- which is why the sample is fixed in the same increment
rather than afterwards.

**The fourth mutation is the tripwire.** `the_sample_has_the_size_this_file_claims`
was, until this increment, named `the_sample_covers_every_request_variant` and
asserted a literal against a literal: it stayed green while two variants went
missing from the sample. It is now named for what it proves, and this mutation
deletes a line from the sample to show the *renamed* row still has teeth. A
tripwire nobody checks is a comment.

Run:  python3 registry_reach_falsify.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

SELFREPORT = f.REPO / "crates/broker/src/selfreport.rs"
RELATIONS = f.REPO / "crates/cli/src/agent/relations.rs"

ENV = dict(os.environ)

# (cargo target, package, row-name prefix).
# The broker's lib tests, where `capability_of`'s sync rows live.
LIB = ("--lib", "asv-broker", "selfreport::tests::")
# The CLI's relation tests. The *binary* target, not the lib: `Cli::command()` --
# the parser the row actually runs -- is defined in `main.rs`.
CLI = ("--bin asv", "asv-cli", "agent::relations::tests::")
# The registry vertical: an integration target, so its row names carry no module
# path.
VERTICAL = ("--test r2f_registry_vertical", "asv-broker", "")

# (label, old, new, row that must go red, target)
SELFREPORT_MUTATIONS = [
    (
        # The defect, restated as a mutation. A capability advertised with no
        # request behind it is a promise the broker cannot keep, which is
        # precisely what `every_advertised_capability_is_handled` exists to
        # refuse.
        #
        # **The mutation had to change shape when `compiled_capabilities()`
        # stopped being a second list.** It used to be derived from
        # `CAPABILITIES`, so `served` and `advertised` now read the same table
        # and a `Some(..) -> None` edit removes the capability from *both*
        # sides at once: the row stayed green no matter what. Classifying the
        # request as plumbing is therefore no longer a mutation of anything
        # this row can see. The only disagreement the row can still witness is
        # a capability that is advertised but unreachable, which is a key that
        # matches no method -- so that is what this edits.
        "advertise a capability no request can serve",
        '    ("registry_pull_manifest", Some("registry.manifest.read")),',
        '    ("registry_pull_manifest_typo", Some("registry.manifest.read")),',
        "every_advertised_capability_is_handled",
        LIB,
    ),
    (
        # The whole increment in one line: a pull the broker serves and does not
        # name. An agent reading its capabilities concludes the product cannot
        # pull, and it is right about what it read.
        "stop advertising the blob read",
        '    ("registry_pull_blob", Some("registry.blob.read")),',
        '    ("registry_pull_blob", None),',
        "an_agent_asking_what_the_broker_can_do_is_told_about_registry",
        VERTICAL,
    ),
    (
        # One name for two requests.
        #
        # **This mutation survived its first row, and the reason is a structural
        # fact worth stating rather than a fix.** It was aimed at
        # `a_manifest_and_a_blob_are_advertised_as_two_operations`, which counts
        # the `registry.*` entries in the advertisement -- and the
        # advertisement is `compiled_capabilities`, a static list that this
        # mutation does not touch. `capability_of` lives inside
        # `#[cfg(test)] mod tests`: it exists so the sync rows can *read* the
        # classification, so no mutation of it can change what the broker
        # advertises. The row was right and the mutation was aimed at the wrong
        # thing; this one counts the classification itself.
        "classify a blob read under the manifest's name",
        '    ("registry_pull_blob", Some("registry.blob.read")),',
        '    ("registry_pull_blob", Some("registry.manifest.read")),',
        "two_operations_do_not_share_one_capability_name",
        LIB,
    ),
    (
        # The tripwire itself. This is what the old row could not do: it counts
        # the sample, and the sample is the list the coverage rows read, so a
        # variant dropped from it stops being covered by any of them.
        "drop the blob pull from the enumerated sample",
        """            Request::PullBlob {
                session,
                surrogate: surrogate.clone(),
                registry: String::new(),
                repository: String::new(),
                digest: String::new(),
            },
""",
        "",
        "the_sample_has_the_size_this_file_claims",
        LIB,
    ),
]

RELATIONS_MUTATIONS = [
    (
        # A relation that exists and is never published is a verb an agent
        # cannot find, which is the same defect as a capability that is not
        # advertised, one layer out.
        "stop publishing the blob relation",
        "            AgentRel::RegistryBlobRead,\n",
        "",
        "the_core_relation_uris_are_pinned",
        CLI,
    ),
    (
        # Two relations, one URI. The pinned row is an exact list, so a rename
        # or a collision is a visible break rather than a silent one -- the URIs
        # are what an agent persists.
        "give both registry relations the same URI",
        '            AgentRel::RegistryManifestRead => "asv://rels/registry/manifest/read",',
        '            AgentRel::RegistryManifestRead => "asv://rels/registry/blob/read",',
        "the_core_relation_uris_are_pinned",
        CLI,
    ),
    (
        # The descriptor drifting from the real subcommand. This is the row that
        # caught `status --json` being advertised by a CLI that had no such flag,
        # and it is why the parser is run rather than compared to a list.
        "advertise an argv the parser rejects",
        '                &["registry", "manifest", "read"],',
        '                &["registry", "manifest", "inspect"],',
        "every_operational_relation_parses_as_a_real_command",
        CLI,
    ),
    (
        # The completion is what makes a template link a *runnable* prefix. A
        # link whose required arguments are never supplied parses as a
        # different command or not at all, and the agent discovers that by
        # spending a turn.
        "stop supplying the blob relation's required arguments",
        """            "asv://rels/registry/blob/read" => &[
                "--registry",
                "registry-1.docker.io",
                "--repository",
                "library/alpine",
                "--digest",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
""",
        "",
        "every_operational_relation_parses_as_a_real_command",
        CLI,
    ),
]


def run_phase(path: Path, mutations: list, title: str) -> dict:
    """Apply each mutation and tally the five buckets.

    A snippet this harness cannot find exactly once is a defect in the harness,
    not a result about the code, and it has its own bucket for that reason.
    """
    original = path.read_text()
    buckets = {
        "red": 0,
        "compiler-refused": 0,
        "green (SURVIVOR)": 0,
        "measured nothing": 0,
        "harness error": 0,
    }
    problems: list = []
    for label, old, new, test, target in mutations:
        if original.count(old) != 1:
            buckets["harness error"] += 1
            problems.append(
                (label, test, f"snippet counts {original.count(old)}, want 1 -- harness defect")
            )
            print(f"SKIP  {label!r}: snippet is not unique ({original.count(old)})", flush=True)
            continue
        path.write_text(original.replace(old, new, 1))
        f.CARGO_TARGET, f.PACKAGE, f.TEST_PREFIX = target
        try:
            verdict, out = f.run_test(test)
        finally:
            path.write_text(original)
        if verdict == "red":
            buckets["red"] += 1
            print(f"ok    [{title}] {label}\n      -> {test} went red", flush=True)
        elif verdict == "green":
            buckets["green (SURVIVOR)"] += 1
            problems.append((label, test, "the row stayed green"))
            print(
                f"SURVIVOR  [{title}] {label}\n      -> {test} stayed GREEN  <-- the finding",
                flush=True,
            )
        elif verdict == "refused":
            buckets["compiler-refused"] += 1
            first = next(
                (ln.strip() for ln in out.splitlines() if ln.strip().startswith("error")), "?"
            )
            print(
                f"ok*   [{title}] {label}\n      -> {test}: refused by the compiler\n         {first}",
                flush=True,
            )
        else:
            buckets["measured nothing"] += 1
            problems.append((label, test, verdict))
            print(f"BAD   [{title}] {label}\n      -> {test}: {verdict}", flush=True)
    assert path.read_text() == original, f"{path} was not restored"
    assert sum(buckets.values()) == len(mutations), (buckets, len(mutations))
    return buckets


def main() -> int:
    total = len(SELFREPORT_MUTATIONS) + len(RELATIONS_MUTATIONS)
    print(f"# falsifying the registry advertisement with {total} mutations\n")

    print(f"## phase 1 -- the broker's self-description ({SELFREPORT.relative_to(f.REPO)})")
    a = run_phase(SELFREPORT, SELFREPORT_MUTATIONS, "R2.F.3c selfreport")
    print()

    print(f"## phase 2 -- the relation vocabulary ({RELATIONS.relative_to(f.REPO)})")
    b = run_phase(RELATIONS, RELATIONS_MUTATIONS, "R2.F.3c relations")
    print()

    merged = {
        "red": a["red"] + b["red"],
        "compiler-refused": a["compiler-refused"] + b["compiler-refused"],
        "green (SURVIVOR)": a["green (SURVIVOR)"] + b["green (SURVIVOR)"],
        "measured nothing": a["measured nothing"] + b["measured nothing"],
        "harness error": a["harness error"] + b["harness error"],
    }
    print(f"mutations: {total}  (the five buckets partition the run)")
    for name, count in merged.items():
        print(f"  {name:<22}: {count}")
    print()
    print("  R2.F.3c selfreport: " + (", ".join(f"{k}={v}" for k, v in a.items() if v) or "none"))
    print("  R2.F.3c relations: " + (", ".join(f"{k}={v}" for k, v in b.items() if v) or "none"))
    print()
    print(
        "  NOT COVERED: `crates/cli/src/main.rs` (run_registry) and\n"
        "  `crates/broker/src/main.rs` (--registries). Their rows spawn the real\n"
        "  binaries and `binary::locate` panics on a stale binary, so a mutation\n"
        "  to either would fail the locator rather than the property. They are\n"
        "  covered by the paired-row argument in r2f_cli_reachability instead."
    )
    return (
        1
        if merged["green (SURVIVOR)"] or merged["harness error"] or merged["measured nothing"]
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())