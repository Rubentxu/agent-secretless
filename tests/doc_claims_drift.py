#!/usr/bin/env python3
"""Falsifiability tests for scripts/check-doc-claims.py.

A guard nobody has tried to break is a guard whose green means nothing.

The shape of this file is inherited from `tests/gate_status_drift.py`, and it
exists for the same reason. V1-C0 found twelve stale or false claims in
`README.md`, `README-es.md` and the spec pack, in files that no guard read, and
two of them were wrong about shipped behaviour rather than merely out of date:
the broker's IPC protocol was documented as v2 while `PROTOCOL_VERSION` was 4,
and both READMEs marked M11 and M12 done while the authority had them NOT MET.
A guard written after the fact and never shown able to fail would be the
thirteenth.

Each case builds a synthetic repository, mutates exactly one claim, and
requires the guard to notice. The suite-size check derives its expected value
from a stubbed `enumerated_test_names`, because running the real suite once per
case would make a unit test into an integration test and buy nothing: what is
under test is the comparison, not `cargo`. The stub returns *names* rather than
a count for the reason the check now needs one: a `--skip` filter can only be
applied to a name, and a stub of a count cannot express "this filter removes
this test".

Run: python3 tests/doc_claims_drift.py
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-doc-claims.py"

PROTOCOL_VERSION = 4
ENUMERATED = 866
PASSED = 865
IGNORED = 1
DOC_COUNT = 20
ADR_COUNT = 19

# Two of the synthetic names are spelled the way the real ones are, because the
# skip-filter cases are only meaningful if the pattern the README documents
# actually matches something in the enumeration. They are the two the shipped
# quick-start skips: a live OpenSSH round trip and a p95 latency budget.
SKIPPED_IN_FIXTURE = (
    "ssh_agent::uat_028_openssh_authenticates_through_the_broker_socket",
    "broker::one_hundred_brokered_reads_stay_under_the_p95_budget",
)


def synthetic_test_names(count: int = ENUMERATED) -> list[str]:
    names = list(SKIPPED_IN_FIXTURE)
    names += [f"crate{i}::unit::test_{i:04d}" for i in range(count - len(names))]
    return names


def load_guard():
    spec = importlib.util.spec_from_file_location("doc_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def build_tree(root: Path) -> dict[str, Path]:
    """A repository that is correct in every respect, so each case breaks one thing."""
    docs = root / "agent-secretless-vault-spec" / "docs"
    adrs = root / "agent-secretless-vault-spec" / "adrs"
    ipc = root / "crates" / "ipc-protocol" / "src"
    docs.mkdir(parents=True)
    adrs.mkdir(parents=True)
    ipc.mkdir(parents=True)

    # 20 documents in total: the two the guard reads by name, plus 18 more.
    (docs / "15-ROADMAP.md").write_text(
        "# ROADMAP\n\n## Status vocabulary\n\n"
        + "| State | Meaning |\n|---|---|\n"
        + "| verified | claimed and green |\n| implemented | exercised, not proven |\n"
        + "| host-dependent | needs another host |\n| prototype | shape only |\n",
        encoding="utf-8",
    )
    (docs / "16-SECURITY-RELEASE-GATES.md").write_text(
        "# Gates\n\n| Gate | Status | Evidence |\n|---|---|---|\n"
        "| M8 eBPF research gate | **NO-GO** — `verified` as a decision | evidence |\n"
        "| M11 live OAuth2 provider | **prototype** — no live provider | evidence |\n"
        "| R11 full suite | pass | fine |\n",
        encoding="utf-8",
    )
    for i in range(DOC_COUNT - 2):
        (docs / f"filler-{i:02d}.md").write_text(f"# filler {i}\n", encoding="utf-8")
    for i in range(ADR_COUNT):
        (adrs / f"{i:04d}-decision-{i}.md").write_text(f"# ADR {i}\n", encoding="utf-8")
    (adrs / "adr-index.md").write_text("# index\n", encoding="utf-8")

    (ipc / "lib.rs").write_text(
        f"pub const PROTOCOL_VERSION: u16 = {PROTOCOL_VERSION};\n", encoding="utf-8"
    )

    readme = (
        f"# ASV\n\n"
        f"The broker speaks protocol v{PROTOCOL_VERSION}.\n\n"
        f"There are {ENUMERATED} tests.\n\n"
        f"```bash\ncargo test --workspace --release\n"
        f"# expected: passed={PASSED} failed=0 ignored={IGNORED}\n```\n\n"
        f"The pack holds {DOC_COUNT} documents and {ADR_COUNT} ADRs.\n"
    )
    (root / "README.md").write_text(readme, encoding="utf-8")
    (root / "README-es.md").write_text(
        readme.replace("protocol v", "protocolo v"), encoding="utf-8"
    )

    return {
        "root": root,
        "readme": root / "README.md",
        "readme_es": root / "README-es.md",
        "gates": docs / "16-SECURITY-RELEASE-GATES.md",
        "roadmap": docs / "15-ROADMAP.md",
        "ipc": ipc / "lib.rs",
    }


def run_checks(tree: dict[str, Path], stub_names: list[str] | None = None):
    """Run every check against a synthetic tree, with cargo stubbed out.

    Returns the accumulated failures.
    """
    guard = load_guard()
    original_repo, original_names = guard.REPO, guard.enumerated_test_names
    guard.REPO = tree["root"]
    guard.enumerated_test_names = lambda: (
        synthetic_test_names() if stub_names is None else stub_names
    )
    failures: list[str] = []
    try:
        guard.check_protocol_claims(failures)
        guard.check_suite_claims(failures)
        guard.check_pack_inventory(failures)
        guard.check_no_status_in_readme(failures)
        guard.check_vocabulary(failures)
    finally:
        guard.REPO, guard.enumerated_test_names = original_repo, original_names
    return failures


def case(
    name: str,
    expect_pass: bool,
    mutate=None,
    must_contain: str = "",
):
    with tempfile.TemporaryDirectory() as tmp:
        tree = build_tree(Path(tmp))
        if mutate is not None:
            mutate(tree)
        failures = run_checks(tree)
        blob = " | ".join(failures)
        if expect_pass:
            ok = not failures
            detail = blob or "(no failures)"
        else:
            ok = bool(failures) and must_contain in blob
            detail = blob or "(no failures — the guard did not notice)"
    return name, ok, detail


def main() -> int:
    if not GUARD.exists():
        print(f"FAIL guard not found: {GUARD}")
        return 1

    results: list[tuple[str, bool, str]] = []

    # 0. The positive control. Everything else is meaningless if the clean
    #    repository does not pass, because a guard that fails on correct
    #    documents is one maintainers disable on its first good day.
    results.append(case("a correct repository passes every check", expect_pass=True))

    # 1. The exact drift V1-C0 found: the documented protocol is two majors
    #    behind the constant. This is the case that proves the guard reads the
    #    code rather than a second document that could drift with the first.
    results.append(
        case(
            "a stale protocol version is caught in the English README",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    f"protocol v{PROTOCOL_VERSION}", "protocol v2"
                ),
                encoding="utf-8",
            ),
            must_contain="protocol v2",
        )
    )

    # 2. Same claim, other language. A guard that only reads README.md is a
    #    guard that lets the translation drift alone, which is the failure the
    #    existing README-count check was written to prevent.
    results.append(
        case(
            "a stale protocol version is caught in the Spanish README",
            expect_pass=False,
            mutate=lambda t: t["readme_es"].write_text(
                t["readme_es"].read_text(encoding="utf-8").replace(
                    f"protocolo v{PROTOCOL_VERSION}", "protocolo v2"
                ),
                encoding="utf-8",
            ),
            # The message quotes the captured number, not the word that
            # preceded it, so it reads "protocol v2" in either language.
            must_contain="protocol v2",
        )
    )

    # 3. The count that drifted by 174 without anything noticing.
    results.append(
        case(
            "a stale quick-start test count is caught",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    f"passed={PASSED} failed=0 ignored={IGNORED}", "passed=692 failed=0 ignored=1"
                ),
                encoding="utf-8",
            ),
            must_contain="693",
        )
    )

    # 4. The bare `N tests` token, which the old quick-start block did not have
    #    and the status line does.
    results.append(
        case(
            "a stale 'N tests' sentence is caught",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    f"There are {ENUMERATED} tests.", "There are 424 tests."
                ),
                encoding="utf-8",
            ),
            must_contain="424",
        )
    )

    # 5. The failure mode this whole cycle exists to close: a second copy of
    #    the milestone status in the README.
    results.append(
        case(
            "milestone status in a README is caught",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8")
                + "\n| M11 | OAuth2 framework | done |\n| M11 \u2705 | framework | tag |\n",
                encoding="utf-8",
            ),
            must_contain="second authority",
        )
    )

    # 6. The pack inventory. "15 ADRs" when there were nineteen.
    results.append(
        case(
            "a stale ADR count is caught",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    f"{ADR_COUNT} ADRs", "15 ADRs"
                ),
                encoding="utf-8",
            ),
            must_contain="15 ADRs",
        )
    )

    # 7. Vocabulary uniformity: a milestone row that answers a different
    #    question from the rest of the table.
    results.append(
        case(
            "a milestone row without a state is caught",
            expect_pass=False,
            mutate=lambda t: t["gates"].write_text(
                t["gates"].read_text(encoding="utf-8").replace(
                    "**prototype** — no live provider", "**NOT MET** — nothing"
                ),
                encoding="utf-8",
            ),
            must_contain="without naming one of",
        )
    )

    # 8. The subtle one. If the roadmap stops defining the vocabulary, every
    #    row's state becomes undefined and the check would silently stop
    #    meaning anything. It has to fail on the missing definition rather than
    #    pass on rows that happen to still carry a word.
    results.append(
        case(
            "a roadmap that stops defining the vocabulary is caught",
            expect_pass=False,
            mutate=lambda t: t["roadmap"].write_text(
                t["roadmap"].read_text(encoding="utf-8").replace(
                    "## Status vocabulary", "## Something else"
                ),
                encoding="utf-8",
            ),
            must_contain="no longer defines the status vocabulary",
        )
    )

    # 9. `adr-index.md` is the index, not a decision. Counting it would make
    #    adding an index row break the build, and a guard that punishes
    #    bookkeeping is a guard that gets special-cased.
    results.append(
        case(
            "the ADR index is not counted as a decision",
            mutate=lambda t: (t["root"] / "agent-secretless-vault-spec" / "adrs"
                              / "adr-index.md").write_text("# index\n", encoding="utf-8"),
            expect_pass=True,
        )
    )

    # 10. Gate rows are not milestone rows. R11 is a pass/fail against a
    #     criterion and is not required to name a capability state; failing it
    #     would push the table toward vocabulary it does not need.
    results.append(
        case(
            "a non-milestone row is not required to name a state",
            mutate=lambda t: t["gates"].write_text(
                t["gates"].read_text(encoding="utf-8").replace(
                    "| R11 full suite | pass | fine |",
                    "| R11 full suite | pass with warning | fine |",
                ),
                encoding="utf-8",
            ),
            expect_pass=True,
        )
    )

    # 11. Prose about a version must not be read as a version claim. The guard
    #     matches `protocol v<N>`; a sentence that merely mentions the word has
    #     no number to be wrong about.
    results.append(
        case(
            "prose mentioning the protocol without a version is not a claim",
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8")
                + "\nThe protocol version is negotiated at start-up.\n",
                encoding="utf-8",
            ),
            expect_pass=True,
        )
    )

    # 12. The false claim this increment was written for, in miniature. The
    #     block skips a test and then claims the full count: the sum
    #     `passed + ignored` is arithmetically consistent with the enumeration
    #     and the claim is still impossible, because the command cannot run the
    #     test it skipped. The sum-only version of this check passed it.
    results.append(
        case(
            "a quick start that skips a test and claims the full count is caught",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    "cargo test --workspace --release\n",
                    "cargo test --workspace --release -- --skip uat_028\n",
                ),
                encoding="utf-8",
            ),
            must_contain="exclude 1 of them",
        )
    )

    # 13. The control for case 12. The same command, with the count corrected to
    #     what it can actually pass, must pass — otherwise the check would be
    #     punishing the honest document instead of the false one, which is how
    #     a guard gets disabled.
    results.append(
        case(
            "a quick start that skips a test and claims only what it can run passes",
            expect_pass=True,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8")
                .replace(
                    "cargo test --workspace --release\n",
                    "cargo test --workspace --release -- --skip uat_028\n",
                )
                .replace(
                    f"passed={PASSED} failed=0 ignored={IGNORED}",
                    f"passed={PASSED - 1} failed=0 ignored={IGNORED}",
                ),
                encoding="utf-8",
            ),
        )
    )

    # 14. A filter that matches nothing removes nothing. A typo in `--skip` must
    #     not lower the ceiling and turn a correct document into a failure; the
    #     guard cannot know whether the author meant to skip that test, and
    #     guessing is how a guard starts refusing work it should do.
    results.append(
        case(
            "a --skip filter that matches no test does not lower the ceiling",
            expect_pass=True,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    "cargo test --workspace --release\n",
                    "cargo test --workspace --release -- --skip uat_999_no_such_test\n",
                ),
                encoding="utf-8",
            ),
        )
    )

    # 15. Two filters, both real: the shipped shape, where the count that is
    #     impossible is off by exactly the number the filters exclude. A check
    #     that only ever sees one filter would still pass this claim.
    results.append(
        case(
            "two skip filters are both counted",
            expect_pass=False,
            mutate=lambda t: t["readme"].write_text(
                t["readme"].read_text(encoding="utf-8").replace(
                    "cargo test --workspace --release\n",
                    "cargo test --workspace --release -- "
                    "--skip uat_028 --skip one_hundred_brokered_reads\n",
                ),
                encoding="utf-8",
            ),
            must_contain="exclude 2 of them",
        )
    )

    # 16. The real repository, through the real entry point. Everything above
    #     drives the check functions against synthetic trees; this runs the
    #     guard as CI runs it. It is the control that says the synthetic cases
    #     are testing the shipped behaviour and not a parallel implementation.
    proc = subprocess.run(
        [sys.executable, str(GUARD)], cwd=REPO, capture_output=True, text=True, check=False
    )
    results.append(
        (
            "the real repository passes the guard as CI runs it",
            proc.returncode == 0 and "consistent" in proc.stdout,
            (proc.stdout + proc.stderr).strip() or "(no output)",
        )
    )

    print("Document-claims guard falsifiability\n")
    failures = 0
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures += 1
            print(f"        {detail}")

    print(f"\n{len(results) - failures}/{len(results)} behaviours confirmed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
