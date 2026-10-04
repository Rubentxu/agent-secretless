#!/usr/bin/env python3
"""Check the claims the shipped documents make about the repository itself.

Every other guard in this repository checks code, tests or configuration. None
of them checked `README.md`, `README-es.md` or the spec pack, and V1-C0 found
why that matters by measurement rather than by argument: a rebaseline of the
authority found **twelve** stale or false claims living in exactly the files
nothing was reading. Two were outright wrong about shipped behaviour — the
broker's IPC protocol was stated as v2 while `PROTOCOL_VERSION` was 4, and both
READMEs carried a milestone table marking M11 and M12 `✅` while the authority
had them as NOT MET — and a third, `passed=692` in the quick-start block, had
drifted by 174 tests without a single failing check.

Rewriting those twelve lines fixes today. This script is what stops it being
tomorrow's drift, and it is the reason the rebaseline is more than prose.

## What it does and does not check

Each check below is a claim a person could make in a document and a machine
could refute. The filter is that the *repository* must be able to decide it. A
sentence about intent or about a host this machine is not cannot be checked
here, and a guard that tried would be asserting an author's intention.

Checked:

- **Protocol version.** A README stating `protocol v<N>` must agree with
  `PROTOCOL_VERSION` in `crates/ipc-protocol/src/lib.rs`. The bump that
  invalidated this claim was a real, deliberate protocol change, and the
  document that describes the product to users was not updated with it.
- **Suite size.** Every `N tests` token in every shipped README, and the
  `passed=N … ignored=N` arithmetic of the quick-start block, must agree with
  what `cargo test -- --list` enumerates. The arithmetic is checked against the
  tests the documented command can *reach*: the block's own `--skip` filters are
  parsed and every enumerated name matching one is subtracted, so a block that
  skips a test and then claims the full count is caught. This replaced a weaker
  sum-only check whose stated justification — that deriving the split would mean
  running the whole suite — measurement refuted; see "Why the split is derivable
  after all" below for the argument and for the part that genuinely is not
  derivable.
- **Spec-pack inventory.** "20 documents, 19 ADRs" must match the filesystem.
  The count was 15 when there were 19.
- **Status does not live in a README.** A `M<N> ✅` in a README fails. This is
  the check that matters most, and it is the one no other guard could make: a
  second copy of the milestone status in the most-read file in the repository
  is a second authority, and it is a second authority that nothing contradicts.
- **Vocabulary uniformity.** Every milestone row in the gates table must carry
  one of the four states the roadmap defines — `verified`, `implemented`,
  `host-dependent`, `prototype`. A row that says "pass" or "MET" without one of
  them is answering a different question, and a reader comparing rows has no
  way to know which.

## Design notes

It deliberately does not hardcode expected values — not 866, not 4, not 19. A
guard that pins "866 tests" fails the moment a test is added, which is the
normal case, and teaches maintainers to edit the guard instead of reading the
document. The job is to catch contradiction.

## Why the split is derivable after all

The first version of the suite-size check compared `passed + ignored` against the
enumerated total, and its docstring defended the sum on the grounds that
"deriving the passed and ignored split would mean running the whole suite".
Measurement found the argument wrong on its own terms. The quick-start block
documents the command that produced the number, and that command carries its own
`--skip` filters; `cargo test -- --list` — already invoked, already cached — emits
the full name of every test, so the tests the command cannot reach are countable
without executing anything. A block that skipped one test and claimed the full
total was green under the sum, because the claim it was making was
arithmetically impossible.

The limit that does remain: the guard can bound how many tests the command can
run, but it cannot say *which* of the reachable ones are `ignored` rather than
`passed`, because that depends on the profile the command is built with. That is
not a small gap. `uat_030_perf` carries
`#[cfg_attr(debug_assertions, ignore = "…")]` on its p95 budget, so the same
enumerated test is `ignored` under `cargo test` and `passed` under
`cargo test --release` — measured, 1490us against a 6000us budget on this host.
A prose sentence about "0 ignored" that names no profile is therefore outside
what this guard can refute, and the fix for that class is to make the sentence
name the profile rather than to teach the guard to guess it.

It re-derives the suite size itself rather than reading it out of the gates
table, even though `scripts/check-gate-status.py` enumerates the same thing in
the same pipeline stage. A guard that trusts another guard's parse of the same
file fails when both are wrong, and the cost is one cached `cargo test --list`.

Unknown shapes are ignored, not failed, exactly as in `check-gate-status.py`: a
claim this guard does not understand is not a claim it may punish.

Exit 0 when every recognised claim holds, 1 on any drift.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

README_CLAIM = re.compile(r"(?<![A-Za-z0-9_])(\d+)\s+tests\b", re.IGNORECASE)
# `(protocol|protocolo) v<N>` in either language. The lookbehind keeps it from
# matching the word inside an identifier, and the `v` is required so a bare
# "protocol 4" in prose is not read as a version claim.
PROTOCOL_CLAIM = re.compile(r"(?:protocol|protocolo)\s+v(\d+)\b", re.IGNORECASE)
# The quick-start arithmetic: `passed=865 failed=0 ignored=1`.
PASSED_CLAIM = re.compile(r"(?:passed|pasaron|aprobados)[=:]\s*(\d+)", re.IGNORECASE)
IGNORED_CLAIM = re.compile(r"ignored[=:]\s*(\d+)", re.IGNORECASE)
# A libtest skip filter, as it appears in a documented command. `--skip` takes a
# substring, not a glob, so the same substring rule is applied when counting the
# tests it keeps out.
SKIP_FLAG = re.compile(r"--skip\s+(\S+)")
# `cargo test`, and the two ways a documented command can narrow the run to a
# subset of the workspace. A block that names a package is describing a subset
# run, whose count is not the workspace enumeration and is not this check's
# business: refusing it would mean punishing a README for documenting how to
# test one crate.
CARGO_TEST = re.compile(r"\bcargo\s+test\b")
PACKAGE_SELECT = re.compile(r"(?:^|\s)(?:-p|--package)\s+\S+")
# A fenced code block, captured whole so a claim and the command it documents can
# be read from the same block. The pattern is deliberately loose about the info
# string: a reader is not required to label the fence `bash` for this to apply.
FENCED_BLOCK = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)
# A milestone marked with a tick anywhere in a README.
MILESTONE_TICK = re.compile(r"\bM(\d{1,2})\s*[✅✔]")

STATES = ("verified", "implemented", "host-dependent", "prototype")

# The four states are defined in the roadmap; this only requires that the
# roadmap still defines them, so that a future edit that renames one is caught
# here rather than leaving every row quietly non-conforming.
VOCABULARY_ANCHOR = "## Status vocabulary"


# Every path is derived from `REPO` at call time rather than bound at import.
#
# The first version of this file computed them as module constants, and the
# falsification suite caught the consequence immediately: it built a synthetic
# spec pack, rebound `REPO` to it, and the vocabulary check read the *real*
# gates table — so a synthetic row missing its state was reported as passing.
# Two of the suite's cases failed against a guard that was not doing what the
# test said it was. Paths are cheap to derive and a check that cannot be pointed
# at a fixture is a check that cannot be shown able to fail.
def spec_pack() -> Path:
    return REPO / "agent-secretless-vault-spec"


def gates_doc() -> Path:
    return spec_pack() / "docs" / "16-SECURITY-RELEASE-GATES.md"


def roadmap_doc() -> Path:
    return spec_pack() / "docs" / "15-ROADMAP.md"


def ipc_protocol_source() -> Path:
    return REPO / "crates" / "ipc-protocol" / "src" / "lib.rs"


def readmes() -> list[Path]:
    return [p for p in (REPO / "README.md", REPO / "README-es.md") if p.exists()]


def protocol_version() -> int | None:
    """The version the broker actually speaks, read from the constant."""
    source = ipc_protocol_source()
    if not source.is_file():
        return None
    text = source.read_text(encoding="utf-8")
    match = re.search(
        r"pub\s+const\s+PROTOCOL_VERSION\s*:\s*u16\s*=\s*(\d+)\s*;", text
    )
    return int(match.group(1)) if match else None


def enumerated_test_names() -> list[str] | None:
    """Every test the workspace enumerates, by name.

    The names are the point. A count cannot tell you which tests a documented
    `--skip` keeps out of a run, and a count is what made the quick-start's
    `passed=1194` — with a skip in the very command that produced it — pass a
    guard that was checking the claim.
    """
    proc = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--", "--list"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    names = []
    for line in proc.stdout.splitlines():
        if not line.strip() or ": test" not in line:
            continue
        names.append(line.split(": test", 1)[0].strip())
    return names


def check_protocol_claims(failures: list[str]) -> None:
    observed = protocol_version()
    if observed is None:
        failures.append(
            f"could not read PROTOCOL_VERSION from {ipc_protocol_source().name}; refusing to "
            f"pass a version claim that cannot be checked"
        )
        return
    for readme in readmes():
        text = readme.read_text(encoding="utf-8")
        for claimed in PROTOCOL_CLAIM.findall(text):
            if int(claimed) != observed:
                failures.append(
                    f"{readme.name} states protocol v{claimed}, the broker speaks v{observed}"
                )


def reachable_tests(names: list[str], patterns: list[str]) -> list[str]:
    """The tests a command carrying these `--skip` filters can still run.

    libtest's `--skip` is a substring match, so a pattern is counted the same way
    it filters. A pattern that matches nothing removes nothing: a typo in a
    filter must not lower the ceiling and manufacture a failure against a
    correct document, because a guard that punishes correct documents is one
    maintainers disable on its first good day.
    """
    return [n for n in names if not any(p in n for p in patterns)]


def check_suite_claims(failures: list[str]) -> None:
    names = enumerated_test_names()
    if names is None:
        failures.append(
            "could not enumerate the suite (cargo test --list failed); refusing to "
            "pass a count claim that cannot be checked"
        )
        return
    observed = len(names)

    for readme in readmes():
        text = readme.read_text(encoding="utf-8")
        for claimed in README_CLAIM.findall(text):
            if int(claimed) != observed:
                failures.append(
                    f"{readme.name} states {claimed} tests, {observed} are enumerated"
                )

        # The quick-start block's own arithmetic, against what the command in
        # that block can reach. A stale count fails the sum without needing the
        # suite to be run, which is the whole point: the number that drifted by
        # 174 was never re-derived by anything.
        for block in FENCED_BLOCK.findall(text):
            passed = PASSED_CLAIM.search(block)
            ignored = IGNORED_CLAIM.search(block)
            if not (passed and ignored):
                continue
            # Only a whole-workspace run carries a count this check can decide.
            # A block documenting `cargo test -p somecrate` is describing a
            # subset, and a guard that refused it would be punishing a README
            # for being helpful.
            if not CARGO_TEST.search(block) or PACKAGE_SELECT.search(block):
                continue
            patterns = SKIP_FLAG.findall(block)
            reachable = reachable_tests(names, patterns)
            skipped = observed - len(reachable)
            total = int(passed.group(1)) + int(ignored.group(1))
            if total != len(reachable):
                detail = (
                    f", and its own `--skip` filters exclude {skipped} of them"
                    if skipped
                    else ""
                )
                failures.append(
                    f"{readme.name} quick start states passed={passed.group(1)} "
                    f"+ ignored={ignored.group(1)} = {total}, but the command it "
                    f"documents can run {len(reachable)} of the {observed} "
                    f"enumerated tests{detail}"
                )


def check_pack_inventory(failures: list[str]) -> None:
    docs = spec_pack() / "docs"
    adrs = spec_pack() / "adrs"
    if not docs.is_dir() or not adrs.is_dir():
        failures.append("the spec pack layout changed; this guard no longer knows it")
        return

    observed_docs = len(list(docs.glob("*.md")))
    observed_adrs = len(list(adrs.glob("[0-9][0-9][0-9][0-9]-*.md")))
    # `adr-index.md` is deliberately excluded: it is the index, not a decision.

    for readme in readmes():
        text = readme.read_text(encoding="utf-8")
        docs_claim = re.search(r"(\d+)\s+documents\b", text, re.IGNORECASE)
        if docs_claim and int(docs_claim.group(1)) != observed_docs:
            failures.append(
                f"{readme.name} states {docs_claim.group(1)} documents, "
                f"the pack holds {observed_docs}"
            )
        adrs_claim = re.search(r"(\d+)\s+ADRs\b", text)
        if adrs_claim and int(adrs_claim.group(1)) != observed_adrs:
            failures.append(
                f"{readme.name} states {adrs_claim.group(1)} ADRs, "
                f"the pack holds {observed_adrs}"
            )


def check_no_status_in_readme(failures: list[str]) -> None:
    """Milestone status belongs to the gates table and nowhere else.

    This is the check that could not exist before V1-C0. Both READMEs carried
    `M11 ✅ / M12 ✅ / M13 ✅` while the authority had M11 and M12 NOT MET and
    M13 partial — a contradiction between two documents, in the file most
    likely to be read, with no guard on either side of it.
    """
    for readme in readmes():
        text = readme.read_text(encoding="utf-8")
        for milestone in MILESTONE_TICK.findall(text):
            failures.append(
                f"{readme.name} marks M{milestone} with a tick; milestone status "
                f"belongs in {gates_doc().name}, which is machine-checked, and a second "
                f"copy in a README is a second authority that nothing contradicts"
            )


def gate_rows() -> list[tuple[str, str]]:
    """(gate, status) for each row of the gates status table."""
    doc = gates_doc()
    if not doc.exists():
        return []
    found = []
    for line in doc.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0] in ("Gate", "---") or set(cells[0]) <= set("- "):
            continue
        found.append((cells[0], cells[1]))
    return found


def check_vocabulary(failures: list[str]) -> int:
    """Every milestone row must name one of the four states.

    Not a maturity gradient and not cosmetic: a row reading only "MET" or
    "partial" answers a different question from one reading "verified", and a
    reader comparing rows across the table cannot tell which is which.
    """
    road = roadmap_doc()
    if VOCABULARY_ANCHOR not in (road.read_text(encoding="utf-8") if road.exists() else ""):
        failures.append(
            f"{road.name} no longer defines the status vocabulary; every row's "
            f"state is currently undefined and this guard cannot check it"
        )
        return 0

    checked = 0
    for gate, status in gate_rows():
        # Milestone rows only. Gate rows R0..R12 are pass/fail against a
        # criterion and are not capability states.
        if not re.match(r"^M\d+\b", gate):
            continue
        checked += 1
        if not any(state in status.lower() for state in STATES):
            failures.append(
                f"{gates_doc().name}: milestone row `{gate}` states `{status}` without "
                f"naming one of {', '.join(STATES)}"
            )
    return checked


def main() -> int:
    failures: list[str] = []
    checks = [
        ("protocol version", check_protocol_claims),
        ("suite size", check_suite_claims),
        ("spec-pack inventory", check_pack_inventory),
        ("status not in README", check_no_status_in_readme),
    ]
    for name, fn in checks:
        before = len(failures)
        try:
            fn(failures)
        except Exception as exc:  # a guard that crashes is not a guard
            failures.append(f"{name}: raised {type(exc).__name__}: {exc}")
        del before

    vocabulary_rows = check_vocabulary(failures)

    if failures:
        print("document claims drift:\n")
        for failure in failures:
            print(f"  - {failure}")
        print(
            "\nEach failure is a claim in a shipped document that the repository "
            "contradicts.\nFix the document to state what is true, or record why "
            "the repository changed."
        )
        return 1

    print(
        f"document claims consistent: protocol version, suite size, spec-pack "
        f"inventory, status placement, and the state vocabulary on "
        f"{vocabulary_rows} milestone rows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
