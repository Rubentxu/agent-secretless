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
  what `cargo test -- --list` enumerates. The arithmetic is checked as a sum
  rather than as two independent numbers on purpose: deriving the passed and
  ignored split would mean running the whole suite, and a sum is enough to
  catch a stale count, which is the failure this exists for.
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


def enumerated_tests() -> int | None:
    proc = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--", "--list"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return sum(1 for line in proc.stdout.splitlines() if line.strip() and ": test" in line)


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


def check_suite_claims(failures: list[str]) -> None:
    observed = enumerated_tests()
    if observed is None:
        failures.append(
            "could not enumerate the suite (cargo test --list failed); refusing to "
            "pass a count claim that cannot be checked"
        )
        return

    for readme in readmes():
        text = readme.read_text(encoding="utf-8")
        for claimed in README_CLAIM.findall(text):
            if int(claimed) != observed:
                failures.append(
                    f"{readme.name} states {claimed} tests, {observed} are enumerated"
                )

        # The quick-start block's own arithmetic. A stale count fails the sum
        # without needing the suite to be run, which is the whole point: the
        # number that drifted by 174 was never re-derived by anything.
        passed = PASSED_CLAIM.search(text)
        ignored = IGNORED_CLAIM.search(text)
        if passed and ignored:
            total = int(passed.group(1)) + int(ignored.group(1))
            if total != observed:
                failures.append(
                    f"{readme.name} quick start states passed={passed.group(1)} "
                    f"+ ignored={ignored.group(1)} = {total}, {observed} are enumerated"
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
