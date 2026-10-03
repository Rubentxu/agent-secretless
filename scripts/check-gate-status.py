#!/usr/bin/env python3
"""Verify the checkable claims in the security release gates status table.

`15-ROADMAP.md` delegates M11 and M13 completion to
`16-SECURITY-RELEASE-GATES.md`, and that document states its own current
status so the delegation is a real gate. A status table with nothing checking
it is a comment: the one written on 2026-09-30 was accurate when written and
had drifted in four rows within eleven days.

This script is what stops that recurring. It verifies the claims that the
repository can decide and leaves the ones it cannot.

It deliberately does NOT hardcode expected values. A guard that pins "596
tests" fails the moment a test is added, which is the normal case, and teaches
maintainers to update the guard instead of reading the table. The job is to
catch contradiction, not to pin values.

A row whose shape it does not recognise is ignored, not failed. An unknown row
is a claim this guard does not understand, and failing on it would punish an
author for writing something honest in a new shape.

Exit 0 when every recognised claim holds, 1 on any drift.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TABLE = REPO / "agent-secretless-vault-spec" / "docs" / "16-SECURITY-RELEASE-GATES.md"
LOCKFILE = REPO / "Cargo.lock"

# Rows whose status is a judgement about the world rather than a fact about the
# repository. M12 needs a TPM; M11 needs a live authorization server. Nothing
# here can decide either, so nothing here asserts them.
UNVERIFIABLE = ("M12", "live OAuth2", "hardware-backed")


def git(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=False
    )
    return proc.returncode, proc.stdout.strip()


def rows(text: str) -> list[tuple[str, str, str]]:
    """Return (gate, status, evidence) for every table row in the status table."""
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        gate, status, evidence = cells[0], cells[1], cells[2]
        if gate in ("Gate", "---") or set(gate) <= set("- "):
            continue
        if not status:
            continue
        found.append((gate, status, evidence))
    return found


def check_milestone_ancestry(gate: str, evidence: str, failures: list[str]) -> None:
    """Tags the row names must be ancestors of the release the row names.

    This is the check that was missing when the M11-M13 row claimed a release
    "must not be moved to cover them" while those tags were already inside it.
    """
    tags = sorted(set(re.findall(r"`(m\d\d-[a-z0-9-]+)`", evidence)))
    releases = sorted(set(re.findall(r"`(v\d+\.\d+\.\d+)`", evidence)))
    if not tags or not releases:
        return

    release = releases[0]
    rc, _ = git("rev-parse", "--verify", f"{release}^{{commit}}")
    if rc != 0:
        failures.append(
            f"{gate}: names release {release}, which does not exist in this repository"
        )
        return

    for tag in tags:
        rc, _ = git("rev-parse", "--verify", f"{tag}^{{commit}}")
        if rc != 0:
            failures.append(f"{gate}: names tag {tag}, which does not exist")
            continue
        rc, _ = git("merge-base", "--is-ancestor", f"{tag}^{{commit}}", f"{release}^{{commit}}")
        if rc != 0:
            failures.append(
                f"{gate}: {tag} is NOT an ancestor of {release}, but the row "
                f"implies it is covered by it"
            )


def check_declared_count(gate: str, evidence: str, pattern: str, observed: int, unit: str,
                         failures: list[str]) -> None:
    """A count stated in the table must equal the observed one."""
    match = re.search(pattern, evidence)
    if not match:
        return
    stated = int(match.group(1))
    if stated != observed:
        failures.append(
            f"{gate}: states {stated} {unit}, observed {observed} {unit}"
        )


def check_full_suite(gate: str, evidence: str, failures: list[str]) -> None:
    # Prefer the explicit "N tests enumerated" form: it compares like with
    # like. The legacy "N passed" form is accepted but compared against the
    # total, because a suite that gained an ignored test would otherwise drift
    # by one and send maintainers to edit a correct row.
    explicit = re.search(r"(\d+)\s+tests enumerated", evidence)
    legacy = re.search(r"(\d+)\s+passed", evidence)
    if not explicit and not legacy:
        return
    stated = int((explicit or legacy).group(1))

    proc = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--", "--list"],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        failures.append(
            f"{gate}: could not enumerate the suite to check the stated "
            f"{stated} (cargo test --list failed); refusing to pass an "
            f"unverified claim"
        )
        return
    observed = sum(
        1 for line in proc.stdout.splitlines()
        if line.strip() and ": test" in line
    )
    if stated != observed:
        failures.append(
            f"{gate}: states {stated} tests, {observed} are enumerated"
        )


def check_dependency_audit(gate: str, evidence: str, failures: list[str]) -> None:
    if not LOCKFILE.exists():
        return
    observed = LOCKFILE.read_text(encoding="utf-8").count("[[package]]")
    check_declared_count(gate, evidence, r"(\d+)\s+deps", observed, "deps", failures)

    match = re.search(r"(\d+)\s+advisor", evidence)
    if match and match.group(1) == "0":
        if shutil_which("cargo-audit") is None:
            failures.append(
                f"{gate}: claims 0 advisories but cargo-audit is not installed, "
                f"so the claim cannot be checked here"
            )
            return
        proc = subprocess.run(
            ["cargo", "audit"], cwd=REPO, capture_output=True, text=True, check=False
        )
        blob = proc.stdout + proc.stderr
        if re.search(r"^\s*Vulnerability", blob, re.MULTILINE) or "vulnerabilities found" in blob:
            failures.append(f"{gate}: claims 0 advisories, cargo audit reports one")


def shutil_which(name: str) -> str | None:
    from shutil import which
    return which(name)


# The README states a test count in three places, in two languages, and it was
# wrong in both for as long as nobody looked. A count in a document is a claim
# like any other; the only difference is that nothing was checking it.
#
# R11's own row is re-derived every run, so the table could not drift. The
# README is not in the table, which is exactly why it drifted: the count was
# true once, then quietly stopped being true, and nothing in CI noticed for
# three milestones.
# The lookbehind is not decoration. Without it, `python3 tests/adversarial`
# matches as "3 tests", and a command in the quick-start block became a
# failure. The number has to be a token of its own, not the tail of an
# identifier.
README_CLAIM = re.compile(r"(?<![A-Za-z0-9_])(\d+)\s+tests\b", re.IGNORECASE)


def readme_files() -> list[Path]:
    """Every README the project ships, so a second translation cannot drift alone."""
    return [p for p in (REPO / "README.md", REPO / "README-es.md") if p.exists()]


def check_readme_count(gate: str, evidence: str, failures: list[str]) -> None:
    """The README must state the suite size the repository actually has.

    Scans every `N tests` claim in every shipped README and compares it with
    the same enumeration R11 uses, so the two numbers cannot disagree.
    """
    stated = re.search(r"(\d+)\s+tests", evidence)
    if not stated:
        return
    expected = int(stated.group(1))

    proc = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--", "--list"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        failures.append(
            f"{gate}: could not enumerate the suite to check the README's "
            f"{expected} (cargo test --list failed); refusing to pass an "
            f"unverified claim"
        )
        return
    observed = sum(1 for line in proc.stdout.splitlines() if line.strip() and ": test" in line)

    # The row's own number first. The first version of this check compared
    # only the READMEs against the repository, so a row stating the wrong
    # count passed as long as the READMEs agreed with each other. The
    # falsifiability case for it is what caught that: the row is a claim too,
    # and a claim that the table and the documents agree on is not a claim
    # anyone has checked.
    if expected != observed:
        failures.append(
            f"{gate}: the table states {expected} tests, "
            f"{observed} are enumerated"
        )

    for readme in readme_files():
        text = readme.read_text(encoding="utf-8")
        for claimed in README_CLAIM.findall(text):
            if int(claimed) != observed:
                failures.append(
                    f"{gate}: {readme.name} states {claimed} tests, "
                    f"{observed} are enumerated"
                )


def check_console_surface(gate: str, evidence: str, failures: list[str]) -> None:
    """M5's front-end must ship no remote origin and a strict CSP.

    UAT-019's first clause is "rendered as data, no script execution", and a
    CSP is the mechanism that makes it true rather than merely intended. A
    console that reaches a CDN at runtime is a console whose front-end is
    whatever that CDN served today, so the check is that no such URL is
    *written*, not that none happens to load.

    This reads the files. It does not build the WebView, so it can run in the
    pipeline, which has no display.
    """
    ui_dir = REPO / "apps/desktop/ui"
    conf_path = REPO / "apps/desktop/tauri.conf.json"

    if not ui_dir.is_dir():
        failures.append(f"{gate}: apps/desktop/ui does not exist, so the claim "
                        f"that it ships no remote assets cannot be checked")
        return
    if not conf_path.is_file():
        failures.append(f"{gate}: apps/desktop/tauri.conf.json is missing, so the "
                        f"CSP claim cannot be checked")
        return

    offenders: list[str] = []
    for path in sorted(ui_dir.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            # A protocol-relative URL (`//host/...`) is remote too, and it is
            # the one a naive `http` search misses.
            for needle in ("http://", "https://", "//cdn.", "src=\"//", "href=\"//"):
                if needle in line:
                    offenders.append(f"{path.relative_to(REPO)}:{lineno} contains {needle!r}")
    if offenders:
        failures.append(
            f"{gate}: the console front-end references a remote origin: "
            + "; ".join(offenders[:5])
        )

    conf = conf_path.read_text(encoding="utf-8")
    # `unsafe-inline` is what an injected `<script>` needs when there is no
    # nonce, and `unsafe-eval` is what turns a string into code. Neither may
    # appear in a console that renders credential metadata.
    for banned in ("unsafe-inline", "unsafe-eval"):
        if banned in conf:
            failures.append(f"{gate}: the CSP permits {banned}")
    for required in ("default-src 'self'", "connect-src 'self'", "object-src 'none'"):
        if required not in conf:
            failures.append(f"{gate}: the CSP is missing `{required}`")
    if '"enable": false' not in conf:
        failures.append(f"{gate}: the asset protocol is not disabled; a console "
                        f"that serves local files over it can be pointed elsewhere")


def main() -> int:
    table_path = TABLE
    args = sys.argv[1:]
    if "--table" in args:
        # Present so the falsifiability tests can drive the guard against
        # synthetic tables. The pipeline never passes it.
        table_path = Path(args[args.index("--table") + 1])

    if not table_path.exists():
        print(f"gate status table not found: {table_path}", file=sys.stderr)
        return 1

    text = table_path.read_text(encoding="utf-8")
    failures: list[str] = []
    checked = 0
    recognised = 0
    unchecked: list[str] = []

    for gate, status, evidence in rows(text):
        if any(marker in gate for marker in UNVERIFIABLE):
            continue
        recognised += 1
        # A row is only *checked* if at least one check below actually applied
        # to it. Counting a recognised row as a verified one is an overclaim
        # this guard was itself making: it reported "17 checkable claims
        # verified" while several rows were only recognised and no check ever
        # ran against them. The V1-C0 rows made that visible — 3 of 20 — so the
        # count is now split and the unverified ones are named.
        applied = False
        if "M11-M13" in gate or "semver" in gate.lower():
            check_milestone_ancestry(gate, evidence, failures)
            applied = True
        if "full suite" in gate.lower():
            check_full_suite(gate, evidence, failures)
            applied = True
        if "dependency audit" in gate.lower():
            check_dependency_audit(gate, evidence, failures)
            applied = True
        if "readme" in gate.lower():
            check_readme_count(gate, evidence, failures)
            applied = True
        if "console front-end" in gate.lower() or "remote origin" in gate.lower():
            check_console_surface(gate, evidence, failures)
            applied = True
        if applied:
            checked += 1
        else:
            unchecked.append(gate)

    if failures:
        print("gate status drift in 16-SECURITY-RELEASE-GATES.md:\n")
        for failure in failures:
            print(f"  - {failure}")
        print(
            "\nEach failure is a claim in the status table that the repository "
            "contradicts.\nFix the row to state what is true, or record why the "
            "repository changed."
        )
        return 1

    print(
        f"gate status table consistent: {checked} of {recognised} claims checked "
        f"by this guard"
    )
    if unchecked:
        # Named rather than counted away, and worded so it does not overclaim in
        # the other direction either: several of these *are* checked elsewhere
        # (clippy and fmt by the `static` stage, NFR-PERF-001 by UAT-030, the
        # UAT map by `tools/check-gates.py`, the console CSP by the M5 row
        # dispatch below). What is true of all of them is only that *this*
        # script applies no check to them — which was previously reported as if
        # every one of them had been verified here.
        print(
            f"\nrecognised but not checked by this guard ({len(unchecked)}); "
            f"some are covered by another stage:\n  "
            + "\n  ".join(unchecked)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
