#!/usr/bin/env python3
"""Check that every UAT in 14-UAT-ADVERSARIAL.md is owned by exactly one milestone
in 15-ROADMAP.md, and that no milestone gates on a UAT whose prerequisite feature
does not exist yet at that milestone.

Exit 0 = all hard checks pass. Exit 1 = at least one hard defect.

Usage:
    tools/check-gates.py [SPEC_DIR]

Why this exists: release gate R11 ("all required UAT green") is only
falsifiable if the UAT -> milestone mapping is machine-checkable. It lived
prose-only, so nothing could detect a gate that could never run.

This script is read-only. It never edits the spec pack.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROADMAP_REL = Path("docs/15-ROADMAP.md")
UATDOC_REL = Path("docs/14-UAT-ADVERSARIAL.md")

# Feature prerequisites, expressed as data so the knowledge stays editable.
# uat_id -> (feature name, first milestone whose Scope provides that feature)
#
# A UAT claimed by several milestones is a legitimate *regression re-run* in the
# later ones. The defect is claiming it EARLIER than the feature exists.
REQUIREMENTS: dict[int, tuple[str, str]] = {
    5: ("surrogate-replay", "M4"),   # copy the placeholder, hit the real provider
    10: ("http-surrogate-bridge", "M4"),
    13: ("ebpf-socket-redirect", "M9"),
    21: ("isolated-exec-worker", "M10"),
}

MILESTONE_RE = re.compile(r"^## (M\d+|v1\.0)\b")
HEADING_RE = re.compile(r"^###\s+(.*)$")
GATE_HEADING_RE = re.compile(r"exit|go criteria", re.IGNORECASE)
UAT_DEF_RE = re.compile(r"^## UAT-(\d{3})\b", re.M)
RANGE_RE = re.compile(r"UAT-(\d{3})\s*(?:through|to)\s*(\d{3})")
LIST_RE = re.compile(r"UAT-(\d{3}(?:\s*,\s*\d{3})*)")
DIGITS_RE = re.compile(r"\d{3}")


def expand(text: str) -> set[int]:
    """Expand 'UAT-001, 002, 004' and 'UAT-005 through 010' into {1, 2, 4} / {5..10}.

    Prose mentions of the word 'UAT' without an id ('UAT threat harness',
    'full UAT matrix') must NOT parse as gates.
    """
    found: set[int] = set()
    for a, b in RANGE_RE.findall(text):
        found.update(range(int(a), int(b) + 1))
    residue = RANGE_RE.sub("", text)
    for group in LIST_RE.findall(residue):
        found.update(int(n) for n in DIGITS_RE.findall(group))
    return found


def parse_milestones(text: str) -> list[dict]:
    """Return one record per milestone, with its exit-gate block and UAT ids."""
    lines = text.split("\n")
    current: dict | None = None
    in_gate = False
    milestones: list[dict] = []

    for line in lines:
        m = MILESTONE_RE.match(line)
        if m:
            current = {
                "name": m.group(1),
                "gate_heading": None,
                "gate_text": [],
                "uats": set(),
            }
            milestones.append(current)
            in_gate = False
            continue

        if current is None:
            continue

        h = HEADING_RE.match(line)
        if h:
            in_gate = bool(GATE_HEADING_RE.search(h.group(1)))
            if in_gate:
                current["gate_heading"] = h.group(1).strip()
                continue

        if in_gate:
            current["gate_text"].append(line)
            current["uats"] |= expand(line)

    for rec in milestones:
        rec["gate_text"] = "\n".join(rec["gate_text"])
    return milestones


def order_key(name: str) -> tuple[int, int]:
    if name.startswith("M"):
        return (0, int(name[1:]))
    return (1, 0)


# A test file that opens with "UAT-005 - ..." is asserting it *is* that UAT.
# Two files asserting the same id makes every gate that cites the id
# ambiguous, and UAT-030 is not cosmetic: NFR-PERF-001 and the R11 gate row
# both hang off it.
UAT_HEADER_RE = re.compile(r"^UAT-(\d{3})\b")
# Claiming an id also asserts the test implements *that* UAT. A title that
# shares nothing with the spec's entry for the id is a misattribution: the
# test is real, the trace back to the spec is not. "CONNECT allow-list" and
# "HTTP surrogate bridge" are different subjects; "performance smoke and
# resource-leak check" against "performance smoke" is the same one, worded
# differently. Token overlap separates the two without a synonym list.
UAT_HEADER_TITLE_RE = re.compile(r"^UAT-(\d{3})\b[\s—–:.-]*(.*)$")
UAT_SPEC_TITLE_RE = re.compile(r"^## (UAT-\d{3}) — (.+?)\s*$", re.M)
TITLE_STOPWORDS = {
    "a", "an", "the", "and", "or", "of", "to", "for", "in", "on", "with",
    "test", "tests", "check", "case",
}
# The filename is a claim too. "uat_017_env_scan.rs" reads as UAT-017 even
# when its header says nothing, which is how a reader ends up citing the
# wrong file.
UAT_FILENAME_RE = re.compile(r"^uat_?(\d{3})[_.]")
DOC_LINE_RE = re.compile(r"^//[/!]\s?(.*)$")
# "> quoted text" inside a doc comment, attributed to the spec pack.
QUOTE_RE = re.compile(r"^//[/!]\s?>\s?(.*)$")
# Below this many consecutive words, a quotation is treated as fabricated.
# Measured on the pack as a whole, not one file: a header may legitimately
# cite a second document, and only text that exists nowhere is a forgery.
# The measured separation is wide — the known fabrications share 5 words
# with the pack, the shortest faithful quotation shares 14.
CITATION_MIN_RUN = 8
# A quotation this short carries too little signal to judge.
CITATION_MIN_WORDS = 8


def title_tokens(s: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", s.lower()) if t not in TITLE_STOPWORDS}


def longest_shared_run(quote: str, pack: str) -> int:
    """Longest run of consecutive words the quote and the pack both contain.

    Word-level matching is far too weak here: a fabricated sentence about
    vaults and attackers still draws most of its individual words from a
    pack that talks about nothing else. Only an unbroken run of words is
    evidence of a real quotation, and re-wrapping a quote to the line width
    costs nothing because word order is preserved.
    """
    hay = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", pack.lower()))
    adjacent = {
        (a, b) for a, b in zip(hay.split(), hay.split()[1:])
    }
    tokens = re.sub(r"[^a-z0-9]+", " ", quote.lower()).split()
    best = run = 0
    for i in range(len(tokens)):
        run = 0
        for j in range(i + 1, len(tokens)):
            if (tokens[j - 1], tokens[j]) in adjacent:
                run += 1
            else:
                break
        best = max(best, run)
    return best


def cited_quote(head: str) -> str | None:
    """The first quoted block of a doc comment, or None."""
    quote = " ".join(
        m.group(1) for m in (QUOTE_RE.match(l) for l in head.splitlines()) if m
    ).strip()
    return quote or None


def fabricated_citation(head: str, pack: str) -> int | None:
    """Length of the longest real run in a header's quotation, or None.

    A header that puts the spec pack's name on a quotation is asserting the
    text came from there. That is a fact about the pack, so it can be
    checked instead of trusted — and five such quotations were fabricated
    before this check existed, each of which let a gate cite a requirement
    the spec never stated.
    """
    quote = cited_quote(head)
    if quote is None:
        return None
    words = re.sub(r"[^a-z0-9]+", " ", quote.lower()).split()
    if len(words) < CITATION_MIN_WORDS:
        return None
    return longest_shared_run(quote, pack)


def spec_pack_text(spec: Path) -> str:
    """Every markdown file in the spec pack, concatenated."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(spec.rglob("*.md"))
    )


def spec_uat_titles(uatdoc: str) -> dict[int, str]:
    """Map each UAT id to its title as written in the spec pack."""
    return {
        int(m.group(1)[4:]): m.group(2)
        for m in UAT_SPEC_TITLE_RE.finditer(uatdoc)
    }


def declared_uat(head: str) -> tuple[int, str] | None:
    """The (id, title) a test file claims, or None.

    Only the FIRST non-empty doc-comment line counts. The repo's convention is
    `//! UAT-005 — title`, so that line is the claim. Later lines are prose,
    and matching them would flag text that merely discusses an id — a header
    explaining that UAT-035 is not a reserved id would otherwise register as a
    claim of UAT-035.

    The id is anchored at the start of the line on purpose. An id appearing
    mid-sentence is a reference, not a claim: "isolated worker runtime, the
    M10 follow-up to UAT-021 and UAT-022" cites two UATs it does not own, and
    reading that as ownership is how two files end up claiming one id.
    """
    for line in head.splitlines():
        m = DOC_LINE_RE.match(line)
        if not m or not m.group(1).strip():
            continue
        declared = UAT_HEADER_TITLE_RE.match(m.group(1).strip())
        return (int(declared.group(1)), declared.group(2).strip()) if declared else None
    return None


def scan_repo_uat_claims(
    root: Path,
) -> tuple[dict[int, list[str]], list[tuple[str, int, str]], list[tuple[str, int, str]], int]:
    """Map each UAT id declared by a test header to the files declaring it.

    Returns (claims, filename_only, titled, files_scanned) where `claims` maps
    id to the files whose leading doc comment declares it, `filename_only`
    lists files whose name implies an id their header does not declare, and
    `titled` lists (path, id, title) for every declared claim so the caller
    can compare the claimed title against the spec's.

    Only the leading doc comment counts. A UAT id mentioned in a test body is
    a reference, not a claim, and treating it as one would make this check
    report on prose.
    """
    claims: dict[int, list[str]] = {}
    filename_only: list[tuple[str, int]] = []
    titled: list[tuple[str, int, str]] = []
    scanned = 0

    for tests_dir in sorted(root.glob("crates/*/tests")):
        if not tests_dir.is_dir():
            continue
        for path in sorted(tests_dir.glob("*.rs")):
            if not UAT_FILENAME_RE.match(path.name):
                continue
            scanned += 1
            head = path.read_text(encoding="utf-8", errors="replace")[:2000]
            declared = declared_uat(head)
            if declared is not None:
                uid, title = declared
                claims.setdefault(uid, []).append(path.relative_to(root).as_posix())
                titled.append((path.relative_to(root).as_posix(), uid, title))
            else:
                filename_only.append(
                    (path.relative_to(root).as_posix(), int(UAT_FILENAME_RE.match(path.name).group(1)))
                )
    return claims, filename_only, titled, scanned


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    spec = root / "agent-secretless-vault-spec"
    if not spec.is_dir():
        spec = root
    roadmap = spec / ROADMAP_REL
    uatdoc = spec / UATDOC_REL

    for path in (roadmap, uatdoc):
        if not path.is_file():
            print(f"error: missing {path}", file=sys.stderr)
            return 2

    defined = sorted({int(n) for n in UAT_DEF_RE.findall(uatdoc.read_text(encoding="utf-8"))})
    milestones = parse_milestones(roadmap.read_text(encoding="utf-8"))
    owner: dict[int, list[str]] = {}
    for rec in milestones:
        for u in rec["uats"]:
            owner.setdefault(u, []).append(rec["name"])

    hard: list[str] = []
    warn: list[str] = []

    print("== per-milestone exit gates ==")
    for rec in sorted(milestones, key=lambda r: order_key(r["name"])):
        head = rec["gate_heading"] or "-"
        ids = sorted(rec["uats"])
        body = rec["gate_text"]
        delegated = bool(re.search(r"16-SECURITY-RELEASE-GATES|release gate", body, re.I))
        prose_only = not ids and re.search(r"\bUAT\b", body) and not delegated
        no_gate = not ids and not delegated
        tag = ""
        if delegated:
            tag = "DELEGATED to 16-SECURITY-RELEASE-GATES"
        elif prose_only:
            tag = "PROSE-ONLY (mentions UAT, no ids)"
        elif no_gate:
            tag = "NO-GATE"
        print(f"  {rec['name']:5} {head:22} {ids} {tag}")

    print("\n== UAT id claims in the repository ==")
    repo_claims, filename_only, titled, scanned = scan_repo_uat_claims(root)
    titles = spec_uat_titles(uatdoc.read_text(encoding="utf-8", errors="replace"))
    for u in sorted(repo_claims):
        holders = repo_claims[u]
        if len(holders) > 1:
            hard.append(
                f"UAT-{u:03d} is claimed by {len(holders)} test files "
                f"({', '.join(holders)}); every gate citing it is ambiguous"
            )
    for u in sorted(repo_claims):
        if u not in defined:
            hard.append(
                f"UAT-{u:03d} is claimed by a test file but 14-UAT-ADVERSARIAL.md "
                f"does not define it ({', '.join(repo_claims[u])})"
            )
    # A claim whose title shares no content word with the spec's entry is a
    # misattribution, not a paraphrase. Reported, not failed: only the spec
    # author can say which side is wrong, and the test itself is real either
    # way. What this prevents is a gate citing UAT-010 and believing it is
    # covered by a CONNECT allow-list test when the spec never said so.
    for path, u, title in titled:
        spec_title = titles.get(u)
        if spec_title is None or not title:
            continue
        if not (title_tokens(title) & title_tokens(spec_title)):
            warn.append(
                f"{path} claims UAT-{u:03d} as '{title}' but the spec titles it "
                f"'{spec_title}'; the id and the test do not describe the same thing"
            )
    for path, u in filename_only:
        warn.append(
            f"{path} is named uat_{u:03d} but declares no UAT id; "
            f"the filename claims UAT-{u:03d} ({', '.join(repo_claims.get(u, [])) or 'no file claims it'})"
        )
    # A header that attributes a quotation to the spec pack is making a
    # checkable claim about the pack. Five such quotations were fabricated
    # before this check existed, each of which made a gate cite a
    # requirement the spec never stated. Every test file is scanned, not
    # only the UAT-named ones: a forged citation is a forged citation.
    pack = spec_pack_text(spec)
    fabricated = 0
    quoted = 0
    for tests_dir in sorted(root.glob("crates/*/tests")):
        if not tests_dir.is_dir():
            continue
        for path in sorted(tests_dir.glob("*.rs")):
            run = fabricated_citation(
                path.read_text(encoding="utf-8", errors="replace")[:2000], pack
            )
            if run is None:
                continue
            quoted += 1
            if run < CITATION_MIN_RUN:
                fabricated += 1
                hard.append(
                    f"{path.relative_to(root).as_posix()} attributes a quotation "
                    f"to the spec pack, but only {run} consecutive words of it "
                    f"exist there; the citation is fabricated"
                )
    print(f"  test files scanned: {scanned}")
    print(f"  quoted spec citations: {quoted} (fabricated: {fabricated})")
    print(f"  distinct ids claimed by a header: {len(repo_claims)}")
    if not filename_only:
        print("  filename-only claims: none")
    else:
        for path, u in filename_only:
            print(f"  filename-only: {path} (implies UAT-{u:03d}, header declares none)")

    print("\n== hard defects ==")
    orphans = sorted(set(defined) - set(owner))
    for u in orphans:
        hard.append(f"UAT-{u:03d} is defined but no milestone gates on it")

    for u in sorted(owner):
        claims = sorted(owner[u], key=order_key)
        if len(claims) > 1:
            req = REQUIREMENTS.get(u)
            if req is None:
                warn.append(
                    f"UAT-{u:03d} claimed by {claims} (no prerequisite recorded)"
                )
                continue
            feature, needed = req
            if order_key(claims[0]) < order_key(needed):
                hard.append(
                    f"UAT-{u:03d} gated by {claims[0]} but '{feature}' "
                    f"does not exist until {needed} (also claimed by {claims[1:]})"
                )

    for line in hard:
        print(f"  FAIL {line}")
    if not hard:
        print("  none")

    print("\n== warnings ==")
    for rec in sorted(milestones, key=lambda r: order_key(r["name"])):
        if not rec["uats"]:
            body = rec["gate_text"]
            if re.search(r"16-SECURITY-RELEASE-GATES|release gate", body, re.I):
                continue
            warn.append(
                f"{rec['name']} exit block has no UAT id "
                f"(gate heading: {rec['gate_heading'] or 'none'})"
            )
    for line in warn:
        print(f"  WARN {line}")
    if not warn:
        print("  none")

    print("\n== summary ==")
    print(f"  UAT defined:            {len(defined)}")
    print(f"  UAT with >=1 gate:      {len(owner)}")
    print(f"  orphaned UAT:           {len(orphans)} {orphans if orphans else ''}")
    print(f"  UAT ids claimed in repo:{len(repo_claims):>4}")
    duplicated = sum(1 for files in repo_claims.values() if len(files) > 1)
    print(f"  duplicate id claims:    {duplicated}")
    print(f"  hard defects:           {len(hard)}")
    print(f"  warnings:               {len(warn)}")

    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
