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
    print(f"  hard defects:           {len(hard)}")
    print(f"  warnings:               {len(warn)}")

    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
