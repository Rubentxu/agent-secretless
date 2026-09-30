#!/usr/bin/env python3
"""Guard: every discarded backlog item must remain reachable from a live item.

Why this exists
---------------
Nine rounds of M9 cleanup found that `sddk backlog discard` silently destroyed
findings. Discarding bl-bl-01M3RYA5J3000387HWP0WSYVR0 to file the sign-off hole
also killed an unrelated finding (uat plan emits features: [] and zero
scenarios) that lived only in that item's summary. Nothing warned.

Reachability is TRANSITIVE. A correction may name the item it corrects, and
that item may name an earlier one:

    live  ->  discarded B  ->  discarded A

so A is covered even though no live item names A directly. A naive
direct-reference check reports 27 false orphans on this repo.

Exit code 0 = clean, 1 = at least one discarded item is unreachable.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

ITEM_RE = re.compile(r"bl-bl-[0-9A-Z]+")


def load(db: Path) -> list[tuple[str, str, str]]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return list(
            con.execute(
                "select item_id, current_status, summary from backlog_items_v1"
            )
        )
    finally:
        con.close()


def reachable_ids(items: list[tuple[str, str, str]]) -> set[str]:
    """Ids mentioned by any live item, plus everything they transitively name."""
    by_id = {i: x for i, _, x in items}
    # Walk from live items outward, following mentions into discarded items.
    seen: set[str] = set()
    frontier = [i for i, s, _ in items if s != "discarded"]
    for ref in frontier:
        seen.update(ITEM_RE.findall(by_id.get(ref, "")))
    changed = True
    while changed:
        changed = False
        for ref in list(seen):
            for mentioned in ITEM_RE.findall(by_id.get(ref, "")):
                if mentioned not in seen:
                    seen.add(mentioned)
                    changed = True
    return seen


def main() -> int:
    default = (
        Path.home()
        / ".local/state/sddk/projects/p-20a1ee316faf2ba3/ledger.sqlite"
    )
    db = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    if not db.exists():
        print(f"error: ledger not found: {db}", file=sys.stderr)
        return 2

    items = load(db)
    discarded = [i for i, s, _ in items if s == "discarded"]
    covered = reachable_ids(items)
    orphans = sorted(i for i in discarded if i not in covered)

    live = sum(1 for _, s, _ in items if s != "discarded")
    print(f"live={live} discarded={len(discarded)} unreachable={len(orphans)}")
    for i in orphans:
        print(f"  UNREACHABLE {i}")
    if orphans:
        print(
            "\nEach id above was discarded but no live item names it, directly "
            "or through a chain.\nRe-file the finding, or supersede it with an "
            "item that names it."
        )
    return 1 if orphans else 0


if __name__ == "__main__":
    sys.exit(main())
