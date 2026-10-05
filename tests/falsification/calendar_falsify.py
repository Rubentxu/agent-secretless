#!/usr/bin/env python3
"""Falsification for R2.C.2.b piece 1, the calendar primitive.

Same discipline as the R2.C.2.a harness, same four-bucket accounting, and the
one mutation that is the point of the whole file: **both directions shifted by
one day together.** That mutation survives every round trip and is caught only
by the rows that assert absolute values, which is the argument the module docs
make and the argument a reader deserves to see run rather than be told.

Run:  python3 calendar_falsify.py
"""

import sys
from pathlib import Path

# The base harness lives beside this one. `python3 tests/falsification/x.py`
# already puts this directory on `sys.path`, so the insert is only load-
# bearing for a runner that imports it as a module instead of executing
# it -- and a campaign that only works one way is a campaign that stops
# being reproducible the first time someone automates it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

CAL = f.REPO / "crates/broker/src/aws/calendar.rs"

MUTATIONS = [
    # ---- amz_date, the field decomposition -------------------------------
    (
        "take the hour as minutes",
        "        rem / 3600,",
        "        rem / 60,",
        "the_instant_stamps_to_the_oracle_at_every_boundary",
    ),
    (
        "take the minute as the remainder itself",
        "        (rem / 60) % 60,",
        "        rem % 60,",
        "the_instant_stamps_to_the_oracle_at_every_boundary",
    ),
    (
        "take the second as the whole remainder",
        "        rem % 60",
        "        rem",
        "the_instant_stamps_to_the_oracle_at_every_boundary",
    ),
    (
        # Was "render the days as seconds-since-epoch", which paired a `u32`
        # field with an `i64` and so never compiled. A mutation that cannot
        # build is not a break, and reporting it as a structural refusal would
        # have been the harness flattering itself. This one compiles and is
        # genuinely wrong.
        "render the day one higher than the calendar says",
        "        date.day,",
        "        date.day + 1,",
        "the_instant_stamps_to_the_oracle_at_every_boundary",
    ),
    # ---- amz_date, the two refusals --------------------------------------
    (
        "stamp a year the four-digit format cannot express",
        "    if date.year > MAX_STAMPED_YEAR {\n        return None;\n    }",
        "    if false {\n        return None;\n    }",
        "a_past_the_last_four_digit_year_is_refused_rather_than_stamped_wrong",
    ),
    (
        "stamp an instant before the epoch by wrapping it",
        "    let secs = now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();",
        "    let secs = now\n"
        "        .duration_since(SystemTime::UNIX_EPOCH)\n"
        "        .unwrap_or_default()\n"
        "        .as_secs();",
        "an_instant_before_the_epoch_is_refused_rather_than_stamped",
    ),
    # ---- civil_from_days --------------------------------------------------
    (
        "shift the era origin by one day",
        "    let z = days + 719_468;",
        "    let z = days + 719_469;",
        "the_writer_side_days_match_the_oracle",
    ),
    (
        "drop the negative-era correction",
        "    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;",
        "    let era = z / 146_097;",
        # Not the writer-side row: that one survived this mutation, because no
        # day it tests makes `z` negative. The row that reaches the branch is
        # the year-zero one, which exists because this survivor did.
        "year_zero_reaches_the_negative_era_branch_and_only_year_zero_does",
    ),
    (
        "put the month boundary a day either side of the real one",
        "    let month = mp + if mp < 10 { 3 } else { -9 };",
        "    let month = mp + if mp < 11 { 3 } else { -9 };",
        "the_writer_side_days_match_the_oracle",
    ),
    (
        "advance the year for every month instead of only the first two",
        "        year: y + if month <= 2 { 1 } else { 0 },",
        "        year: y + 1,",
        "the_writer_side_days_match_the_oracle",
    ),
    # ---- days_from_civil --------------------------------------------------
    (
        "move the year boundary from February to January",
        "    let y = year - if month <= 2 { 1 } else { 0 };",
        "    let y = year - if month <= 1 { 1 } else { 0 };",
        "the_reader_side_days_match_the_oracle",
    ),
    (
        "drop the leap-day correction in the era",
        "    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;",
        "    let doe = yoe * 365 + yoe / 4 + doy;",
        "the_reader_side_days_match_the_oracle",
    ),
    (
        "shift every date by one day",
        "    era * 146_097 + doe - 719_468",
        "    era * 146_097 + doe - 719_469",
        "the_reader_side_days_match_the_oracle",
    ),
    # ---- the one this file exists for ------------------------------------
    (
        # Both directions shifted by a day together, so the pair still
        # round-trips. Attributed to an *absolute* row, because that is what
        # catches it: measured separately, this same mutation leaves
        # `the_two_directions_survive_every_day_in_a_wide_window` GREEN, which
        # is the demonstration the module docs claim and the reason the absolute
        # rows exist beside it.
        "shift BOTH directions by a day, so every round trip still passes",
        # days_from_civil one day later, civil_from_days one day earlier.
        [
            ("    era * 146_097 + doe - 719_468", "    era * 146_097 + doe - 719_467"),
            ("    let z = days + 719_468;", "    let z = days + 719_467;"),
        ],
        "the_reader_side_days_match_the_oracle",
    ),
]


def main() -> int:
    f.STS = CAL
    f.TEST_PREFIX = "aws::calendar::tests::"
    # A two-site mutation is written `(label, [(old, new), ...], test)`; the
    # harness wants `(label, old, new, test)`. Normalise rather than hand-writing
    # the same list twice, so the mutation reads as what it does.
    f.MUTATIONS[:] = [
        (m[0], m[1], m[1], m[2]) if len(m) == 3 else m for m in MUTATIONS
    ]
    f.STS = CAL
    original = CAL.read_text()
    # The harness restores and asserts against STS; point both at calendar.
    f.STS = CAL
    kept = f.STS
    f.STS = CAL
    print(f"# falsifying {CAL.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert CAL.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
