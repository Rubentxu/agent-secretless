//! R2.C.2.b, piece 1 — the civil-date arithmetic and the `X-Amz-Date` stamp.
//!
//! # The oracle
//!
//! Every value below comes from `$TMPDIR/calendar_reference.py`, written from
//! the SigV4 `X-Amz-Date` shape and from Python's own proleptic Gregorian
//! calendar. It does not read this crate. One of the instants is not derived at
//! all: **1440938160 is the exact `amz_date` AWS publishes in its own SigV4
//! examples**, so the forward direction is checked against a documented vector
//! and not only against this calendar agreeing with itself.
//!
//! # Why the round trip is not the check
//!
//! Every function here has an inverse, and a round trip through one
//! implementation proves only that it agrees with itself. A shift of one day in
//! *both* directions survives any round trip and produces a signature the
//! provider rejects with nothing to reconcile. So the rows below are absolute
//! values, and the round trip is there as an extra, not as the evidence.

use std::time::{Duration, SystemTime};

use asv_broker::aws::calendar::{amz_date, civil_from_days, days_from_civil, MAX_STAMPED_YEAR};

fn at(secs: i64) -> SystemTime {
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs((-secs) as u64)
    }
}

#[test]
fn the_documented_amz_date_is_reproduced_from_its_own_instant() {
    // AWS publishes 20150830T123600Z beside the signature it produces. If this
    // row is ever edited rather than the code, the signer has stopped agreeing
    // with the documentation it claims to implement.
    assert_eq!(
        amz_date(at(1_440_938_160)),
        Some("20150830T123600Z".to_string())
    );
}

#[test]
fn the_instant_stamps_to_the_oracle_at_every_boundary() {
    // Oracle `amz_date`. Each of these is a boundary the arithmetic could get
    // wrong: the epoch, a second after it, a leap day, the 32-bit edge, the last
    // day a four-digit year can express, and a day rollover that has to carry
    // into the date.
    for (secs, expected) in [
        (0_i64, "19700101T000000Z"),
        (1, "19700101T000001Z"),
        (86_399, "19700101T235959Z"),
        (951_825_600, "20000229T120000Z"),
        (1_438_671_097, "20150804T065137Z"),
        (1_767_225_599, "20251231T235959Z"),
        (2_147_483_647, "20380119T031407Z"),
        (253_402_300_799, "99991231T235959Z"),
    ] {
        assert_eq!(
            amz_date(at(secs)),
            Some(expected.to_string()),
            "{secs} stamped wrongly"
        );
    }
}

#[test]
fn an_instant_before_the_epoch_is_refused_rather_than_stamped() {
    // The oracle's calendar covers 1969-12-31, and the arithmetic can produce
    // it — `civil_from_days` is total. `amz_date` is not, and the difference is
    // deliberate: there is no unsigned duration before the epoch to convert, no
    // request has ever needed one, and a fallback would be a signature over a
    // stamp nobody chose. The refusal is named by being absent.
    assert_eq!(amz_date(at(-1)), None);
    // The calendar still reaches it, which is what `parse_rfc3339` needs.
    assert_eq!(
        civil_from_days(-1),
        asv_broker::aws::calendar::Civil {
            year: 1969,
            month: 12,
            day: 31
        }
    );
}

#[test]
fn a_past_the_last_four_digit_year_is_refused_rather_than_stamped_wrong() {
    // `{:04}` renders 10000 as five digits, so the stamp silently stops being
    // the documented shape. It would sign, send, and be refused — so it is
    // refused here, with a name instead of a length.
    let beyond = Duration::from_secs((MAX_STAMPED_YEAR as u64 + 1) * 365 * 86_400);
    assert_eq!(
        amz_date(SystemTime::UNIX_EPOCH + beyond),
        None,
        "an instant past the last stampable year produced a stamp"
    );
    assert_eq!(MAX_STAMPED_YEAR, 9999);
}

#[test]
fn the_reader_side_days_match_the_oracle() {
    // Oracle `days_from_civil`. These are the same values `sts.rs` was built
    // against, checked here because the function moved: a move that changed a
    // value would not fail anything else in the tree.
    for (date, expected) in [
        ((1969, 12, 31), -1_i64),
        ((1970, 1, 1), 0),
        ((1970, 1, 2), 1),
        ((2000, 2, 29), 11_016),
        ((2015, 8, 4), 16_651),
        ((2038, 1, 19), 24_855),
        ((2100, 3, 1), 47_541),
        ((2400, 2, 29), 157_113),
        ((9999, 12, 31), 2_932_896),
    ] {
        let (y, m, d) = date;
        assert_eq!(
            days_from_civil(y, m, d),
            expected,
            "{y:04}-{m:02}-{d:02} counted wrongly"
        );
    }
}

#[test]
fn the_writer_side_days_match_the_oracle() {
    // Oracle `civil_specific`, which exists by name for exactly this table. The
    // first version of this row hand-copied its pairs from a sampled print of
    // the oracle and paired `-504` with the date the oracle gives for `-430`; it
    // went red against a correct implementation, which is the second time in
    // this block that the test was the wrong side. A table transcribed by eye
    // off a listing is the same class of error as a count copied from memory.
    for (days, expected) in [
        (-504_i64, (1968, 8, 15)),
        (-430, (1968, 10, 28)),
        (-23, (1969, 12, 9)),
        (-134, (1969, 8, 20)),
        (0, (1970, 1, 1)),
        (11_016, (2000, 2, 29)),
        (16_651, (2015, 8, 4)),
        (24_855, (2038, 1, 19)),
    ] {
        let date = civil_from_days(days);
        assert_eq!(
            (date.year, date.month as i64, date.day as i64),
            expected,
            "{days} days was not the oracle's date"
        );
    }
}

#[test]
fn the_two_directions_survive_every_day_in_a_wide_window() {
    // Not the evidence — the rows above are. This is the property that makes a
    // *future* change to either direction detectable at all, and it is cheap.
    // Oracle `round_trip_failures`: 0 across the same window.
    for days in (-40_000..40_000).step_by(97) {
        let date = civil_from_days(days);
        assert_eq!(
            days_from_civil(date.year, date.month, date.day),
            days,
            "{days} days did not survive the round trip"
        );
    }
}

#[test]
fn year_zero_reaches_the_negative_era_branch_and_only_year_zero_does() {
    // The one row in this file that exists because a mutation survived.
    //
    // `civil_from_days` computes `days + 719_468` and then, if that is
    // negative, shifts before dividing. A mutation that removed the shift left
    // every other row green, because **no other row in this file produces a
    // negative `z`** — the reader-side dates start at 1969 and the writer-side
    // ones at year 0 *March*, where `z` is already 0.
    //
    // So the branch had no row at all, which is a branch nobody can trust. What
    // reaches it is year 0 in the first two months, and that is not exotic:
    // `sts::parse_rfc3339` takes a four-digit year and only range-checks the
    // month and the day, so `0000-01-01T00:00:00Z` is an instant this product
    // already accepts from a provider.
    //
    // Oracle `year_zero_days`. Python cannot supply the *writer* direction here
    // — `date.fromordinal` refuses anything before year 1 — so these are reader
    // values, and the writer is checked by the round trip in both directions.
    // Of the four, two reach the negative branch and two do not, which is the
    // boundary this row is for.
    for (month, day, days, reaches_negative_branch) in [
        (1_u32, 1_u32, -719_528_i64, true),
        (2, 29, -719_469, true),
        (3, 1, -719_468, false),
        (12, 31, -719_163, false),
    ] {
        assert_eq!(
            days_from_civil(0, month, day),
            days,
            "0000-{month:02}-{day:02} counted wrongly"
        );
        assert_eq!(
            days + 719_468 < 0,
            reaches_negative_branch,
            "the oracle's own arithmetic disagrees about which side of the branch \
             0000-{month:02}-{day:02} is on"
        );
        // The writer direction, which is what the branch is in.
        let back = civil_from_days(days);
        assert_eq!(
            (back.year, back.month, back.day),
            (0, month, day),
            "0000-{month:02}-{day:02} did not survive the round trip"
        );
    }
}

#[test]
fn the_epoch_is_where_both_directions_agree_it_is() {
    // Stated on its own because it is the one date both functions are defined
    // relative to, and an off-by-one there shifts everything else silently.
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(
        civil_from_days(0),
        asv_broker::aws::calendar::Civil {
            year: 1970,
            month: 1,
            day: 1
        }
    );
    assert_eq!(amz_date(SystemTime::UNIX_EPOCH), Some("19700101T000000Z".into()));
}
