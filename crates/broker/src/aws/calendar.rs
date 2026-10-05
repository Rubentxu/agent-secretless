//! Civil-date arithmetic, in both directions, in one place.
//!
//! # Why this is a module and not two functions in two files
//!
//! [`super::sts::parse_assume_role`] reads an instant, and SigV4 signing stamps
//! one. The reader was built on `days_from_civil`; the writer needs
//! `civil_from_days`, which did not exist anywhere in this tree. Implementing
//! them separately would put two implementations of the proleptic Gregorian
//! calendar in one module tree, and **their disagreement is the bug that hurts**:
//! a signature computed perfectly over the wrong day is locally indistinguishable
//! from one computed over the right day, and the provider answers
//! `SignatureDoesNotMatch` with nothing a caller can reconcile against it.
//!
//! So the two directions live together, and [`tests`] checks them against an
//! oracle *and* against each other. The round trip is not the whole check — a
//! round trip through one implementation proves only that it agrees with
//! itself — which is why the boundaries below are absolute values, not
//! self-consistency.
//!
//! The arithmetic is Howard Hinnant's `days_from_civil` / `civil_from_days`,
//! chosen because it is exact over the whole range with no date library, no
//! lookup table and no 32-bit overflow. Both directions use truncating integer
//! division, which is what the C++ original is written in and what Rust's `/`
//! does; the shifted terms are always non-negative, so truncating and flooring
//! agree and there is no hidden asymmetry to reason about.

use std::time::SystemTime;

/// A proleptic Gregorian date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

/// The largest year the `X-Amz-Date` format can express.
///
/// `{:04}` renders 9999 as `9999` and 10000 as `10000`, so an instant past this
/// produces a *longer* string that is no longer the documented shape. It would
/// sign, send, and be refused — so it is refused here instead, with a name
/// instead of a length.
pub const MAX_STAMPED_YEAR: i64 = 9999;

/// Days since 1970-01-01, for any date in range including before the epoch.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let d = day as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` days after 1970-01-01, for negative `days` too.
pub fn civil_from_days(days: i64) -> Civil {
    // Shift into a range where the era division is never negative.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    Civil {
        year: y + if month <= 2 { 1 } else { 0 },
        month: month as u32,
        day: day as u32,
    }
}

/// The `X-Amz-Date` SigV4 stamps: `20150830T123600Z`.
///
/// `None` rather than a fallback in each of the three refusals, because a
/// fallback here is a signature over a stamp the provider will reject:
///
/// - **before the epoch**, because a `SystemTime` earlier than `UNIX_EPOCH`
///   has no unsigned duration to convert, and no request has ever needed one;
/// - **a year past [`MAX_STAMPED_YEAR`]**, because the stamp stops being the
///   documented shape;
/// - **a second count that does not fit `i64`**, which is unreachable in
///   practice and refused rather than wrapped. A wrapped day count is a
///   signature computed over a date nobody chose.
pub fn amz_date(now: SystemTime) -> Option<String> {
    let secs = now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
    let secs = i64::try_from(secs).ok()?;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let date = civil_from_days(days);
    if date.year > MAX_STAMPED_YEAR {
        return None;
    }
    Some(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        date.year,
        date.month,
        date.day,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    ))
}

#[cfg(test)]
mod tests;
