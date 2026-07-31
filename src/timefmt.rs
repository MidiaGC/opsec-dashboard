//! Minimal date formatting.
//!
//! The dashboard needs one timestamp and one relative age; pulling in a full
//! date-time crate for that is not worth the dependency, so the civil-from-days
//! algorithm (Howard Hinnant's `civil_from_days`) is inlined here.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds since the epoch, saturating at 0 for pre-epoch instants.
fn epoch_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_ts(t: SystemTime) -> String {
    format!("{} UTC", format_epoch(epoch_secs(t)))
}

/// `YYYY-MM-DD HH:MM:SS ±HH:MM`, in the machine's local timezone.
pub fn format_local(t: SystemTime) -> String {
    let (offset, label) = local_offset();
    format!("{} {label}", format_epoch(epoch_secs(t) + offset as i64))
}

/// A compact relative age: `4s ago`, `2m ago`, `1h07m ago`.
pub fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h{:02}m ago", secs / 3600, (secs % 3600) / 60)
    }
}

/// The local UTC offset in seconds and its display label, resolved once.
///
/// `std` exposes no timezone API, so the offset is read from `date +%z` on
/// first use; if that fails we stay on UTC rather than guess.
pub fn local_offset() -> (i32, &'static str) {
    static CACHE: OnceLock<(i32, String)> = OnceLock::new();
    let (offset, label) = CACHE.get_or_init(|| {
        let out = crate::exec::run("date", &["+%z"]);
        out.success_stdout()
            .and_then(|s| parse_utc_offset(s.trim()))
            .unwrap_or((0, "UTC".to_string()))
    });
    (*offset, label.as_str())
}

/// Parse a `+HHMM` / `-HHMM` offset into (seconds, `±HH:MM` label).
pub fn parse_utc_offset(raw: &str) -> Option<(i32, String)> {
    let bytes = raw.as_bytes();
    if bytes.len() != 5 {
        return None;
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hours: i32 = raw.get(1..3)?.parse().ok()?;
    let minutes: i32 = raw.get(3..5)?.parse().ok()?;
    if hours > 14 || minutes > 59 {
        return None;
    }
    let label = format!(
        "{}{hours:02}:{minutes:02}",
        if sign > 0 { '+' } else { '-' }
    );
    Some((sign * (hours * 3600 + minutes * 60), label))
}

/// `YYYY-MM-DD HH:MM:SS` for an epoch-seconds value.
fn format_epoch(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

/// Convert days since 1970-01-01 into a proleptic Gregorian (year, month, day).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}
