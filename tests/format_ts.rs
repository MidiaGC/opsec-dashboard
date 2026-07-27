use std::time::{SystemTime, UNIX_EPOCH};

use opsec_dashboard::checks::{CheckResult, Status};
use opsec_dashboard::ui::format_ts;

#[test]
fn format_ts_epoch_is_1970() {
    let s = format_ts(UNIX_EPOCH);
    assert_eq!(s, "1970-01-01 00:00:00 UTC");
}

#[test]
fn format_ts_known_instant() {
    // 2026-07-25 19:28:39 UTC = 1785007719 seconds since epoch
    let t = UNIX_EPOCH + std::time::Duration::from_secs(1_785_007_719);
    let s = format_ts(t);
    assert_eq!(s, "2026-07-25 19:28:39 UTC");
}

#[test]
fn format_ts_handles_leap_year() {
    // 2024-02-29 12:00:00 UTC = 1709208000
    let t = UNIX_EPOCH + std::time::Duration::from_secs(1_709_208_000);
    let s = format_ts(t);
    assert_eq!(s, "2024-02-29 12:00:00 UTC");
}

// Keep SystemTime import used even if tests above change.
#[allow(dead_code)]
fn _unused(_t: SystemTime) {}
