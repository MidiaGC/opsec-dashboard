use std::time::{Duration, UNIX_EPOCH};

use opsec_dashboard::timefmt::{format_age, format_ts, parse_utc_offset};

#[test]
fn format_ts_epoch_is_1970() {
    assert_eq!(format_ts(UNIX_EPOCH), "1970-01-01 00:00:00 UTC");
}

#[test]
fn format_ts_known_instant() {
    // 2026-07-25 19:28:39 UTC
    let t = UNIX_EPOCH + Duration::from_secs(1_785_007_719);
    assert_eq!(format_ts(t), "2026-07-25 19:28:39 UTC");
}

#[test]
fn format_ts_handles_leap_year() {
    // 2024-02-29 12:00:00 UTC
    let t = UNIX_EPOCH + Duration::from_secs(1_709_208_000);
    assert_eq!(format_ts(t), "2024-02-29 12:00:00 UTC");
}

#[test]
fn format_ts_handles_century_boundary() {
    // 2000-03-01 00:00:00 UTC — the year 2000 is a leap year, 1900 was not.
    let t = UNIX_EPOCH + Duration::from_secs(951_868_800);
    assert_eq!(format_ts(t), "2000-03-01 00:00:00 UTC");
}

#[test]
fn format_age_is_compact() {
    assert_eq!(format_age(Duration::from_secs(0)), "0s ago");
    assert_eq!(format_age(Duration::from_secs(45)), "45s ago");
    assert_eq!(format_age(Duration::from_secs(90)), "1m ago");
    assert_eq!(format_age(Duration::from_secs(3600)), "1h00m ago");
    assert_eq!(format_age(Duration::from_secs(4020)), "1h07m ago");
}

#[test]
fn utc_offset_parsing() {
    assert_eq!(parse_utc_offset("-0300"), Some((-10_800, "-03:00".into())));
    assert_eq!(parse_utc_offset("+0000"), Some((0, "+00:00".into())));
    assert_eq!(parse_utc_offset("+0530"), Some((19_800, "+05:30".into())));

    assert_eq!(parse_utc_offset(""), None);
    assert_eq!(parse_utc_offset("0300"), None);
    assert_eq!(parse_utc_offset("-03:00"), None);
    assert_eq!(parse_utc_offset("+9900"), None);
}
