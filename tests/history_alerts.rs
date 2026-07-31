use opsec_dashboard::alerts;
use opsec_dashboard::checks::{CheckResult, Severity, Status};
use opsec_dashboard::config::Alerts;
use opsec_dashboard::history::{
    History, SPARK_WIDTH, Snapshot, is_regression, parse_line, render_line, spark_glyph,
};

fn snapshot(at: u64, entries: &[(&str, Severity)]) -> Snapshot {
    Snapshot {
        at,
        severities: entries.iter().map(|(id, s)| (id.to_string(), *s)).collect(),
    }
}

// ---------- serialisation ----------

#[test]
fn a_snapshot_round_trips() {
    let original = snapshot(
        1785007719,
        &[("vpn", Severity::Pass), ("mac", Severity::Fail)],
    );
    let parsed = parse_line(&render_line(&original)).expect("must round-trip");
    assert_eq!(parsed, original);
}

#[test]
fn the_line_format_is_greppable() {
    let line = render_line(&snapshot(100, &[("vpn", Severity::Pass)]));
    assert_eq!(line, "100 vpn=pass");
}

// Losing a trend line is not worth refusing to start over.
#[test]
fn corrupt_lines_are_skipped_not_fatal() {
    assert!(parse_line("not a snapshot").is_none());
    assert!(parse_line("").is_none());

    let partial = parse_line("100 vpn=pass mac=nonsense garbage").expect("prefix is usable");
    assert_eq!(partial.severities.get("vpn"), Some(&Severity::Pass));
    assert_eq!(partial.severities.get("mac"), None);
}

// ---------- history ----------

#[test]
fn last_returns_the_most_recent_observation() {
    let mut history = History::ephemeral(10);
    history.record(snapshot(1, &[("vpn", Severity::Pass)]));
    history.record(snapshot(2, &[("vpn", Severity::Fail)]));

    assert_eq!(history.last("vpn"), Some(Severity::Fail));
    assert_eq!(history.last("never-seen"), None);
}

#[test]
fn series_is_oldest_first_and_capped() {
    let mut history = History::ephemeral(100);
    for i in 0..(SPARK_WIDTH as u64 + 5) {
        let severity = if i == 0 {
            Severity::Fail
        } else {
            Severity::Pass
        };
        history.record(snapshot(i, &[("vpn", severity)]));
    }

    let series = history.series("vpn");
    assert_eq!(series.len(), SPARK_WIDTH);
    // The old Fail has scrolled off the visible window.
    assert!(series.iter().all(|s| *s == Severity::Pass));
}

// Disabling and re-enabling a check must not punch a hole in its trend.
#[test]
fn snapshots_without_a_check_do_not_break_its_series() {
    let mut history = History::ephemeral(10);
    history.record(snapshot(1, &[("vpn", Severity::Pass)]));
    history.record(snapshot(2, &[("mac", Severity::Fail)]));
    history.record(snapshot(3, &[("vpn", Severity::Fail)]));

    assert_eq!(history.series("vpn"), vec![Severity::Pass, Severity::Fail]);
}

#[test]
fn retention_drops_the_oldest_snapshots() {
    let mut history = History::ephemeral(3);
    for i in 0..10 {
        history.record(snapshot(i, &[("vpn", Severity::Pass)]));
    }
    assert_eq!(history.snapshots.len(), 3);
    assert_eq!(history.snapshots[0].at, 7);
}

#[test]
fn history_survives_a_round_trip_through_a_file() {
    let dir = std::env::temp_dir().join(format!("opsec-history-{}", std::process::id()));
    let path = dir.join("history");
    let _ = std::fs::remove_dir_all(&dir);

    let mut history = History::open(Some(path.clone()), 10);
    history.record(snapshot(1, &[("vpn", Severity::Pass)]));
    history.record(snapshot(2, &[("vpn", Severity::Fail)]));

    let reloaded = History::open(Some(path), 10);
    assert_eq!(reloaded.snapshots.len(), 2);
    assert_eq!(reloaded.last("vpn"), Some(Severity::Fail));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn spark_glyphs_grow_with_severity() {
    assert_eq!(spark_glyph(Severity::Pass), '▁');
    assert_eq!(spark_glyph(Severity::Fail), '▇');
    assert_ne!(spark_glyph(Severity::Warn), spark_glyph(Severity::Pass));
}

// ---------- regressions ----------

#[test]
fn a_regression_is_a_move_to_a_worse_severity() {
    assert!(is_regression(Some(Severity::Pass), Severity::Fail));
    assert!(is_regression(Some(Severity::Warn), Severity::Fail));
    assert!(is_regression(Some(Severity::Pass), Severity::Unknown));

    assert!(!is_regression(Some(Severity::Fail), Severity::Pass));
    assert!(!is_regression(Some(Severity::Warn), Severity::Warn));
}

// Otherwise the first run of the day pages you about everything at once.
#[test]
fn the_first_observation_is_never_a_regression() {
    assert!(!is_regression(None, Severity::Fail));
}

// ---------- alerts ----------

fn enabled_alerts() -> Alerts {
    Alerts {
        enabled: true,
        command: "true".to_string(),
        on_any_problem: false,
    }
}

fn failing() -> CheckResult {
    CheckResult::new("vpn", "VPN", Status::Fail("no VPN interface".into()))
}

#[test]
fn regressions_alert_and_steady_state_does_not() {
    let alerts = enabled_alerts();
    assert!(alerts::should_alert(
        Some(Severity::Pass),
        &failing(),
        &alerts
    ));
    // Still broken, but no worse — an alert channel that repeats itself every
    // five seconds is one nobody reads.
    assert!(!alerts::should_alert(
        Some(Severity::Fail),
        &failing(),
        &alerts
    ));
}

#[test]
fn any_problem_mode_alerts_on_steady_failures_too() {
    let alerts = Alerts {
        on_any_problem: true,
        ..enabled_alerts()
    };
    assert!(alerts::should_alert(
        Some(Severity::Fail),
        &failing(),
        &alerts
    ));
    let passing = CheckResult::new("vpn", "VPN", Status::Pass("up".into()));
    assert!(!alerts::should_alert(
        Some(Severity::Pass),
        &passing,
        &alerts
    ));
}

#[test]
fn disabled_or_empty_alerts_never_fire() {
    let off = Alerts {
        enabled: false,
        ..enabled_alerts()
    };
    assert!(!alerts::should_alert(
        Some(Severity::Pass),
        &failing(),
        &off
    ));

    let blank = Alerts {
        command: "   ".to_string(),
        ..enabled_alerts()
    };
    assert!(!alerts::should_alert(
        Some(Severity::Pass),
        &failing(),
        &blank
    ));
}

// An accepted risk is a decision already made; it does not get to page you.
#[test]
fn accepted_risks_do_not_alert() {
    let accepted = failing().accept("known, tracked elsewhere");
    assert!(!alerts::should_alert(
        Some(Severity::Pass),
        &accepted,
        &enabled_alerts()
    ));
}

#[test]
fn placeholders_are_substituted() {
    let command = alerts::expand(
        "notify {id} {label} {status} {message} {previous}",
        &failing(),
        Some(Severity::Pass),
    );
    assert!(command.contains("'vpn'"));
    assert!(command.contains("'VPN'"));
    assert!(command.contains("'fail'"));
    assert!(command.contains("'no VPN interface'"));
    assert!(command.contains("'pass'"));
}

#[test]
fn a_first_observation_renders_previous_as_none() {
    let command = alerts::expand("{previous}", &failing(), None);
    assert_eq!(command, "'none'");
}

// Check messages contain whatever the system printed — interface names, ports,
// file paths. Interpolating that into a shell command unquoted is a command
// injection, so this runs the expanded command for real and verifies the
// payload stayed inert data.
#[test]
fn message_content_cannot_escape_into_the_shell() {
    let marker = std::env::temp_dir().join(format!("opsec-injection-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);

    let payload = format!("'; touch {}; echo '", marker.display());
    let hostile = CheckResult::new("vpn", "VPN", Status::Fail(payload));
    let command = alerts::expand("printf '%s' {message}", &hostile, None);

    let output = std::process::Command::new("sh")
        .args(["-c", &command])
        .output()
        .expect("sh should run");

    assert!(
        !marker.exists(),
        "the payload executed — command was: {command}"
    );
    // And the message still arrived intact as a single argument.
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(printed.contains("touch"), "message mangled: {printed}");

    let _ = std::fs::remove_file(&marker);
}

#[test]
fn shell_quoting_handles_embedded_quotes() {
    assert_eq!(alerts::shell_quote("plain"), "'plain'");
    assert_eq!(alerts::shell_quote("it's"), r"'it'\''s'");
}
