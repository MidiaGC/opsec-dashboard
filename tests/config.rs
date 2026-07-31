use opsec_dashboard::config::{self, Config, Value, parse_document};

// ---------- parsing ----------

#[test]
fn parses_sections_scalars_and_lists() {
    let doc = parse_document(
        r#"
[general]
interval = 10
sudo     = false
profile  = "travel"

[checks]
disabled = ["usbguard", "updates"]
"#,
    )
    .expect("valid document");

    assert_eq!(doc.get("general", "interval"), Some(&Value::Int(10)));
    assert_eq!(doc.get("general", "sudo"), Some(&Value::Bool(false)));
    assert_eq!(
        doc.get("general", "profile").and_then(Value::as_str),
        Some("travel")
    );
    assert_eq!(
        doc.get("checks", "disabled").and_then(Value::as_list),
        Some(&["usbguard".to_string(), "updates".to_string()][..])
    );
}

#[test]
fn keys_before_any_section_land_in_general() {
    let doc = parse_document("interval = 7").unwrap();
    assert_eq!(doc.get("general", "interval"), Some(&Value::Int(7)));
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let doc = parse_document("# a comment\n\n[general]\ninterval = 3 # trailing\n").unwrap();
    assert_eq!(doc.get("general", "interval"), Some(&Value::Int(3)));
}

// A `#` inside a quoted alert command is part of the command, not a comment.
#[test]
fn hashes_inside_strings_survive() {
    let doc = parse_document(
        r#"[alerts]
command = "notify-send 'tag #1'"
"#,
    )
    .unwrap();
    assert_eq!(
        doc.get("alerts", "command").and_then(Value::as_str),
        Some("notify-send 'tag #1'")
    );
}

// Half-applying a config would give the user a posture they did not ask for.
#[test]
fn malformed_input_is_rejected_with_a_line_number() {
    let err = parse_document("[general]\nthis line has no equals sign\n").unwrap_err();
    assert!(err.contains("line 2"), "got {err}");

    let err = parse_document("[unterminated\n").unwrap_err();
    assert!(err.contains("line 1"), "got {err}");
}

#[test]
fn a_bare_string_is_accepted_where_a_list_is_expected() {
    let doc = parse_document(
        r#"[checks]
disabled = "usbguard"
"#,
    )
    .unwrap();
    assert_eq!(
        doc.get("checks", "disabled").and_then(Value::as_list),
        Some(&["usbguard".to_string()][..])
    );
}

// ---------- settings ----------

#[test]
fn defaults_match_the_hardcoded_behaviour_they_replaced() {
    let t = Config::default().thresholds;
    assert_eq!(t.failed_logins_warn_above, 0);
    assert_eq!(t.failed_logins_fail_above, 5);
    assert_eq!(t.listening_warn_above, 0);
    assert_eq!(t.listening_fail_above, 2);
}

#[test]
fn thresholds_and_exceptions_are_read() {
    let doc = parse_document(
        r#"
[thresholds]
failed_logins_fail_above = 20

[exceptions]
listening-tcp = "5900 is VNC on the LAN"
"#,
    )
    .unwrap();
    let config = Config::from_document(&doc, None);

    assert_eq!(config.thresholds.failed_logins_fail_above, 20);
    // Unset keys keep their defaults rather than resetting to zero.
    assert_eq!(config.thresholds.listening_fail_above, 2);
    assert_eq!(
        config.exception("listening-tcp"),
        Some("5900 is VNC on the LAN")
    );
    assert_eq!(config.exception("vpn"), None);
}

#[test]
fn disabled_checks_do_not_run() {
    let doc = parse_document("[checks]\ndisabled = [\"usbguard\"]\n").unwrap();
    let config = Config::from_document(&doc, None);
    assert!(!config.runs("usbguard"));
    assert!(config.runs("vpn"));
}

// A non-empty `enabled` list is an allowlist.
#[test]
fn enabled_acts_as_an_allowlist() {
    let doc = parse_document("[checks]\nenabled = [\"vpn\", \"dns\"]\n").unwrap();
    let config = Config::from_document(&doc, None);
    assert!(config.runs("vpn"));
    assert!(config.runs("dns"));
    assert!(!config.runs("usbguard"));
}

#[test]
fn disabled_wins_over_enabled() {
    let doc = parse_document("[checks]\nenabled = [\"vpn\"]\ndisabled = [\"vpn\"]\n").unwrap();
    assert!(!Config::from_document(&doc, None).runs("vpn"));
}

// ---------- profiles ----------

const WITH_PROFILE: &str = r#"
[general]
interval = 30

[checks]
disabled = ["updates"]

[thresholds]
failed_logins_fail_above = 50

[profiles.travel]
interval = 3

[profiles.travel.thresholds]
failed_logins_fail_above = 0
"#;

#[test]
fn a_profile_layers_over_the_base_settings() {
    let doc = parse_document(WITH_PROFILE).unwrap();

    let base = Config::from_document(&doc, None);
    assert_eq!(base.interval.as_secs(), 30);
    assert_eq!(base.thresholds.failed_logins_fail_above, 50);

    let travel = Config::from_document(&doc, Some("travel"));
    assert_eq!(travel.interval.as_secs(), 3);
    assert_eq!(travel.thresholds.failed_logins_fail_above, 0);
    // Keys the profile does not mention are inherited, not reset.
    assert!(!travel.runs("updates"), "base disabled list should survive");
}

#[test]
fn the_config_can_select_its_own_profile() {
    let doc = parse_document(&format!("[general]\nprofile = \"travel\"\n{WITH_PROFILE}")).unwrap();
    let config = Config::from_document(&doc, None);
    assert_eq!(config.profile.as_deref(), Some("travel"));
    assert_eq!(config.interval.as_secs(), 3);
}

#[test]
fn an_unknown_profile_leaves_the_base_settings_alone() {
    let doc = parse_document(WITH_PROFILE).unwrap();
    let config = Config::from_document(&doc, Some("nonexistent"));
    assert_eq!(config.interval.as_secs(), 30);
}

#[test]
fn interval_from_the_config_is_clamped() {
    let doc = parse_document("[general]\ninterval = 99999\n").unwrap();
    assert!(Config::from_document(&doc, None).interval <= opsec_dashboard::app::MAX_INTERVAL);

    let doc = parse_document("[general]\ninterval = 0\n").unwrap();
    assert!(Config::from_document(&doc, None).interval >= opsec_dashboard::app::MIN_INTERVAL);
}

// ---------- loading ----------

#[test]
fn a_missing_config_file_is_not_an_error() {
    let path = std::path::PathBuf::from("/nonexistent/opsec/config.toml");
    assert!(
        config::load(Some(&path), None).is_err(),
        "an explicitly named file must exist"
    );

    // ...but no path at all, with nothing installed, yields defaults.
    let config = config::current();
    assert_eq!(config.thresholds, Config::default().thresholds);
}

#[test]
fn the_bundled_template_parses() {
    let doc = parse_document(config::TEMPLATE).expect("shipped template must be valid");
    let config = Config::from_document(&doc, None);
    // The template documents the defaults, so it must reproduce them.
    assert_eq!(config.thresholds, Config::default().thresholds);
    assert!(!config.alerts.enabled);
}
