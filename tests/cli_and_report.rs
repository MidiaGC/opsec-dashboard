use opsec_dashboard::checks::{self, CheckResult, Severity, Status};
use opsec_dashboard::cli::{self, Mode, Parsed};
use opsec_dashboard::report;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// ---------- cli ----------

#[test]
fn no_arguments_launches_the_tui() {
    match cli::parse(args(&[])) {
        Parsed::Run(config) => {
            assert_eq!(config.mode, Mode::Tui);
            assert!(config.allow_sudo);
            assert!(config.only.is_empty());
            // No flag means "defer to the config file".
            assert_eq!(config.interval, None);
        }
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn once_and_json_select_headless_modes() {
    assert!(matches!(
        cli::parse(args(&["--once"])),
        Parsed::Run(c) if c.mode == Mode::Text
    ));
    assert!(matches!(
        cli::parse(args(&["--json"])),
        Parsed::Run(c) if c.mode == Mode::Json
    ));
}

#[test]
fn interval_accepts_both_spellings() {
    let expect = Some(std::time::Duration::from_secs(30));
    assert!(matches!(
        cli::parse(args(&["-i", "30"])),
        Parsed::Run(c) if c.interval == expect
    ));
    assert!(matches!(
        cli::parse(args(&["--interval=30"])),
        Parsed::Run(c) if c.interval == expect
    ));
}

#[test]
fn out_of_range_interval_is_rejected() {
    assert!(matches!(cli::parse(args(&["-i", "0"])), Parsed::Error(_)));
    assert!(matches!(
        cli::parse(args(&["-i", "9999"])),
        Parsed::Error(_)
    ));
    assert!(matches!(cli::parse(args(&["-i", "abc"])), Parsed::Error(_)));
    assert!(matches!(cli::parse(args(&["-i"])), Parsed::Error(_)));
}

#[test]
fn only_accepts_ids_and_categories() {
    match cli::parse(args(&["--only", "vpn,network"])) {
        Parsed::Run(config) => assert_eq!(config.only, vec!["vpn", "network"]),
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn unknown_selectors_are_rejected_at_parse_time() {
    match cli::parse(args(&["--only", "vpn,nonsense"])) {
        Parsed::Error(msg) => assert!(msg.contains("nonsense"), "got {msg}"),
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn unknown_flags_are_rejected() {
    assert!(matches!(cli::parse(args(&["--wat"])), Parsed::Error(_)));
}

#[test]
fn help_version_and_list_short_circuit() {
    assert!(matches!(cli::parse(args(&["--help"])), Parsed::Help));
    assert!(matches!(cli::parse(args(&["-V"])), Parsed::Version));
    assert!(matches!(cli::parse(args(&["--list"])), Parsed::List));
}

// ---------- registry ----------

#[test]
fn check_ids_are_unique() {
    let mut ids: Vec<&str> = checks::REGISTRY.iter().map(|c| c.id).collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "duplicate check id in the registry");
}

#[test]
fn selecting_a_category_yields_its_checks_in_registry_order() {
    let selected = checks::select(&["network".to_string()]).expect("network is a valid category");
    assert!(!selected.is_empty());
    assert!(selected.iter().all(|c| c.category.as_str() == "network"));

    let positions: Vec<usize> = selected
        .iter()
        .map(|c| checks::REGISTRY.iter().position(|r| r.id == c.id).unwrap())
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted, "registry order must be preserved");
}

#[test]
fn empty_selection_means_every_check() {
    assert_eq!(checks::select(&[]).unwrap().len(), checks::REGISTRY.len());
}

#[test]
fn every_registered_check_is_addressable_by_id() {
    for check in checks::REGISTRY {
        assert!(
            checks::find(check.id).is_some(),
            "{} not findable",
            check.id
        );
    }
}

// ---------- report ----------

fn sample() -> Vec<CheckResult> {
    vec![
        CheckResult::new("a", "Alpha", Status::Pass("fine".into())),
        CheckResult::new("b", "Beta", Status::Warn("iffy".into())).with_hint("do the thing"),
        CheckResult::new("c", "Gamma", Status::Fail("broken \"badly\"".into())),
    ]
}

#[test]
fn exit_code_reflects_the_worst_result() {
    assert_eq!(
        report::exit_code(&[CheckResult::new("a", "A", Status::Pass("ok".into()))]),
        0
    );
    assert_eq!(
        report::exit_code(&[CheckResult::new("a", "A", Status::Unknown("?".into()))]),
        1
    );
    assert_eq!(
        report::exit_code(&[CheckResult::new("a", "A", Status::Warn("!".into()))]),
        1
    );
    assert_eq!(report::exit_code(&sample()), 2);
    assert_eq!(report::exit_code(&[]), 0);
}

#[test]
fn text_report_lists_every_check_with_its_hint() {
    let text = report::render_text(&sample());
    for label in ["Alpha", "Beta", "Gamma"] {
        assert!(text.contains(label), "{label} missing from:\n{text}");
    }
    assert!(text.contains("do the thing"), "hint missing");
    assert!(text.contains("1 pass, 1 warn, 1 fail"), "summary missing");
}

#[test]
fn json_report_escapes_quotes_and_reports_the_worst_severity() {
    let json = report::render_json(&sample());
    assert!(
        json.contains(r#"broken \"badly\""#),
        "quotes not escaped:\n{json}"
    );
    assert!(
        json.contains(r#""worst": "fail""#),
        "worst missing:\n{json}"
    );
    assert!(
        json.contains(r#""hint": null"#),
        "absent hint should be null"
    );
    assert!(json.contains(r#""id": "b""#));
}

#[test]
fn json_escaping_covers_control_characters() {
    assert_eq!(report::escape("a\"b\\c"), r#"a\"b\\c"#);
    assert_eq!(report::escape("line\nbreak\ttab"), r"line\nbreak\ttab");
    assert_eq!(report::escape("\u{1}"), "\\u0001");
}

#[test]
fn worst_of_no_results_is_a_pass() {
    assert_eq!(checks::worst(&[]), Severity::Pass);
}

#[test]
fn severity_ordering_is_worst_last() {
    assert!(Severity::Fail > Severity::Warn);
    assert!(Severity::Warn > Severity::Unknown);
    assert!(Severity::Unknown > Severity::Pass);
}

// An "unknown" result is the absence of evidence, not evidence of safety, so it
// must never be silently folded into the passing count.
#[test]
fn unknown_is_not_a_pass() {
    let results = vec![CheckResult::new("a", "A", Status::Unknown("?".into()))];
    assert_eq!(checks::worst(&results), Severity::Unknown);
    assert_ne!(report::exit_code(&results), 0);
}

// Hints describe a fix; a passing check has nothing to fix.
#[test]
fn hints_are_not_attached_to_passing_results() {
    let passing =
        CheckResult::new("a", "A", Status::Pass("ok".into())).with_hint("irrelevant advice");
    assert_eq!(passing.hint, None);

    let failing = CheckResult::new("a", "A", Status::Fail("bad".into())).with_hint("fix it");
    assert_eq!(failing.hint.as_deref(), Some("fix it"));
}
