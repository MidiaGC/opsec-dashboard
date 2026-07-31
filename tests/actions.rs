use std::time::{Duration, Instant};

use opsec_dashboard::app::{ActionState, App};
use opsec_dashboard::checks::{CheckResult, Severity, Status};
use opsec_dashboard::report;

fn app_with_fix() -> App {
    App::with_checks(vec![
        CheckResult::new("plain", "Plain", Status::Fail("broken".into())),
        CheckResult::new("fixable", "Fixable", Status::Fail("broken".into()))
            .with_fix("echo repaired"),
    ])
}

/// Drive the app until the action leaves `Running`, or give up.
fn settle(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        app.poll_action();
        if !matches!(app.action, ActionState::Running { .. }) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("action never finished");
}

#[test]
fn a_check_without_a_fix_offers_nothing() {
    let mut app = app_with_fix();
    assert!(!app.propose_action(), "no fix means nothing to propose");
    assert_eq!(app.action, ActionState::Idle);
}

#[test]
fn proposing_shows_the_exact_command_without_running_it() {
    let mut app = app_with_fix();
    app.select_next();
    assert!(app.propose_action());

    match &app.action {
        ActionState::Confirm { command, label, .. } => {
            assert_eq!(command, "echo repaired");
            assert_eq!(label, "Fixable");
        }
        other => panic!("expected Confirm, got {other:?}"),
    }
}

// Nothing may run without a deliberate keystroke on a visible command.
#[test]
fn cancelling_runs_nothing() {
    let mut app = app_with_fix();
    app.select_next();
    app.propose_action();
    app.cancel_action();
    assert_eq!(app.action, ActionState::Idle);
}

#[test]
fn a_dry_run_reports_without_executing() {
    let marker = std::env::temp_dir().join(format!("opsec-dryrun-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);

    let mut app = App::with_checks(vec![
        CheckResult::new("t", "T", Status::Fail("broken".into()))
            .with_fix(format!("touch {}", marker.display())),
    ]);
    app.propose_action();
    app.dry_run_action();

    match &app.action {
        ActionState::Done { success, .. } => assert_eq!(*success, None, "dry run has no verdict"),
        other => panic!("expected Done, got {other:?}"),
    }
    assert!(!marker.exists(), "a dry run must not touch the system");
}

#[test]
fn confirming_runs_the_command_and_captures_its_output() {
    let mut app = app_with_fix();
    app.select_next();
    app.propose_action();
    app.confirm_action();
    settle(&mut app);

    match &app.action {
        ActionState::Done {
            success, output, ..
        } => {
            assert_eq!(*success, Some(true));
            assert!(output.contains("repaired"), "output missing: {output}");
        }
        other => panic!("expected Done, got {other:?}"),
    }
}

#[test]
fn a_failing_command_is_reported_as_failed() {
    let mut app = App::with_checks(vec![
        CheckResult::new("t", "T", Status::Fail("broken".into())).with_fix("echo nope >&2; exit 1"),
    ]);
    app.propose_action();
    app.confirm_action();
    settle(&mut app);

    match &app.action {
        ActionState::Done {
            success, output, ..
        } => {
            assert_eq!(*success, Some(false));
            assert!(output.contains("nope"), "stderr missing: {output}");
        }
        other => panic!("expected Done, got {other:?}"),
    }
}

// The fix changes the thing being measured, so a passing check must not be
// offered one — there would be nothing to repair.
#[test]
fn passing_checks_never_carry_a_fix() {
    let passing =
        CheckResult::new("t", "T", Status::Pass("all good".into())).with_fix("rm -rf /nope");
    assert_eq!(passing.fix, None);
}

// ---------- accepted risks ----------

#[test]
fn an_accepted_risk_keeps_its_real_status_on_screen() {
    let accepted = CheckResult::new("t", "T", Status::Fail("exposed".into()))
        .accept("VNC on the LAN, reviewed");

    // What the user sees is unchanged...
    assert_eq!(accepted.severity(), Severity::Fail);
    assert!(accepted.is_accepted());
    // ...but it stops driving the alarm.
    assert_eq!(accepted.effective_severity(), Severity::Pass);
}

#[test]
fn accepted_risks_do_not_set_the_exit_code() {
    let results = vec![
        CheckResult::new("a", "A", Status::Pass("fine".into())),
        CheckResult::new("b", "B", Status::Fail("exposed".into())).accept("reviewed"),
    ];
    assert_eq!(report::exit_code(&results), 0);
    assert_eq!(opsec_dashboard::checks::worst(&results), Severity::Pass);
}

#[test]
fn an_unaccepted_failure_still_sets_the_exit_code() {
    let results = vec![
        CheckResult::new("a", "A", Status::Fail("exposed".into())).accept("reviewed"),
        CheckResult::new("b", "B", Status::Fail("also exposed".into())),
    ];
    assert_eq!(report::exit_code(&results), 2);
}

// ---------- surfacing ----------

// An accepted risk that looks identical to an unaddressed one is a trap: the
// exit code ignores it for reasons the report never explains.
#[test]
fn reports_say_why_a_failure_is_being_ignored() {
    let results =
        vec![CheckResult::new("t", "T", Status::Fail("exposed".into())).accept("VNC on the LAN")];

    let text = report::render_text(&results);
    assert!(text.contains("FAIL"), "the real status must stay visible");
    assert!(text.contains("accepted: VNC on the LAN"), "got:\n{text}");
    assert!(text.contains("1 accepted"), "summary missing:\n{text}");

    let json = report::render_json(&results);
    assert!(json.contains(r#""status": "fail""#), "got:\n{json}");
    assert!(json.contains(r#""effective": "pass""#), "got:\n{json}");
    assert!(
        json.contains(r#""accepted": "VNC on the LAN""#),
        "got:\n{json}"
    );
}

#[test]
fn the_board_counts_accepted_risks_separately() {
    let app = App::with_checks(vec![
        CheckResult::new("a", "A", Status::Pass("fine".into())),
        CheckResult::new("b", "B", Status::Fail("exposed".into())).accept("reviewed"),
        CheckResult::new("c", "C", Status::Fail("exposed".into())),
    ]);
    let summary = app.summary();

    // Still reported as failures — the board never hides a finding...
    assert_eq!(summary.fail, 2);
    // ...but one of them is a decision, not an outstanding problem.
    assert_eq!(summary.accepted, 1);
    assert_eq!(
        app.worst(),
        Severity::Fail,
        "the unaccepted failure still counts"
    );
}

#[test]
fn accepted_risks_drop_out_of_the_problems_filter() {
    let mut app = App::with_checks(vec![
        CheckResult::new("a", "A", Status::Pass("fine".into())),
        CheckResult::new("b", "B", Status::Fail("exposed".into())).accept("reviewed"),
        CheckResult::new("c", "C", Status::Fail("exposed".into())),
    ]);
    app.toggle_filter();
    assert_eq!(
        app.visible(),
        vec![2],
        "only the outstanding problem remains"
    );
}

#[test]
fn a_board_of_only_accepted_risks_reads_as_clear() {
    let app = App::with_checks(vec![
        CheckResult::new("b", "B", Status::Fail("exposed".into())).accept("reviewed"),
    ]);
    assert_eq!(app.worst(), Severity::Pass);
}
