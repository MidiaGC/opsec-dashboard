use opsec_dashboard::app::{App, Filter, SortMode};
use opsec_dashboard::checks::{CheckResult, Severity, Status};
use opsec_dashboard::ui::UiState;

use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn result(id: &'static str, status: Status) -> CheckResult {
    CheckResult::new(id, id, status)
}

fn fixture(n: usize) -> App {
    const IDS: [&str; 8] = [
        "check-0", "check-1", "check-2", "check-3", "check-4", "check-5", "check-6", "check-7",
    ];
    App::with_checks(
        IDS.iter()
            .take(n)
            .map(|id| result(id, Status::Pass("ok".into())))
            .collect(),
    )
}

fn render(app: &App, w: u16, h: u16) -> String {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut ui = UiState::default();
    terminal
        .draw(|f| opsec_dashboard::ui::draw(f, app, &mut ui))
        .unwrap();
    terminal.backend().to_string()
}

#[test]
fn normal_size_renders_header_checks_and_footer() {
    let out = render(&fixture(5), 100, 30);
    assert!(out.contains("OPSEC Health Dashboard"), "header missing");
    assert!(out.contains("quit"), "footer missing");
    assert!(out.contains("Details"), "detail pane missing");
    for i in 0..5 {
        assert!(out.contains(&format!("check-{i}")), "check-{i} missing");
    }
}

#[test]
fn summary_counts_are_shown() {
    let app = App::with_checks(vec![
        result("a", Status::Pass("ok".into())),
        result("b", Status::Warn("meh".into())),
        result("c", Status::Fail("bad".into())),
        result("d", Status::Unknown("dunno".into())),
    ]);
    let out = render(&app, 100, 30);
    assert!(out.contains("1 fail"), "fail count missing:\n{out}");
    assert!(out.contains("1 warn"), "warn count missing");
    assert!(out.contains("1 pass"), "pass count missing");
    assert!(out.contains("1 unknown"), "unknown count missing");
}

#[test]
fn too_small_shows_message_not_check_cells() {
    let out = render(&fixture(5), 80, 2);
    assert!(out.contains("too small"), "expected too-small message");
    assert!(!out.contains("check-0"), "check rendered despite tiny size");
}

// Regression: rows beyond the viewport used to be dropped with a "resize to
// view" hint. A one-line-per-check list scrolls instead, so every check stays
// reachable at any terminal size.
#[test]
fn more_checks_than_rows_stay_reachable_by_scrolling() {
    let mut app = fixture(8);
    let small = render(&app, 80, 8);
    assert!(small.contains("check-0"), "first check missing");
    assert!(!small.contains("resize"), "should scroll, not give up");

    app.select_last();
    let scrolled = render(&app, 80, 8);
    assert!(
        scrolled.contains("check-7"),
        "last check unreachable:\n{scrolled}"
    );
}

#[test]
fn header_survives_a_short_terminal_and_is_dropped_before_the_list() {
    let out = render(&fixture(1), 60, 7);
    assert!(out.contains("OPSEC Health Dashboard"));
    assert!(out.contains("check-0"));

    // Shorter still: the header goes, the checks stay.
    let tiny = render(&fixture(1), 60, 5);
    assert!(tiny.contains("check-0"), "checks must be the last to go");
}

#[test]
fn help_overlay_lists_the_keybindings() {
    let mut app = fixture(3);
    app.show_help = true;
    let out = render(&app, 100, 30);
    assert!(out.contains("Keys"), "help title missing");
    assert!(out.contains("toggle auto-refresh"), "help body missing");
}

#[test]
fn detail_pane_shows_the_selected_check_and_its_hint() {
    let app = App::with_checks(vec![
        result("first", Status::Pass("ok".into())),
        CheckResult::new("second", "second", Status::Fail("it is broken".into()))
            .with_hint("turn it back on"),
    ]);
    let out = render(&app, 100, 30);
    assert!(out.contains("ok"), "first check message missing");

    let mut app = app;
    app.select_next();
    let out = render(&app, 100, 30);
    assert!(
        out.contains("it is broken"),
        "detail message missing:\n{out}"
    );
    assert!(out.contains("turn it back on"), "hint missing:\n{out}");
}

// ---------- state ----------

#[test]
fn severity_sort_puts_the_worst_first() {
    let mut app = App::with_checks(vec![
        result("p", Status::Pass("ok".into())),
        result("w", Status::Warn("meh".into())),
        result("f", Status::Fail("bad".into())),
    ]);
    assert_eq!(app.visible(), vec![0, 1, 2]);

    app.sort = SortMode::Severity;
    assert_eq!(app.visible(), vec![2, 1, 0], "fail, then warn, then pass");
}

#[test]
fn problems_filter_hides_passing_checks() {
    let mut app = App::with_checks(vec![
        result("p", Status::Pass("ok".into())),
        result("f", Status::Fail("bad".into())),
    ]);
    app.filter = Filter::Problems;
    assert_eq!(app.visible(), vec![1]);

    let out = render(&app, 100, 30);
    assert!(out.contains("bad"));
}

#[test]
fn cursor_is_clamped_when_the_filter_shrinks_the_list() {
    let mut app = App::with_checks(vec![
        result("f", Status::Fail("bad".into())),
        result("p1", Status::Pass("ok".into())),
        result("p2", Status::Pass("ok".into())),
    ]);
    app.select_last();
    assert_eq!(app.cursor, 2);

    app.toggle_filter();
    assert_eq!(app.cursor, 0, "cursor must stay inside the visible set");
    assert!(app.selected().is_some());
}

#[test]
fn navigation_wraps_around() {
    let mut app = fixture(3);
    app.select_prev();
    assert_eq!(app.cursor, 2, "moving up from the top wraps to the bottom");
    app.select_next();
    assert_eq!(app.cursor, 0);
}

#[test]
fn navigation_on_an_empty_list_does_not_panic() {
    let mut app = App::with_checks(Vec::new());
    app.select_next();
    app.select_prev();
    app.select_last();
    assert!(app.selected().is_none());
    render(&app, 60, 20);
}

#[test]
fn worst_severity_drives_the_overall_posture() {
    let app = App::with_checks(vec![
        result("p", Status::Pass("ok".into())),
        result("u", Status::Unknown("dunno".into())),
        result("w", Status::Warn("meh".into())),
    ]);
    assert_eq!(app.worst(), Severity::Warn);
}

#[test]
fn interval_adjustment_is_clamped() {
    let mut app = fixture(1);
    app.adjust_interval(-1000);
    assert_eq!(app.interval, opsec_dashboard::app::MIN_INTERVAL);
    app.adjust_interval(100_000);
    assert_eq!(app.interval, opsec_dashboard::app::MAX_INTERVAL);
}
