use opsec_dashboard::app::App;
use opsec_dashboard::checks::{CheckResult, Status};

use ratatui::backend::TestBackend;
use ratatui::Terminal;

fn fixture(n: usize) -> App {
    let checks = (0..n)
        .map(|i| CheckResult {
            label: format!("check-{i}"),
            status: Status::Pass("ok".into()),
        })
        .collect();
    App::with_checks(checks)
}

fn render(app: &App, w: u16, h: u16) -> String {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| opsec_dashboard::ui::draw(f, app)).unwrap();
    terminal.backend().to_string()
}

#[test]
fn normal_size_renders_all_checks_and_header_footer() {
    let app = fixture(5);
    let out = render(&app, 80, 30);
    assert!(out.contains("OPSEC Health Dashboard"), "header missing");
    assert!(out.contains("[r] refresh"), "footer missing");
    for i in 0..5 {
        assert!(out.contains(&format!("check-{i}")), "check-{i} missing");
    }
}

#[test]
fn too_small_shows_message_not_check_cells() {
    let app = fixture(5);
    let out = render(&app, 80, 4);
    assert!(out.contains("Terminal too small"), "expected too-small message");
    assert!(!out.contains("check-0"), "check cell rendered despite tiny size");
}

#[test]
fn partial_fit_hides_overflow_with_hint() {
    // 80x10: header(3) + body(6) + footer(1). body reserves 1 row for the hint,
    // so cells_area=5 fits 1 cell. 4 checks hidden.
    let app = fixture(5);
    let out = render(&app, 80, 10);
    assert!(out.contains("check-0"), "first check missing");
    assert!(!out.contains("check-1"), "second check should be hidden");
    assert!(out.contains("+4 checks hidden"), "overflow hint missing");
}

#[test]
fn header_always_present_when_not_too_small() {
    let app = fixture(1);
    let out = render(&app, 60, 7);
    assert!(out.contains("OPSEC Health Dashboard"));
}
