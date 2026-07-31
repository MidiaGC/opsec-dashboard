use std::time::{Duration, Instant};

use opsec_dashboard::exec::{self, Outcome};

#[test]
fn captures_stdout_and_exit_status() {
    let out = exec::run("sh", &["-c", "echo hello"]);
    assert!(out.succeeded());
    assert_eq!(out.stdout().trim(), "hello");
    assert_eq!(out.success_stdout().map(str::trim), Some("hello"));
}

#[test]
fn captures_stderr_separately_from_stdout() {
    let out = exec::run("sh", &["-c", "echo oops >&2; exit 3"]);
    assert!(!out.succeeded());
    assert_eq!(out.stdout(), "");
    assert_eq!(out.stderr().trim(), "oops");
    // stdout of a failed run must not be mistaken for a valid empty result.
    assert_eq!(out.success_stdout(), None);
}

#[test]
fn missing_binary_is_reported_as_not_found() {
    let out = exec::run("definitely-not-a-real-binary-9f3a", &[]);
    assert_eq!(out, Outcome::NotFound);
    assert!(out.unavailable_reason().is_some());
}

// A wedged helper must not stall its check forever.
#[test]
fn a_hung_child_is_killed_at_the_deadline() {
    let started = Instant::now();
    let out = exec::run_timeout("sleep", &["30"], Duration::from_millis(300));
    let elapsed = started.elapsed();

    assert_eq!(out, Outcome::TimedOut);
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout did not fire, took {elapsed:?}"
    );
}

// Regression guard for pipe-buffer deadlock: a child writing more than a pipe
// buffer holds while we wait on the deadline must still complete.
#[test]
fn large_output_does_not_deadlock() {
    let out = exec::run_timeout("sh", &["-c", "seq 1 200000"], Duration::from_secs(20));
    assert!(out.succeeded(), "expected success, got {out:?}");
    assert_eq!(out.stdout().lines().count(), 200_000);
}

#[test]
fn stdin_is_closed_so_children_cannot_block_on_input() {
    let out = exec::run_timeout("cat", &[], Duration::from_secs(3));
    assert!(
        out.succeeded(),
        "cat should see EOF immediately, got {out:?}"
    );
    assert_eq!(out.stdout(), "");
}

#[test]
fn sudo_escalation_can_be_disabled() {
    assert!(exec::sudo_allowed(), "escalation is on by default");
    exec::set_allow_sudo(false);
    assert!(!exec::sudo_allowed());
    exec::set_allow_sudo(true);
}
