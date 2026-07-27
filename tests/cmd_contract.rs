// These tests verify that the orchestration functions degrade correctly
// when the underlying command fails (non-zero exit). We can't easily inject
// command failures in unit tests without mocking, but we CAN verify the
// contract: the parse_* functions are pure, and the orchestration functions
// must use run_cmd (strict) for commands where empty output is a valid result,
// and run_cmd_loose only for commands where non-zero exit still carries
// meaningful stdout (like `systemctl is-active`).
//
// This file documents the expected behavior contract.

use opsec_dashboard::checks::parse_failed_logins;

#[test]
fn empty_journal_output_means_zero_attempts() {
    // When journalctl succeeds (exit 0) but finds no matches, stdout may
    // contain only boot separators or be empty. Both → 0 attempts → Pass.
    assert!(matches!(parse_failed_logins("").status, opsec_dashboard::checks::Status::Pass(_)));
    assert!(matches!(
        parse_failed_logins("-- Boot abc --\n-- Boot def --").status,
        opsec_dashboard::checks::Status::Pass(_)
    ));
}

// The bug: failed_logins() previously used run_cmd_loose, which returns
// Some("") even on non-zero exit (e.g. unsupported --grep flag on old
// systemd). This caused a false "0 attempts" Pass. The fix: use run_cmd
// (strict) so command failures return None → Unknown.
//
// We can't directly test the orchestration function without mocking Command,
// but we can verify the source code uses the right helper:
#[test]
fn failed_logins_uses_strict_cmd_helper() {
    let source = include_str!("../src/checks.rs");
    // The failed_logins function should use run_cmd (not run_cmd_loose)
    // because journalctl exits 0 on no-match and non-zero on error.
    let fn_start = source.find("pub fn failed_logins()").expect("function not found");
    let fn_end = source[fn_start..]
        .find("pub fn ")
        .map(|i| fn_start + i)
        .unwrap_or(source.len());
    let fn_body = &source[fn_start..fn_end];
    assert!(
        fn_body.contains("run_cmd(") && !fn_body.contains("run_cmd_loose"),
        "failed_logins must use run_cmd (strict), not run_cmd_loose. Found:\n{fn_body}"
    );
}
