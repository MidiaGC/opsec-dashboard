use opsec_dashboard::checks::{
    Status, parse_failed_logins, parse_failed_logins_full, parse_failed_logins_outcome,
};
use opsec_dashboard::exec::Outcome;

const ATTEMPT: &str = "Jul 25 22:16:39 host sudo[123]: pam_unix(sudo:auth): authentication failure";

fn repeat(n: usize) -> String {
    (0..n).map(|_| ATTEMPT).collect::<Vec<_>>().join("\n")
}

#[test]
fn zero_attempts_passes() {
    assert!(matches!(parse_failed_logins("").status, Status::Pass(_)));
}

#[test]
fn only_boot_separators_passes() {
    let input = "-- Boot abc123 --\n-- Boot def456 --";
    assert!(matches!(parse_failed_logins(input).status, Status::Pass(_)));
}

#[test]
fn one_attempt_warns() {
    let msg = match parse_failed_logins(ATTEMPT).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains('1'));
}

#[test]
fn five_attempts_warn_six_fail() {
    assert!(matches!(
        parse_failed_logins(&repeat(5)).status,
        Status::Warn(_)
    ));
    assert!(matches!(
        parse_failed_logins(&repeat(6)).status,
        Status::Fail(_)
    ));
}

#[test]
fn thousands_of_attempts_fail() {
    let msg = match parse_failed_logins(&repeat(5000)).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    assert!(msg.contains("5000"));
}

#[test]
fn boot_separators_and_blank_lines_are_not_counted() {
    let input = "-- Boot abc123 --

Jul 25 22:16:39 host sudo[123]: authentication failure
-- Boot def456 --
Jul 25 22:17:00 host sshd[456]: Failed password for invalid user root
";
    let msg = match parse_failed_logins(input).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains('2'), "expected 2 attempts, got: {msg}");
}

#[test]
fn real_machine_output() {
    let input = "-- Boot 81e889ca81884049afd981d746d7cac9 --
-- Boot b7144ab49d454b639ae0cc5f94ed7ffe --
Jul 25 22:16:39 archlinux hyprlock[18272]: pam_unix(hyprlock:auth): authentication failure; logname=kalex uid=1000 euid=1000 tty= ruser= rhost=  user=kalex";
    let msg = match parse_failed_logins(input).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains('1'));
}

// The dangerous case: journalctl exits 0 having read only the caller's own
// journal, which holds no PAM records. Reporting that as "0 attempts, clear"
// is a false negative on exactly the signal this check exists for.
#[test]
fn restricted_journal_is_unknown_not_a_clean_pass() {
    let stderr = "No journal files were found.\n";
    let r = parse_failed_logins_full("", stderr);
    let msg = match r.status {
        Status::Unknown(m) => m,
        other => panic!("a restricted journal must not pass, got {other:?}"),
    };
    assert!(msg.contains("no access"), "got {msg}");
    assert!(r.hint.is_some(), "should tell the user how to fix access");
}

#[test]
fn permission_denied_is_also_unknown() {
    assert!(matches!(
        parse_failed_logins_full("", "Permission denied\n").status,
        Status::Unknown(_)
    ));
}

// A warning on stderr alongside real records must not discard the records.
#[test]
fn stderr_noise_with_results_still_counts_them() {
    let r = parse_failed_logins_full(ATTEMPT, "Hint: You are currently not seeing messages\n");
    assert!(matches!(r.status, Status::Warn(_)), "got {:?}", r.status);
}

// ---------- orchestration failure modes ----------

#[test]
fn successful_run_with_no_matches_passes() {
    assert!(matches!(
        parse_failed_logins_outcome(&Outcome::ok("")).status,
        Status::Pass(_)
    ));
}

// Regression: the orchestrator used to accept stdout regardless of exit code,
// so an unsupported `--grep` on an older systemd reported a confident
// "0 attempts / PASS".
#[test]
fn nonzero_exit_is_unknown_not_a_pass() {
    let outcome = Outcome::failed_with("", "journalctl: unrecognized option '--grep'");
    let msg = match parse_failed_logins_outcome(&outcome).status {
        Status::Unknown(m) => m,
        other => panic!("a failed journalctl must not pass, got {other:?}"),
    };
    assert!(msg.contains("--grep"), "stderr should be surfaced: {msg}");
}

#[test]
fn missing_journalctl_is_unknown() {
    assert!(matches!(
        parse_failed_logins_outcome(&Outcome::NotFound).status,
        Status::Unknown(_)
    ));
}

#[test]
fn timed_out_journalctl_is_unknown() {
    let msg = match parse_failed_logins_outcome(&Outcome::TimedOut).status {
        Status::Unknown(m) => m,
        other => panic!("expected Unknown, got {other:?}"),
    };
    assert!(msg.contains("timed out"), "got {msg}");
}
