//! Journal-derived checks.

use crate::checks::CheckResult;
use crate::config::{self, Thresholds};
use crate::exec::{self, Outcome, SLOW_TIMEOUT};

const LOGIN_ID: &str = "failed-logins";
const LOGIN_LABEL: &str = "Failed logins (24h)";

const GREP_PATTERN: &str = "authentication failure|invalid user|Failed password|FAILED LOGIN";

pub fn failed_logins() -> CheckResult {
    let outcome = exec::run_timeout(
        "journalctl",
        &["--since", "24h ago", "--grep", GREP_PATTERN, "--no-pager"],
        SLOW_TIMEOUT,
    );
    parse_failed_logins_outcome(&outcome)
}

/// Interpret the journalctl invocation.
///
/// The important failure mode: without membership of `systemd-journal` (or
/// `wheel`), journalctl happily exits **zero** having read only the user's own
/// journal — which contains no PAM records. Counting that as "0 attempts, all
/// clear" is a false negative on the exact signal this check exists to catch,
/// so a restricted journal is reported as unknown instead.
pub fn parse_failed_logins_outcome(outcome: &Outcome) -> CheckResult {
    match outcome {
        Outcome::Completed {
            stdout,
            stderr,
            success: true,
        } => parse_failed_logins_full(stdout, stderr),
        Outcome::Completed {
            stderr,
            success: false,
            ..
        } => CheckResult::unknown(
            LOGIN_ID,
            LOGIN_LABEL,
            first_line(stderr)
                .unwrap_or("journalctl failed")
                .to_string(),
        ),
        other => CheckResult::unknown(
            LOGIN_ID,
            LOGIN_LABEL,
            other
                .unavailable_reason()
                .unwrap_or_else(|| "journalctl unavailable".to_string()),
        ),
    }
}

/// Pure parser for journalctl output, ignoring stderr diagnostics.
pub fn parse_failed_logins(journal_output: &str) -> CheckResult {
    parse_failed_logins_full(journal_output, "")
}

/// Pure parser for journalctl stdout **and** stderr, at the configured
/// thresholds.
pub fn parse_failed_logins_full(journal_output: &str, stderr: &str) -> CheckResult {
    parse_failed_logins_with(journal_output, stderr, config::thresholds())
}

/// Pure parser with explicit thresholds.
pub fn parse_failed_logins_with(
    journal_output: &str,
    stderr: &str,
    thresholds: Thresholds,
) -> CheckResult {
    let count = journal_output
        .lines()
        .map(str::trim_end)
        // `-- Boot <id> --` and `-- No entries --` are journalctl's own
        // separators, not log records.
        .filter(|l| !l.is_empty() && !l.starts_with("-- "))
        .count();

    if count == 0 && journal_restricted(stderr) {
        return CheckResult::unknown(LOGIN_ID, LOGIN_LABEL, "no access to the system journal")
            .with_hint(
                "Add your user to the `systemd-journal` group; until then this check \
                 can only see your own session's journal.",
            );
    }

    let result = if count > thresholds.failed_logins_fail_above {
        CheckResult::fail(LOGIN_ID, LOGIN_LABEL, format!("{count} attempts"))
    } else if count > thresholds.failed_logins_warn_above {
        CheckResult::warn(LOGIN_ID, LOGIN_LABEL, format!("{count} attempts"))
    } else {
        CheckResult::pass(LOGIN_ID, LOGIN_LABEL, format!("{count} attempts"))
    };
    result.with_hint("Review with `journalctl --since '24h ago' --grep 'authentication failure'`.")
}

/// Whether journalctl's diagnostics indicate we were denied the system journal.
fn journal_restricted(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("no journal files were found")
        || lower.contains("not have access")
        || lower.contains("permission denied")
        || lower.contains("operation not permitted")
}

fn first_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| !l.is_empty())
}
