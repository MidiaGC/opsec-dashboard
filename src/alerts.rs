//! Notifications for checks that get worse.
//!
//! The default is to fire only on a **regression** — a check that was fine and
//! now is not. Alerting on every non-passing result would mean a notification
//! storm on every refresh for a machine with a known, accepted gap, and an
//! alert channel that is always shouting is one nobody reads.

use std::time::Duration;

use crate::checks::{CheckResult, Severity};
use crate::config::Alerts;
use crate::exec;
use crate::history;

/// How long an alert command gets before it is killed.
const ALERT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether this result should raise an alert, given what the check said last
/// time.
pub fn should_alert(previous: Option<Severity>, result: &CheckResult, alerts: &Alerts) -> bool {
    if !alerts.enabled || alerts.command.trim().is_empty() {
        return false;
    }
    // An accepted risk is a decision already made; it does not get to page you.
    if result.is_accepted() {
        return false;
    }

    if alerts.on_any_problem {
        result.severity() != Severity::Pass
    } else {
        history::is_regression(previous, result.severity())
    }
}

/// Substitute the placeholders in an alert command template.
///
/// Values are shell-quoted, because a check message contains whatever the
/// system printed — interface names, ports, file paths — and interpolating that
/// into a command line unquoted is a command-injection waiting to happen.
pub fn expand(template: &str, result: &CheckResult, previous: Option<Severity>) -> String {
    let previous = previous.map(Severity::as_str).unwrap_or("none");
    template
        .replace("{id}", &shell_quote(result.id))
        .replace("{label}", &shell_quote(&result.label))
        .replace("{status}", &shell_quote(result.severity().as_str()))
        .replace("{message}", &shell_quote(result.message()))
        .replace("{previous}", &shell_quote(previous))
}

/// Wrap a value in single quotes, escaping any single quote it contains.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Run the alert command for a result, off the caller's thread.
///
/// Alerts are best-effort: a broken `notify-send` must not stall a refresh or
/// take down the dashboard, so failures are swallowed by design.
pub fn fire(result: &CheckResult, previous: Option<Severity>, alerts: &Alerts) {
    let command = expand(&alerts.command, result, previous);
    std::thread::spawn(move || {
        let _ = exec::run_timeout("sh", &["-c", &command], ALERT_TIMEOUT);
    });
}

/// Evaluate and, if warranted, fire. Returns whether an alert was raised.
pub fn maybe_fire(result: &CheckResult, previous: Option<Severity>, alerts: &Alerts) -> bool {
    if should_alert(previous, result, alerts) {
        fire(result, previous, alerts);
        true
    } else {
        false
    }
}
