//! Headless output for `--once` and `--json`, so the dashboard can be used
//! from scripts, cron jobs and CI as well as interactively.

use std::io::IsTerminal;

use crate::checks::{CheckResult, Severity};
use crate::timefmt::format_local;

/// Exit code convention: 0 clean, 1 warnings or unknowns, 2 failures.
/// Chosen so `opsec-dashboard --once || alert` does something useful.
pub fn exit_code(results: &[CheckResult]) -> i32 {
    match crate::checks::worst(results) {
        Severity::Pass => 0,
        Severity::Warn | Severity::Unknown => 1,
        Severity::Fail => 2,
    }
}

/// Human-readable single-shot report. Colours are emitted only when stdout is
/// a terminal, so redirecting to a file yields clean text.
pub fn render_text(results: &[CheckResult]) -> String {
    let colored = std::io::stdout().is_terminal();
    let width = results
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0);

    let mut out = format!(
        "OPSEC health — {}\n\n",
        format_local(std::time::SystemTime::now())
    );

    for result in results {
        let severity = result.severity();
        let tag = severity.tag();
        let tag = if colored {
            format!("\x1b[{}m{tag}\x1b[0m", ansi_code(severity))
        } else {
            tag.to_string()
        };
        out.push_str(&format!(
            "{tag}  {:<width$}  {}\n",
            result.label,
            result.message()
        ));
        // An accepted risk keeps its real status, so the reason has to be on
        // screen next to it — otherwise the report reads as an unaddressed
        // failure that the exit code inexplicably ignores.
        match (&result.accepted, &result.hint) {
            (Some(reason), _) => {
                out.push_str(&format!("      {:<width$}  ✓ accepted: {reason}\n", ""));
            }
            (None, Some(hint)) => {
                out.push_str(&format!("      {:<width$}  → {hint}\n", ""));
            }
            (None, None) => {}
        }
    }

    let (pass, warn, fail, unknown) = tally(results);
    let accepted = results.iter().filter(|r| r.is_accepted()).count();
    out.push_str(&format!(
        "\n{pass} pass, {warn} warn, {fail} fail, {unknown} unknown"
    ));
    if accepted > 0 {
        out.push_str(&format!(
            " ({accepted} accepted, not counted against the exit code)"
        ));
    }
    out.push('\n');
    out
}

/// Machine-readable report. Hand-rolled rather than pulling in serde for one
/// flat array of four-field objects.
pub fn render_json(results: &[CheckResult]) -> String {
    let (pass, warn, fail, unknown) = tally(results);
    let mut out = String::from("{\n");
    out.push_str(&format!(
        "  \"generated_at\": \"{}\",\n",
        format_local(std::time::SystemTime::now())
    ));
    out.push_str(&format!(
        "  \"worst\": \"{}\",\n",
        crate::checks::worst(results).as_str()
    ));
    let accepted = results.iter().filter(|r| r.is_accepted()).count();
    out.push_str(&format!(
        "  \"summary\": {{ \"pass\": {pass}, \"warn\": {warn}, \"fail\": {fail}, \"unknown\": {unknown}, \"accepted\": {accepted} }},\n"
    ));
    out.push_str("  \"checks\": [\n");

    for (i, result) in results.iter().enumerate() {
        let comma = if i + 1 == results.len() { "" } else { "," };
        let hint = match &result.hint {
            Some(h) => format!("\"{}\"", escape(h)),
            None => "null".to_string(),
        };
        let accepted = match &result.accepted {
            Some(reason) => format!("\"{}\"", escape(reason)),
            None => "null".to_string(),
        };
        let fix = match &result.fix {
            Some(command) => format!("\"{}\"", escape(command)),
            None => "null".to_string(),
        };
        out.push_str(&format!(
            "    {{ \"id\": \"{}\", \"label\": \"{}\", \"status\": \"{}\", \"effective\": \"{}\", \"message\": \"{}\", \"hint\": {hint}, \"fix\": {fix}, \"accepted\": {accepted} }}{comma}\n",
            escape(result.id),
            escape(&result.label),
            result.severity().as_str(),
            result.effective_severity().as_str(),
            escape(result.message()),
        ));
    }

    out.push_str("  ]\n}\n");
    out
}

fn tally(results: &[CheckResult]) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);
    for result in results {
        match result.severity() {
            Severity::Pass => counts.0 += 1,
            Severity::Warn => counts.1 += 1,
            Severity::Fail => counts.2 += 1,
            Severity::Unknown => counts.3 += 1,
        }
    }
    counts
}

fn ansi_code(severity: Severity) -> &'static str {
    match severity {
        Severity::Pass => "32",
        Severity::Warn => "33",
        Severity::Fail => "31",
        Severity::Unknown => "90",
    }
}

/// Escape a string for inclusion in a JSON string literal.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
