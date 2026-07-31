//! Result history: a trend line per check, and the "what did this look like
//! last time" that regression alerts are built on.
//!
//! Stored as one append-only line per refresh:
//!
//! ```text
//! 1785007719 vpn=pass mac=fail nftables=warn
//! ```
//!
//! Deliberately not JSON: the file is written on every refresh and read on
//! every start, it is useful to `grep` and `awk` directly, and the alternative
//! is carrying a parser for a format only this program produces.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checks::{CheckResult, Severity};

/// How many samples the sparkline shows.
pub const SPARK_WIDTH: usize = 12;

/// One refresh: when it happened and what every check said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub at: u64,
    pub severities: BTreeMap<String, Severity>,
}

impl Snapshot {
    pub fn from_results(results: &[CheckResult]) -> Self {
        Self {
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            severities: results
                .iter()
                .map(|r| (r.id.to_string(), r.severity()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct History {
    /// Oldest first.
    pub snapshots: Vec<Snapshot>,
    path: Option<PathBuf>,
    retain: usize,
}

impl History {
    /// Open the history at `path`. A missing or partly corrupt file yields
    /// whatever could be read — losing a trend line is not worth refusing to
    /// start over.
    pub fn open(path: Option<PathBuf>, retain: usize) -> Self {
        let snapshots = path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|text| text.lines().filter_map(parse_line).collect())
            .unwrap_or_default();

        Self {
            snapshots,
            path,
            retain: retain.max(1),
        }
    }

    /// An in-memory history, for tests and for `history.enabled = false`.
    pub fn ephemeral(retain: usize) -> Self {
        Self {
            snapshots: Vec::new(),
            path: None,
            retain: retain.max(1),
        }
    }

    /// The severity a check reported in the most recent snapshot.
    pub fn last(&self, id: &str) -> Option<Severity> {
        self.snapshots
            .iter()
            .rev()
            .find_map(|s| s.severities.get(id).copied())
    }

    /// The most recent `SPARK_WIDTH` samples for a check, oldest first. Only
    /// snapshots that actually recorded the check contribute, so disabling and
    /// re-enabling one does not punch a hole in its trend.
    pub fn series(&self, id: &str) -> Vec<Severity> {
        let mut series: Vec<Severity> = self
            .snapshots
            .iter()
            .rev()
            .filter_map(|s| s.severities.get(id).copied())
            .take(SPARK_WIDTH)
            .collect();
        series.reverse();
        series
    }

    /// Record a refresh and persist it.
    pub fn record(&mut self, snapshot: Snapshot) {
        self.snapshots.push(snapshot);
        self.trim();
        self.persist();
    }

    fn trim(&mut self) {
        if self.snapshots.len() > self.retain {
            let excess = self.snapshots.len() - self.retain;
            self.snapshots.drain(..excess);
        }
    }

    /// Write the whole file. It is bounded by `retain` and written once per
    /// refresh interval, so the simplicity is worth more than an append plus
    /// periodic compaction.
    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let body: String = self
            .snapshots
            .iter()
            .map(|s| render_line(s) + "\n")
            .collect();

        // Write-then-rename so an interrupted write cannot truncate the
        // history that already exists.
        let temp = path.with_extension("tmp");
        if let Ok(mut file) = std::fs::File::create(&temp)
            && file.write_all(body.as_bytes()).is_ok()
            && file.sync_all().is_ok()
        {
            let _ = std::fs::rename(&temp, path);
            return;
        }
        let _ = std::fs::remove_file(&temp);
    }
}

/// `<epoch> id=severity id=severity …`
pub fn render_line(snapshot: &Snapshot) -> String {
    let mut out = snapshot.at.to_string();
    for (id, severity) in &snapshot.severities {
        out.push(' ');
        out.push_str(id);
        out.push('=');
        out.push_str(severity.as_str());
    }
    out
}

pub fn parse_line(line: &str) -> Option<Snapshot> {
    let mut tokens = line.split_whitespace();
    let at: u64 = tokens.next()?.parse().ok()?;

    let severities = tokens
        .filter_map(|token| {
            let (id, severity) = token.split_once('=')?;
            Some((id.to_string(), severity_from_str(severity)?))
        })
        .collect();

    Some(Snapshot { at, severities })
}

pub fn severity_from_str(raw: &str) -> Option<Severity> {
    match raw {
        "pass" => Some(Severity::Pass),
        "warn" => Some(Severity::Warn),
        "fail" => Some(Severity::Fail),
        "unknown" => Some(Severity::Unknown),
        _ => None,
    }
}

/// The block character for one sample. Taller and redder is worse.
pub fn spark_glyph(severity: Severity) -> char {
    match severity {
        Severity::Pass => '▁',
        Severity::Unknown => '▃',
        Severity::Warn => '▅',
        Severity::Fail => '▇',
    }
}

/// `$XDG_STATE_HOME/opsec-dashboard/history`, falling back to
/// `~/.local/state/...`.
pub fn default_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("opsec-dashboard").join("history"))
}

/// Whether `new` is worse than `previous` — the trigger for a regression alert.
pub fn is_regression(previous: Option<Severity>, new: Severity) -> bool {
    match previous {
        Some(before) => new > before,
        // First ever observation: nothing to compare against, so nothing has
        // regressed. Alerting here would fire the whole board on first run.
        None => false,
    }
}

/// Convenience for callers that only have a path as `&Path`.
pub fn open_at(path: &Path, retain: usize) -> History {
    History::open(Some(path.to_path_buf()), retain)
}
