//! Dashboard state and the asynchronous refresh engine.
//!
//! Checks shell out to `ip`, `ss`, `nft`, `journalctl` and friends; on a busy
//! machine the journal scan alone can take seconds. Running them on the render
//! thread would freeze the UI on every refresh, so each check runs on its own
//! worker and reports back over a channel. The previous values stay on screen,
//! dimmed, until the new ones land.

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime};

use crate::alerts;
use crate::checks::{Check, CheckResult, Severity};
use crate::config::Config;
use crate::exec;
use crate::history::{History, Snapshot};

pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_INTERVAL: Duration = Duration::from_secs(300);

/// One line of the dashboard.
#[derive(Clone, Debug)]
pub struct Row {
    pub id: &'static str,
    pub label: String,
    pub about: &'static str,
    /// Last known result. `None` only before the very first result arrives.
    pub result: Option<CheckResult>,
    /// A refresh is in flight for this row; `result` may be stale.
    pub running: bool,
}

impl Row {
    pub fn severity(&self) -> Option<Severity> {
        self.result.as_ref().map(CheckResult::severity)
    }

    pub fn message(&self) -> &str {
        match &self.result {
            Some(r) => r.message(),
            None => "checking…",
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.result.as_ref().is_some_and(CheckResult::is_accepted)
    }
}

/// Row ordering.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SortMode {
    /// Registry order — stable, so rows never jump under the cursor.
    Registry,
    /// Worst first, ties broken by registry order.
    Severity,
}

impl SortMode {
    pub fn next(self) -> Self {
        match self {
            SortMode::Registry => SortMode::Severity,
            SortMode::Severity => SortMode::Registry,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortMode::Registry => "order",
            SortMode::Severity => "severity",
        }
    }
}

/// Which rows are shown.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    All,
    /// Anything that is not a clean pass, including unknowns.
    Problems,
}

impl Filter {
    pub fn next(self) -> Self {
        match self {
            Filter::All => Filter::Problems,
            Filter::Problems => Filter::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::Problems => "problems",
        }
    }
}

/// Counts per severity, plus how many checks are still running.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub unknown: usize,
    pub running: usize,
    /// Non-passing results covered by an `[exceptions]` entry. Counted here
    /// *as well as* in their real severity bucket, so the board never hides a
    /// finding — it only records that a decision was made about it.
    pub accepted: usize,
}

/// The confirm-then-run flow for a check's remediation command.
///
/// A dashboard that can change the system has to be explicit about it: the
/// command is always shown in full and always requires a keystroke of consent.
/// Nothing here ever runs as a side effect of a refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionState {
    Idle,
    /// Waiting for the user to approve `command`.
    Confirm {
        id: &'static str,
        label: String,
        command: String,
    },
    Running {
        id: &'static str,
        command: String,
    },
    Done {
        id: &'static str,
        command: String,
        /// `None` for a dry run — the command was shown, not executed.
        success: Option<bool>,
        output: String,
    },
}

/// How long a remediation command gets before it is killed.
const ACTION_TIMEOUT: Duration = Duration::from_secs(60);

pub struct App {
    pub rows: Vec<Row>,
    pub sort: SortMode,
    pub filter: Filter,
    pub auto_refresh: bool,
    pub interval: Duration,
    pub show_help: bool,
    /// Index into [`App::visible`], not into `rows`.
    pub cursor: usize,
    pub spinner: usize,

    /// Wall-clock time of the last completed refresh, for display only.
    pub last_refresh: SystemTime,
    /// Monotonic start of the last refresh. Used for the interval so a system
    /// clock adjustment cannot stall or spam auto-refresh.
    last_started: Instant,

    specs: Vec<&'static Check>,
    tx: Sender<(u64, CheckResult)>,
    rx: Receiver<(u64, CheckResult)>,
    /// Results tagged with an older generation belong to a superseded refresh
    /// and are dropped.
    generation: u64,
    pending: usize,

    pub config: Config,
    pub history: History,
    pub action: ActionState,
    action_tx: Sender<(&'static str, String, bool, String)>,
    action_rx: Receiver<(&'static str, String, bool, String)>,
    /// Set once the first full refresh has been recorded, so the very first
    /// snapshot of a session is not compared against a stale one from days ago
    /// in a way the user did not ask for.
    pub alerts_armed: bool,
}

impl App {
    pub fn new(specs: Vec<&'static Check>, interval: Duration) -> Self {
        Self::with_config(specs, interval, Config::default(), History::ephemeral(1))
    }

    pub fn with_config(
        specs: Vec<&'static Check>,
        interval: Duration,
        config: Config,
        history: History,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();
        let rows = specs
            .iter()
            .map(|c| Row {
                id: c.id,
                label: c.label.to_string(),
                about: c.about,
                result: None,
                running: false,
            })
            .collect();

        let mut app = Self {
            rows,
            sort: SortMode::Registry,
            filter: Filter::All,
            auto_refresh: true,
            interval: interval.clamp(MIN_INTERVAL, MAX_INTERVAL),
            show_help: false,
            cursor: 0,
            spinner: 0,
            last_refresh: SystemTime::UNIX_EPOCH,
            last_started: Instant::now(),
            specs,
            tx,
            rx,
            generation: 0,
            pending: 0,
            config,
            history,
            action: ActionState::Idle,
            action_tx,
            action_rx,
            alerts_armed: true,
        };
        app.refresh();
        app
    }

    /// Test/fixture constructor: an app holding fixed results, with no workers
    /// and no registry behind it.
    pub fn with_checks(checks: Vec<CheckResult>) -> Self {
        let (tx, rx) = mpsc::channel();
        let (action_tx, action_rx) = mpsc::channel();
        let rows = checks
            .into_iter()
            .map(|r| Row {
                id: r.id,
                label: r.label.clone(),
                about: "",
                result: Some(r),
                running: false,
            })
            .collect();

        Self {
            rows,
            sort: SortMode::Registry,
            filter: Filter::All,
            auto_refresh: false,
            interval: DEFAULT_INTERVAL,
            show_help: false,
            cursor: 0,
            spinner: 0,
            last_refresh: SystemTime::UNIX_EPOCH,
            last_started: Instant::now(),
            specs: Vec::new(),
            tx,
            rx,
            generation: 0,
            pending: 0,
            config: Config::default(),
            history: History::ephemeral(1),
            action: ActionState::Idle,
            action_tx,
            action_rx,
            alerts_armed: false,
        }
    }

    // -- refresh ------------------------------------------------------------

    /// Start a refresh. Returns immediately; results arrive via [`App::poll`].
    pub fn refresh(&mut self) {
        self.generation += 1;
        let generation = self.generation;
        self.last_started = Instant::now();
        self.pending = self.specs.len();

        for row in &mut self.rows {
            row.running = true;
        }

        for spec in &self.specs {
            let tx = self.tx.clone();
            let spec: &'static Check = spec;
            // `run_one` catches panics and applies configured exceptions, so a
            // misbehaving check cannot take the process down and an accepted
            // risk is honoured on every path.
            std::thread::spawn(move || {
                let _ = tx.send((generation, crate::checks::run_one(spec)));
            });
        }
    }

    /// Collect any results that have arrived. Returns true if anything changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok((generation, result)) = self.rx.try_recv() {
            if generation != self.generation {
                continue;
            }
            if !self.rows.iter().any(|r| r.id == result.id) {
                continue;
            }

            if self.alerts_armed {
                let previous = self.history.last(result.id);
                alerts::maybe_fire(&result, previous, &self.config.alerts);
            }

            if let Some(row) = self.rows.iter_mut().find(|r| r.id == result.id) {
                row.result = Some(result);
                row.running = false;
                self.pending = self.pending.saturating_sub(1);
                changed = true;
            }
        }

        if changed && self.pending == 0 {
            self.last_refresh = SystemTime::now();
            self.record_snapshot();
            // From here on every result has a predecessor from this session.
            self.alerts_armed = true;
        }
        changed
    }

    /// Store the completed refresh so the next one has something to compare
    /// against and the sparklines have another sample.
    fn record_snapshot(&mut self) {
        let results: Vec<CheckResult> = self.rows.iter().filter_map(|r| r.result.clone()).collect();
        if !results.is_empty() {
            self.history.record(Snapshot::from_results(&results));
        }
    }

    /// The recent trend for a check, oldest sample first.
    pub fn series(&self, id: &str) -> Vec<Severity> {
        self.history.series(id)
    }

    /// Start an auto-refresh if one is due. Returns true if it did.
    pub fn tick(&mut self) -> bool {
        if self.auto_refresh && !self.is_busy() && self.last_started.elapsed() >= self.interval {
            self.refresh();
            true
        } else {
            false
        }
    }

    pub fn is_busy(&self) -> bool {
        self.pending > 0
    }

    pub fn advance_spinner(&mut self) {
        self.spinner = self.spinner.wrapping_add(1);
    }

    /// How long ago the last full refresh completed.
    pub fn age(&self) -> Option<Duration> {
        self.last_refresh
            .elapsed()
            .ok()
            .filter(|_| self.last_refresh != SystemTime::UNIX_EPOCH)
    }

    // -- view ---------------------------------------------------------------

    /// Indices into `rows`, in display order after sorting and filtering.
    pub fn visible(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.rows.len())
            .filter(|&i| match self.filter {
                Filter::All => true,
                // Accepted risks are not problems to work through; they are
                // decisions already taken.
                Filter::Problems => self.rows[i]
                    .result
                    .as_ref()
                    .is_none_or(|r| r.effective_severity() != Severity::Pass),
            })
            .collect();

        if self.sort == SortMode::Severity {
            // Stable sort keeps registry order within a severity band.
            indices.sort_by_key(|&i| std::cmp::Reverse(self.rows[i].severity()));
        }
        indices
    }

    pub fn selected(&self) -> Option<&Row> {
        let visible = self.visible();
        visible.get(self.cursor).map(|&i| &self.rows[i])
    }

    pub fn summary(&self) -> Summary {
        let mut s = Summary::default();
        for row in &self.rows {
            if row.running && row.result.is_none() {
                s.running += 1;
                continue;
            }
            if row.result.as_ref().is_some_and(|r| r.is_accepted()) {
                s.accepted += 1;
            }
            match row.severity() {
                Some(Severity::Pass) => s.pass += 1,
                Some(Severity::Warn) => s.warn += 1,
                Some(Severity::Fail) => s.fail += 1,
                Some(Severity::Unknown) => s.unknown += 1,
                None => s.running += 1,
            }
        }
        s
    }

    /// Worst severity currently known, ignoring accepted risks — this drives
    /// the header colour, so it must mean "needs your attention".
    pub fn worst(&self) -> Severity {
        self.rows
            .iter()
            .filter_map(|r| r.result.as_ref())
            .map(CheckResult::effective_severity)
            .max()
            .unwrap_or(Severity::Pass)
    }

    // -- navigation ---------------------------------------------------------

    pub fn select_next(&mut self) {
        let len = self.visible().len();
        if len > 0 {
            self.cursor = (self.cursor + 1) % len;
        }
    }

    pub fn select_prev(&mut self) {
        let len = self.visible().len();
        if len > 0 {
            self.cursor = (self.cursor + len - 1) % len;
        }
    }

    pub fn select_first(&mut self) {
        self.cursor = 0;
    }

    pub fn select_last(&mut self) {
        self.cursor = self.visible().len().saturating_sub(1);
    }

    /// Keep the cursor inside the visible set after a sort/filter change.
    pub fn clamp_cursor(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.cursor = 0;
        } else if self.cursor >= len {
            self.cursor = len - 1;
        }
    }

    // -- corrective actions -------------------------------------------------

    /// Offer the selected check's remediation command for confirmation.
    /// Returns false when there is nothing to offer.
    pub fn propose_action(&mut self) -> bool {
        let Some(row) = self.selected() else {
            return false;
        };
        let Some(result) = &row.result else {
            return false;
        };
        let Some(command) = result.fix.clone() else {
            return false;
        };

        self.action = ActionState::Confirm {
            id: row.id,
            label: row.label.clone(),
            command,
        };
        true
    }

    pub fn cancel_action(&mut self) {
        self.action = ActionState::Idle;
    }

    /// Show what would run without running it.
    pub fn dry_run_action(&mut self) {
        if let ActionState::Confirm { id, command, .. } = &self.action {
            self.action = ActionState::Done {
                id,
                command: command.clone(),
                success: None,
                output: "dry run — nothing was executed".to_string(),
            };
        }
    }

    /// Execute the pending command. Only reachable from `Confirm`, so there is
    /// no path that runs anything the user has not just seen and approved.
    pub fn confirm_action(&mut self) {
        let ActionState::Confirm { id, command, .. } = &self.action else {
            return;
        };
        let (id, command) = (*id, command.clone());
        let tx = self.action_tx.clone();
        let spawned = command.clone();

        self.action = ActionState::Running {
            id,
            command: command.clone(),
        };

        std::thread::spawn(move || {
            let outcome = exec::run_timeout("sh", &["-c", &spawned], ACTION_TIMEOUT);
            let success = outcome.succeeded();
            let output = match &outcome {
                crate::exec::Outcome::Completed { stdout, stderr, .. } => {
                    let mut combined = String::new();
                    combined.push_str(stdout.trim());
                    if !stderr.trim().is_empty() {
                        if !combined.is_empty() {
                            combined.push('\n');
                        }
                        combined.push_str(stderr.trim());
                    }
                    if combined.is_empty() {
                        "(no output)".to_string()
                    } else {
                        combined
                    }
                }
                other => other
                    .unavailable_reason()
                    .unwrap_or_else(|| "could not run".to_string()),
            };
            let _ = tx.send((id, command, success, output));
        });
    }

    /// Collect a finished action. Returns true if the state changed.
    pub fn poll_action(&mut self) -> bool {
        let mut changed = false;
        while let Ok((id, command, success, output)) = self.action_rx.try_recv() {
            self.action = ActionState::Done {
                id,
                command,
                success: Some(success),
                output,
            };
            changed = true;
            // A successful fix changes the very thing being measured, so the
            // board must not keep showing the pre-fix verdict.
            if success {
                self.refresh();
            }
        }
        changed
    }

    pub fn action_is_modal(&self) -> bool {
        !matches!(self.action, ActionState::Idle)
    }

    /// The remediation command for the selected row, if it has one.
    pub fn selected_fix(&self) -> Option<&str> {
        self.selected()?.result.as_ref()?.fix.as_deref()
    }

    pub fn toggle_sort(&mut self) {
        self.sort = self.sort.next();
        self.clamp_cursor();
    }

    pub fn toggle_filter(&mut self) {
        self.filter = self.filter.next();
        self.clamp_cursor();
    }

    pub fn adjust_interval(&mut self, delta: i64) {
        let secs = self.interval.as_secs() as i64 + delta;
        let secs = secs.clamp(MIN_INTERVAL.as_secs() as i64, MAX_INTERVAL.as_secs() as i64);
        self.interval = Duration::from_secs(secs as u64);
    }
}
