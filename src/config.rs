//! Configuration file: which checks run, at what thresholds, with which
//! exceptions, and what happens when something regresses.
//!
//! The format is a deliberate subset of TOML — sections, scalars and string
//! arrays — parsed here rather than pulled in as a dependency. A tool whose job
//! is to audit a machine's security posture should be readable end to end.
//!
//! ```toml
//! [general]
//! interval = 10
//! profile  = "travel"
//!
//! [checks]
//! disabled = ["usbguard"]
//!
//! [thresholds]
//! failed_logins_fail_above = 10
//!
//! [exceptions]
//! listening-tcp = "5900 is VNC on the LAN, accepted"
//!
//! [alerts]
//! enabled = true
//! command = "notify-send 'OPSEC' '{label}: {status} — {message}'"
//!
//! [profiles.travel]
//! interval = 3
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use crate::app::{DEFAULT_INTERVAL, MAX_INTERVAL, MIN_INTERVAL};

// ---------------------------------------------------------------------------
// Values and documents
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[String]> {
        match self {
            Value::List(l) => Some(l),
            // A bare string is accepted where a list is expected; writing
            // `disabled = "usbguard"` is an easy slip and rejecting it would be
            // pedantry.
            Value::Str(s) => Some(std::slice::from_ref(s)),
            _ => None,
        }
    }
}

/// A parsed document: section name → key → value. Section names keep their
/// dotted form (`profiles.travel`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    pub sections: BTreeMap<String, BTreeMap<String, Value>>,
}

impl Document {
    pub fn get(&self, section: &str, key: &str) -> Option<&Value> {
        self.sections.get(section)?.get(key)
    }

    pub fn section(&self, name: &str) -> Option<&BTreeMap<String, Value>> {
        self.sections.get(name)
    }
}

/// Parse the supported TOML subset. Errors carry the line number, because a
/// config that silently half-applies is worse than one that refuses to load.
pub fn parse_document(text: &str) -> Result<Document, String> {
    let mut doc = Document::default();
    let mut current = String::from("general");

    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(header) = line.strip_prefix('[') {
            let name = header
                .strip_suffix(']')
                .ok_or_else(|| format!("line {line_no}: unterminated section header"))?
                .trim();
            if name.is_empty() {
                return Err(format!("line {line_no}: empty section name"));
            }
            current = name.trim_matches('"').to_string();
            doc.sections.entry(current.clone()).or_default();
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_no}: expected `key = value`"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("line {line_no}: empty key"));
        }
        let value = parse_value(value.trim())
            .ok_or_else(|| format!("line {line_no}: could not parse value for `{key}`"))?;

        doc.sections
            .entry(current.clone())
            .or_default()
            .insert(key.trim_matches('"').to_string(), value);
    }

    Ok(doc)
}

/// Remove a trailing `#` comment, respecting quoted strings so a `#` inside an
/// alert command survives.
fn strip_comment(line: &str) -> &str {
    // The opening quote has to be remembered, not just counted: a `'` inside a
    // double-quoted alert command is content, and treating it as a delimiter
    // would end the string early and swallow the rest as a comment.
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (c, quote) {
            ('"' | '\'', None) => quote = Some(c),
            (c, Some(open)) if c == open => quote = None,
            ('#', None) => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse_value(raw: &str) -> Option<Value> {
    if raw.is_empty() {
        return None;
    }
    if let Some(inner) = raw.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        let items = inner
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| unquote(s).to_string())
            .collect();
        return Some(Value::List(items));
    }
    match raw {
        "true" => return Some(Value::Bool(true)),
        "false" => return Some(Value::Bool(false)),
        _ => {}
    }
    if let Ok(n) = raw.parse::<i64>() {
        return Some(Value::Int(n));
    }
    Some(Value::Str(unquote(raw).to_string()))
}

fn unquote(raw: &str) -> &str {
    let raw = raw.trim();
    for quote in ['"', '\''] {
        if raw.len() >= 2 && raw.starts_with(quote) && raw.ends_with(quote) {
            return &raw[1..raw.len() - 1];
        }
    }
    raw
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Boundaries at which a count stops being acceptable. Both are "above", so
/// `warn_above = 0` means "any occurrence warns".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Thresholds {
    pub failed_logins_warn_above: usize,
    pub failed_logins_fail_above: usize,
    pub listening_warn_above: usize,
    pub listening_fail_above: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            failed_logins_warn_above: 0,
            failed_logins_fail_above: 5,
            listening_warn_above: 0,
            listening_fail_above: 2,
        }
    }
}

/// When a check gets worse, what to do about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alerts {
    pub enabled: bool,
    /// Shell command with `{id}`, `{label}`, `{status}`, `{message}` and
    /// `{previous}` placeholders.
    pub command: String,
    /// Alert on any non-passing result rather than only on a regression.
    pub on_any_problem: bool,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            enabled: false,
            command: "notify-send 'OPSEC: {label}' '{status} — {message}'".to_string(),
            on_any_problem: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistorySettings {
    pub enabled: bool,
    /// How many refreshes to retain.
    pub retain: usize,
}

impl Default for HistorySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            retain: 500,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub interval: Duration,
    pub sudo: bool,
    pub profile: Option<String>,
    /// Checks that never run.
    pub disabled: Vec<String>,
    /// When non-empty, an allowlist: only these run.
    pub enabled: Vec<String>,
    pub thresholds: Thresholds,
    /// Check id → why its result is accepted. Accepted results keep their real
    /// status on screen but stop driving alerts and the exit code.
    pub exceptions: BTreeMap<String, String>,
    pub alerts: Alerts,
    pub history: HistorySettings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            sudo: true,
            profile: None,
            disabled: Vec::new(),
            enabled: Vec::new(),
            thresholds: Thresholds::default(),
            exceptions: BTreeMap::new(),
            alerts: Alerts::default(),
            history: HistorySettings::default(),
        }
    }
}

impl Config {
    /// Whether a check should run at all.
    pub fn runs(&self, id: &str) -> bool {
        if self.disabled.iter().any(|d| d == id) {
            return false;
        }
        self.enabled.is_empty() || self.enabled.iter().any(|e| e == id)
    }

    /// The accepted-risk note for a check, if any.
    pub fn exception(&self, id: &str) -> Option<&str> {
        self.exceptions.get(id).map(String::as_str)
    }

    /// Build a config from a parsed document, layering the selected profile on
    /// top of the base settings.
    pub fn from_document(doc: &Document, profile_override: Option<&str>) -> Self {
        let mut config = Config::default();
        config.apply_scope(doc, "");

        let profile = profile_override
            .map(str::to_string)
            .or_else(|| config.profile.clone());

        if let Some(name) = &profile {
            config.apply_scope(doc, &format!("profiles.{name}."));
            config.profile = Some(name.clone());
        }
        config
    }

    /// Read the keys for one scope. The base scope uses the plain section
    /// names; a profile scope prefixes them (`profiles.travel.checks`).
    fn apply_scope(&mut self, doc: &Document, prefix: &str) {
        let general = if prefix.is_empty() {
            "general".to_string()
        } else {
            prefix.trim_end_matches('.').to_string()
        };

        if let Some(v) = doc.get(&general, "interval").and_then(Value::as_int) {
            self.interval = Duration::from_secs(v.max(0) as u64).clamp(MIN_INTERVAL, MAX_INTERVAL);
        }
        if let Some(v) = doc.get(&general, "sudo").and_then(Value::as_bool) {
            self.sudo = v;
        }
        if prefix.is_empty()
            && let Some(v) = doc.get(&general, "profile").and_then(Value::as_str)
        {
            self.profile = Some(v.to_string());
        }

        let checks = format!("{prefix}checks");
        if let Some(v) = doc.get(&checks, "disabled").and_then(Value::as_list) {
            self.disabled = v.to_vec();
        }
        if let Some(v) = doc.get(&checks, "enabled").and_then(Value::as_list) {
            self.enabled = v.to_vec();
        }

        let thresholds = format!("{prefix}thresholds");
        let set = |key: &str, target: &mut usize| {
            if let Some(v) = doc.get(&thresholds, key).and_then(Value::as_int) {
                *target = v.max(0) as usize;
            }
        };
        set(
            "failed_logins_warn_above",
            &mut self.thresholds.failed_logins_warn_above,
        );
        set(
            "failed_logins_fail_above",
            &mut self.thresholds.failed_logins_fail_above,
        );
        set(
            "listening_warn_above",
            &mut self.thresholds.listening_warn_above,
        );
        set(
            "listening_fail_above",
            &mut self.thresholds.listening_fail_above,
        );

        if let Some(section) = doc.section(&format!("{prefix}exceptions")) {
            for (id, value) in section {
                if let Some(reason) = value.as_str() {
                    self.exceptions.insert(id.clone(), reason.to_string());
                }
            }
        }

        let alerts = format!("{prefix}alerts");
        if let Some(v) = doc.get(&alerts, "enabled").and_then(Value::as_bool) {
            self.alerts.enabled = v;
        }
        if let Some(v) = doc.get(&alerts, "command").and_then(Value::as_str) {
            self.alerts.command = v.to_string();
        }
        if let Some(v) = doc.get(&alerts, "on").and_then(Value::as_str) {
            self.alerts.on_any_problem = v.eq_ignore_ascii_case("any-problem");
        }

        let history = format!("{prefix}history");
        if let Some(v) = doc.get(&history, "enabled").and_then(Value::as_bool) {
            self.history.enabled = v;
        }
        if let Some(v) = doc.get(&history, "retain").and_then(Value::as_int) {
            self.history.retain = v.clamp(1, 100_000) as usize;
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

static ACTIVE: OnceLock<Config> = OnceLock::new();

/// Install the process-wide config. Checks read thresholds from here rather
/// than threading them through every signature.
pub fn install(config: Config) {
    let _ = ACTIVE.set(config);
}

/// The active config, or the defaults if none was installed.
pub fn current() -> &'static Config {
    static FALLBACK: OnceLock<Config> = OnceLock::new();
    ACTIVE
        .get()
        .unwrap_or_else(|| FALLBACK.get_or_init(Config::default))
}

pub fn thresholds() -> Thresholds {
    current().thresholds
}

/// `$XDG_CONFIG_HOME/opsec-dashboard/config.toml`, falling back to
/// `~/.config/...`.
pub fn default_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("opsec-dashboard").join("config.toml"))
}

/// Load a config file. A missing file is not an error — it means "defaults".
/// A malformed one is, because silently ignoring it would apply a posture the
/// user did not ask for.
pub fn load(path: Option<&PathBuf>, profile: Option<&str>) -> Result<Config, String> {
    let path = match path {
        Some(p) => p.clone(),
        None => match default_path() {
            Some(p) if p.exists() => p,
            _ => return Ok(Config::from_document(&Document::default(), profile)),
        },
    };

    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let doc = parse_document(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Config::from_document(&doc, profile))
}

/// A commented starter config, for `--write-config`.
pub const TEMPLATE: &str = r#"# opsec-dashboard configuration
# Every key is optional; what is not set here keeps its default.

[general]
interval = 5          # auto-refresh seconds (1-300)
sudo     = true       # allow `sudo -n` for nftables/usbguard
# profile = "travel"  # apply a [profiles.*] block on top of these settings

[checks]
# disabled = ["usbguard", "updates"]   # never run these
# enabled  = []                        # if non-empty, run ONLY these

[thresholds]
failed_logins_warn_above = 0   # any failed login warns
failed_logins_fail_above = 5   # more than five fails
listening_warn_above     = 0
listening_fail_above     = 2

[exceptions]
# An accepted risk keeps its real status on screen but stops driving alerts
# and the exit code. The reason is shown in the detail pane.
# listening-tcp = "5900 is VNC on the LAN, accepted"

[alerts]
enabled = false
# Placeholders: {id} {label} {status} {message} {previous}
command = "notify-send 'OPSEC: {label}' '{status} — {message}'"
on      = "regression"   # or "any-problem"

[history]
enabled = true
retain  = 500

# [profiles.travel]
# interval = 3
# [profiles.travel.checks]
# disabled = []
"#;
