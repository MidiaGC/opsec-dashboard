//! Command-line parsing.
//!
//! Hand-rolled: the surface is eight flags, and a dashboard that inspects the
//! host's security posture is a poor place to add dependencies for convenience.

use std::time::Duration;

use std::path::PathBuf;

use crate::app::{MAX_INTERVAL, MIN_INTERVAL};

pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const USAGE: &str = "\
opsec-dashboard — live OPSEC health checks for a Linux host

USAGE:
    opsec-dashboard [OPTIONS]

OPTIONS:
    -1, --once            Run every check once, print a report, exit
        --json            Same as --once but emit JSON
    -i, --interval SECS   Auto-refresh interval (1-300, default 5)
    -o, --only SELECTOR   Restrict to checks by id or category, comma-separated
        --no-sudo         Never attempt `sudo -n` for privileged checks
    -c, --config PATH     Config file (default: $XDG_CONFIG_HOME/opsec-dashboard/config.toml)
    -p, --profile NAME    Apply a [profiles.NAME] block from the config
        --write-config    Print a commented starter config to stdout
    -l, --list            List available checks and exit
    -h, --help            Show this help
    -V, --version         Show version

EXIT CODES (--once / --json):
    0  everything passed
    1  warnings or undetermined checks
    2  at least one failure
";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Tui,
    Text,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    /// `None` means "whatever the config file says".
    pub interval: Option<Duration>,
    pub allow_sudo: bool,
    pub only: Vec<String>,
    pub config_path: Option<PathBuf>,
    pub profile: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Tui,
            interval: None,
            allow_sudo: true,
            only: Vec::new(),
            config_path: None,
            profile: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    Run(Config),
    Help,
    Version,
    List,
    WriteConfig,
    Error(String),
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Parsed {
    let mut config = Config::default();
    let mut args = args.into_iter().peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "-l" | "--list" => return Parsed::List,
            "--write-config" => return Parsed::WriteConfig,
            "-1" | "--once" => config.mode = Mode::Text,
            "--json" => config.mode = Mode::Json,
            "--no-sudo" => config.allow_sudo = false,
            "-i" | "--interval" => match args.next() {
                Some(value) => match parse_interval(&value) {
                    Ok(d) => config.interval = Some(d),
                    Err(e) => return Parsed::Error(e),
                },
                None => return Parsed::Error("--interval needs a value in seconds".into()),
            },
            "-c" | "--config" => match args.next() {
                Some(value) => config.config_path = Some(PathBuf::from(value)),
                None => return Parsed::Error("--config needs a path".into()),
            },
            "-p" | "--profile" => match args.next() {
                Some(value) => config.profile = Some(value),
                None => return Parsed::Error("--profile needs a name".into()),
            },
            "-o" | "--only" => match args.next() {
                Some(value) => config.only.extend(split_selectors(&value)),
                None => return Parsed::Error("--only needs a check id or category".into()),
            },
            other if other.starts_with("--interval=") => {
                match parse_interval(other.trim_start_matches("--interval=")) {
                    Ok(d) => config.interval = Some(d),
                    Err(e) => return Parsed::Error(e),
                }
            }
            other if other.starts_with("--config=") => {
                config.config_path = Some(PathBuf::from(other.trim_start_matches("--config=")));
            }
            other if other.starts_with("--profile=") => {
                config.profile = Some(other.trim_start_matches("--profile=").to_string());
            }
            other if other.starts_with("--only=") => {
                config
                    .only
                    .extend(split_selectors(other.trim_start_matches("--only=")));
            }
            other => {
                return Parsed::Error(format!("unrecognised argument: {other}"));
            }
        }
    }

    if let Err(unknown) = crate::checks::select(&config.only) {
        return Parsed::Error(format!(
            "unknown check or category: {}\nRun with --list to see the available ids.",
            unknown.join(", ")
        ));
    }

    Parsed::Run(config)
}

fn parse_interval(raw: &str) -> Result<Duration, String> {
    let secs: u64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("--interval expects whole seconds, got {raw:?}"))?;
    let duration = Duration::from_secs(secs);
    if duration < MIN_INTERVAL || duration > MAX_INTERVAL {
        return Err(format!(
            "--interval must be between {} and {} seconds",
            MIN_INTERVAL.as_secs(),
            MAX_INTERVAL.as_secs()
        ));
    }
    Ok(duration)
}

fn split_selectors(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The `--list` output.
pub fn render_list() -> String {
    let width = crate::checks::REGISTRY
        .iter()
        .map(|c| c.id.len())
        .max()
        .unwrap_or(0);
    let mut out = String::from("Available checks (use with --only):\n\n");
    for check in crate::checks::REGISTRY {
        out.push_str(&format!(
            "  {:<width$}  [{}] {}\n",
            check.id,
            check.category.as_str(),
            check.about
        ));
    }
    out.push_str("\nCategories: network, system, services, logs\n");
    out
}
