//! The check catalogue.
//!
//! Every check is split in two halves:
//!
//! * an **orchestrator** (`vpn_status`, `nftables_status`, …) that gathers raw
//!   material from the system, and
//! * a **pure interpreter** (`parse_vpn`, `parse_nftables`, …) that turns that
//!   material into a [`CheckResult`].
//!
//! Interpreters take plain `&str` / [`Outcome`] inputs and never touch the
//! system, which is what makes the whole security surface unit-testable.

pub mod logs;
pub mod network;
pub mod privacy;
pub mod services;
pub mod system;

pub use logs::*;
pub use network::*;
pub use privacy::*;
pub use services::*;
pub use system::*;

/// How bad a result is. Ordered from best to worst so `max()` yields the
/// overall posture of the machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Pass,
    /// We could not determine the state — not proof of safety.
    Unknown,
    Warn,
    Fail,
}

impl Severity {
    /// Short fixed-width tag rendered in the TUI and in `--once` output.
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
            Severity::Unknown => "????",
        }
    }

    /// Lowercase machine-readable name used by `--json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Pass => "pass",
            Severity::Warn => "warn",
            Severity::Fail => "fail",
            Severity::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Pass(String),
    Warn(String),
    Fail(String),
    Unknown(String),
}

impl Status {
    pub fn severity(&self) -> Severity {
        match self {
            Status::Pass(_) => Severity::Pass,
            Status::Warn(_) => Severity::Warn,
            Status::Fail(_) => Severity::Fail,
            Status::Unknown(_) => Severity::Unknown,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Status::Pass(m) | Status::Warn(m) | Status::Fail(m) | Status::Unknown(m) => m,
        }
    }
}

/// Broad grouping, used for the category column and for `--only net` style
/// filtering.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Category {
    Network,
    System,
    Services,
    Logs,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Network => "network",
            Category::System => "system",
            Category::Services => "services",
            Category::Logs => "logs",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    /// Stable identifier — used by `--only`, by the JSON output and to route
    /// async results back to their row. Never localised, never renamed.
    pub id: &'static str,
    pub label: String,
    pub status: Status,
    /// Remediation advice, shown in the detail pane. Only meaningful for
    /// non-passing results.
    pub hint: Option<String>,
    /// The shell command that would fix this, if one can be stated exactly.
    /// Offered to the user for confirmation; never run on its own.
    pub fix: Option<String>,
    /// Why this result is an accepted risk, from `[exceptions]`. The status is
    /// still shown as-is; what changes is that it stops driving alerts and the
    /// exit code.
    pub accepted: Option<String>,
}

impl CheckResult {
    pub fn new(id: &'static str, label: impl Into<String>, status: Status) -> Self {
        Self {
            id,
            label: label.into(),
            status,
            hint: None,
            fix: None,
            accepted: None,
        }
    }

    pub fn pass(id: &'static str, label: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(id, label, Status::Pass(msg.into()))
    }

    pub fn warn(id: &'static str, label: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(id, label, Status::Warn(msg.into()))
    }

    pub fn fail(id: &'static str, label: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(id, label, Status::Fail(msg.into()))
    }

    pub fn unknown(id: &'static str, label: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(id, label, Status::Unknown(msg.into()))
    }

    /// Attach remediation advice, but only when the result is not a pass —
    /// telling someone how to fix something that is already correct is noise.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        if self.severity() != Severity::Pass {
            self.hint = Some(hint.into());
        }
        self
    }

    /// Attach the exact command that fixes this, for the confirm-then-run flow.
    /// Like [`CheckResult::with_hint`], a pass has nothing to fix.
    pub fn with_fix(mut self, command: impl Into<String>) -> Self {
        if self.severity() != Severity::Pass {
            self.fix = Some(command.into());
        }
        self
    }

    /// Mark this result as an accepted risk.
    pub fn accept(mut self, reason: impl Into<String>) -> Self {
        self.accepted = Some(reason.into());
        self
    }

    /// The severity as measured.
    pub fn severity(&self) -> Severity {
        self.status.severity()
    }

    /// The severity as it counts towards alerts, the exit code and the overall
    /// posture. An accepted risk is still displayed at its real severity — it
    /// simply stops raising the alarm.
    pub fn effective_severity(&self) -> Severity {
        if self.accepted.is_some() {
            Severity::Pass
        } else {
            self.severity()
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.accepted.is_some()
    }

    pub fn message(&self) -> &str {
        self.status.message()
    }
}

/// A registered check: static metadata plus the function that performs it.
///
/// Adding a check is one entry in [`REGISTRY`] plus one function — nothing else
/// in the app needs to know about it.
pub struct Check {
    pub id: &'static str,
    pub label: &'static str,
    pub category: Category,
    /// What the check inspects, shown in the help overlay and the detail pane.
    pub about: &'static str,
    pub run: fn() -> CheckResult,
}

pub static REGISTRY: &[Check] = &[
    Check {
        id: "vpn",
        label: "VPN",
        category: Category::Network,
        about: "Looks for an up tun/tap/wg/ipsec/tailscale interface in `ip -o link`.",
        run: vpn_status,
    },
    Check {
        id: "dns",
        label: "DNS (dnscrypt)",
        category: Category::Services,
        about: "dnscrypt-proxy service state, cross-checked against /etc/resolv.conf.",
        run: dns_status,
    },
    Check {
        id: "mac",
        label: "MAC randomization",
        category: Category::Network,
        about: "Compares each interface's current link/ether against its permaddr.",
        run: mac_randomization,
    },
    Check {
        id: "nftables",
        label: "nftables",
        category: Category::Services,
        about: "Service state plus a default-deny policy on the input hook.",
        run: nftables_status,
    },
    Check {
        id: "listening-tcp",
        label: "Listening (TCP)",
        category: Category::Network,
        about: "Wildcard-bound TCP sockets from `ss -tlnH` — externally reachable surface.",
        run: listening_tcp,
    },
    Check {
        id: "listening-udp",
        label: "Listening (UDP)",
        category: Category::Network,
        about: "Wildcard-bound UDP sockets from `ss -ulnH`.",
        run: listening_udp,
    },
    Check {
        id: "failed-logins",
        label: "Failed logins (24h)",
        category: Category::Logs,
        about: "Authentication failures in the journal over the last 24 hours.",
        run: failed_logins,
    },
    Check {
        id: "secure-boot",
        label: "Secure Boot",
        category: Category::System,
        about: "UEFI Secure Boot enforcement state via `bootctl status`.",
        run: secure_boot,
    },
    Check {
        id: "apparmor",
        label: "AppArmor / LSM",
        category: Category::System,
        about: "Mandatory access control: AppArmor parameter, falling back to the active LSM list.",
        run: apparmor,
    },
    Check {
        id: "disk-encryption",
        label: "Disk encryption",
        category: Category::System,
        about: "Whether / sits on a dm-crypt (LUKS) device, per `lsblk`.",
        run: disk_encryption,
    },
    Check {
        id: "kernel-hardening",
        label: "Kernel hardening",
        category: Category::System,
        about: "A baseline of hardening sysctls under /proc/sys.",
        run: kernel_hardening,
    },
    Check {
        id: "ssh",
        label: "SSH daemon",
        category: Category::Services,
        about: "If sshd is running: root login and password authentication policy.",
        run: ssh_hardening,
    },
    Check {
        id: "usbguard",
        label: "USBGuard",
        category: Category::Services,
        about: "USBGuard service state and the number of authorised devices.",
        run: usbguard,
    },
    Check {
        id: "ipv6-leak",
        label: "IPv6 leak",
        category: Category::Network,
        about: "With a tunnel up: whether the IPv6 default route still leaves outside it.",
        run: ipv6_leak,
    },
    Check {
        id: "kill-switch",
        label: "VPN kill switch",
        category: Category::Network,
        about: "Whether the firewall blocks egress if the tunnel drops.",
        run: kill_switch,
    },
    Check {
        id: "swap",
        label: "Swap encryption",
        category: Category::System,
        about: "Whether swap devices are in RAM or on an encrypted volume.",
        run: swap_encryption,
    },
    Check {
        id: "core-dumps",
        label: "Core dumps",
        category: Category::System,
        about: "Whether a crash can write process memory — keys included — to disk.",
        run: core_dumps,
    },
    Check {
        id: "time-sync",
        label: "Time sync",
        category: Category::System,
        about: "NTP synchronisation; a drifted clock breaks certificate validation.",
        run: time_sync,
    },
    Check {
        id: "bluetooth",
        label: "Bluetooth",
        category: Category::Services,
        about: "Whether the Bluetooth radio is powered and whether anything uses it.",
        run: bluetooth,
    },
    Check {
        id: "updates",
        label: "Pending updates",
        category: Category::System,
        about: "Packages behind the last database sync, via `pacman -Qu`.",
        run: pending_updates,
    },
];

/// Look up a check by id.
pub fn find(id: &str) -> Option<&'static Check> {
    REGISTRY.iter().find(|c| c.id == id)
}

/// Resolve a list of selectors (check ids or category names) into checks,
/// preserving registry order. Returns the unrecognised selectors on error.
pub fn select(selectors: &[String]) -> Result<Vec<&'static Check>, Vec<String>> {
    if selectors.is_empty() {
        return Ok(REGISTRY.iter().collect());
    }

    let unknown: Vec<String> = selectors
        .iter()
        .filter(|s| {
            !REGISTRY
                .iter()
                .any(|c| c.id == s.as_str() || c.category.as_str() == s.as_str())
        })
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(unknown);
    }

    Ok(REGISTRY
        .iter()
        .filter(|c| {
            selectors
                .iter()
                .any(|s| c.id == s.as_str() || c.category.as_str() == s.as_str())
        })
        .collect())
}

/// Run one check and apply any configured exception to its result.
///
/// This is the single point where a check's raw verdict becomes the verdict the
/// rest of the app sees, so an accepted risk cannot be forgotten on one path and
/// honoured on another.
pub fn run_one(check: &'static Check) -> CheckResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(check.run))
        .unwrap_or_else(|_| CheckResult::unknown(check.id, check.label, "check panicked"));

    match crate::config::current().exception(check.id) {
        Some(reason) if result.severity() != Severity::Pass => result.accept(reason),
        _ => result,
    }
}

/// Run the given checks concurrently and return their results in the same
/// order. Used by the headless (`--once` / `--json`) modes.
pub fn run_all(checks: &[&'static Check]) -> Vec<CheckResult> {
    let handles: Vec<_> = checks
        .iter()
        .map(|check| {
            let check: &'static Check = check;
            std::thread::spawn(move || run_one(check))
        })
        .collect();

    handles
        .into_iter()
        .zip(checks)
        .map(|(handle, check)| {
            handle
                .join()
                .unwrap_or_else(|_| CheckResult::unknown(check.id, check.label, "check panicked"))
        })
        .collect()
}

/// The worst severity across a set of results — the machine's overall posture.
/// Accepted risks do not count.
pub fn worst(results: &[CheckResult]) -> Severity {
    results
        .iter()
        .map(CheckResult::effective_severity)
        .max()
        .unwrap_or(Severity::Pass)
}
