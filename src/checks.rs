use std::process::Command;

#[derive(Clone, Debug)]
pub enum Status {
    Pass(String),
    Warn(String),
    Fail(String),
    Unknown(String),
}

#[derive(Clone, Debug)]
pub struct CheckResult {
    pub label: String,
    pub status: Status,
}

/// VPN status: detects an active tun/wg/ppp/tailscale interface via `ip -o link`.
fn run_cmd(prog: &str, args: &[&str]) -> Option<String> {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Like `run_cmd` but returns stdout even on non-zero exit (e.g. `systemctl
/// is-active` exits 3 when inactive — the stdout still carries the state).
fn run_cmd_loose(prog: &str, args: &[&str]) -> Option<String> {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Like `run_cmd` but returns (stdout, stderr) so callers can distinguish
/// "succeeded with empty output" from "failed with empty output".
fn run_cmd_full(prog: &str, args: &[&str]) -> Option<(String, String, bool)> {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .map(|o| {
            (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.success(),
            )
        })
}

/// VPN status: detects an active tun/wg/ppp/tailscale interface via `ip -o link`.
/// No sudo required.
pub fn vpn_status() -> CheckResult {
    match run_cmd("ip", &["-o", "link"]) {
        Some(out) => parse_vpn(&out),
        None => CheckResult {
            label: "VPN".into(),
            status: Status::Unknown("ip command failed".into()),
        },
    }
}

/// Pure parser for `ip -o link` output. Detects VPN interfaces by name prefix.
pub fn parse_vpn(ip_output: &str) -> CheckResult {
    for line in ip_output.lines() {
        let lower = line.to_ascii_lowercase();
        for prefix in ["tun", "tap", "wg", "ppp", "pppoe", "ipsec", "tailscale"] {
            if interface_starts_with(&lower, prefix) {
                let name = line
                    .split(':')
                    .nth(1)
                    .map(|s| s.trim().split('@').next().unwrap_or("").trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| prefix.into());
                return CheckResult {
                    label: "VPN".into(),
                    status: Status::Pass(format!("ACTIVE: {name}")),
                };
            }
        }
    }
    CheckResult {
        label: "VPN".into(),
        status: Status::Fail("no VPN interface".into()),
    }
}

/// Checks if the interface name in an `ip -o link` line matches a VPN prefix.
/// Format: `N: name: <FLAGS> ...`. Real VPN interfaces follow the convention
/// `<prefix><digits>` (tun0, wg0, tailscale0). Rejects `tunnelup` matching `tun`.
fn interface_starts_with(lowered_line: &str, prefix: &str) -> bool {
    let after_idx = match lowered_line.find(':') {
        Some(i) => i + 1,
        None => return false,
    };
    let rest = &lowered_line[after_idx..];
    let name = rest.trim_start().split(':').next().unwrap_or("").trim();
    let name = name.split('@').next().unwrap_or(name);
    let after_prefix = match name.strip_prefix(prefix) {
        Some(s) => s,
        None => return false,
    };
    // First char after prefix must be a digit (tun0, wg0, tailscale0, pppoe0).
    // Real VPN interfaces are always numbered; bare "tun" or "tunnelup" don't match.
    after_prefix.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// dnscrypt-proxy status: service active + listening on a local port.
/// No sudo required (systemctl is-active + ss work as normal user).
pub fn dnscrypt_status() -> CheckResult {
    let active = run_cmd_loose("systemctl", &["is-active", "dnscrypt-proxy.service"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    parse_dnscrypt(&active)
}

/// Pure parser for `systemctl is-active` output.
pub fn parse_dnscrypt(active_state: &str) -> CheckResult {
    let active = active_state.trim();
    if active == "active" {
        CheckResult {
            label: "dnscrypt-proxy".into(),
            status: Status::Pass("service active".into()),
        }
    } else if active.is_empty() {
        CheckResult {
            label: "dnscrypt-proxy".into(),
            status: Status::Unknown("systemctl unavailable".into()),
        }
    } else {
        CheckResult {
            label: "dnscrypt-proxy".into(),
            status: Status::Fail(format!("service {active}")),
        }
    }
}

/// MAC randomization: for each non-loopback interface with a `permaddr`,
/// compare current `link/ether` against the permanent MAC.
/// No sudo required.
pub fn mac_randomization() -> CheckResult {
    match run_cmd("ip", &["-o", "link"]) {
        Some(out) => parse_mac(&out),
        None => CheckResult {
            label: "MAC randomization".into(),
            status: Status::Unknown("ip command failed".into()),
        },
    }
}

/// Pure parser for `ip -o link` output. Compares link/ether vs permaddr.
pub fn parse_mac(ip_output: &str) -> CheckResult {
    let mut randomized: Vec<String> = Vec::new();
    let mut exposed: Vec<String> = Vec::new();

    for line in ip_output.lines() {
        if line.to_ascii_lowercase().contains(" lo:") {
            continue;
        }

        let name = line
            .split(':')
            .nth(1)
            .map(|s| s.trim().split('@').next().unwrap_or("").trim().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        let current = extract_field(line, "link/ether");
        let permanent = extract_field(line, "permaddr");

        match (current.as_deref(), permanent.as_deref()) {
            (Some(c), Some(p)) if c != p => randomized.push(format!("{name}: {c} ≠ {p}")),
            (Some(c), Some(p)) if c == p => exposed.push(name.clone()),
            _ => {}
        }
    }

    if !randomized.is_empty() {
        CheckResult {
            label: "MAC randomization".into(),
            status: Status::Pass(randomized.join("  ")),
        }
    } else if !exposed.is_empty() {
        CheckResult {
            label: "MAC randomization".into(),
            status: Status::Fail(format!("exposed: {}", exposed.join(", "))),
        }
    } else {
        CheckResult {
            label: "MAC randomization".into(),
            status: Status::Warn("no interfaces with permaddr".into()),
        }
    }
}

pub fn extract_field(line: &str, field: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == field {
            return tokens.next().map(|s| s.to_string());
        }
    }
    None
}

/// Secure Boot state via `bootctl status`. No sudo required.
/// Pass = enabled, Fail = disabled, Warn = setup mode (can be changed).
pub fn secure_boot() -> CheckResult {
    match run_cmd_loose("bootctl", &["status"]) {
        Some(out) => parse_secure_boot(&out),
        None => CheckResult {
            label: "Secure Boot".into(),
            status: Status::Unknown("bootctl unavailable".into()),
        },
    }
}

/// Pure parser for `bootctl status` output.
pub fn parse_secure_boot(bootctl_output: &str) -> CheckResult {
    let enabled = bootctl_output
        .lines()
        .find(|l| l.to_ascii_lowercase().contains("secure boot:"))
        .map(|l| l.to_ascii_lowercase())
        .unwrap_or_default();

    if enabled.contains("enabled") {
        CheckResult {
            label: "Secure Boot".into(),
            status: Status::Pass("enabled".into()),
        }
    } else if enabled.contains("disabled") {
        CheckResult {
            label: "Secure Boot".into(),
            status: Status::Fail("disabled".into()),
        }
    } else if enabled.contains("setup") {
        CheckResult {
            label: "Secure Boot".into(),
            status: Status::Warn("setup mode (not enforced)".into()),
        }
    } else {
        CheckResult {
            label: "Secure Boot".into(),
            status: Status::Unknown("could not parse bootctl output".into()),
        }
    }
}

/// USBGuard status: service active. Device list requires IPC access (root or
/// usbguard group), so we degrade to Warn if we can't reach the daemon.
pub fn usbguard() -> CheckResult {
    let state = run_cmd_loose("systemctl", &["is-active", "usbguard.service"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let ipc = run_cmd_full("usbguard", &["list-devices"])
        .or_else(|| run_cmd_full("sudo", &["-n", "usbguard", "list-devices"]));

    let ipc_out = ipc.and_then(|(out, _err, ok)| if ok { Some(out) } else { None });

    parse_usbguard(&state, ipc_out.as_deref())
}

/// Pure parser: takes service state + optional IPC output (None = needs sudo).
pub fn parse_usbguard(service_state: &str, ipc_output: Option<&str>) -> CheckResult {
    let state = service_state.trim();
    if state.is_empty() {
        return CheckResult {
            label: "USBGuard".into(),
            status: Status::Unknown("systemctl unavailable".into()),
        };
    }
    if state != "active" {
        return CheckResult {
            label: "USBGuard".into(),
            status: Status::Fail(format!("service {state}")),
        };
    }
    match ipc_output {
        Some(out) => {
            let count = out.lines().filter(|l| !l.is_empty()).count();
            CheckResult {
                label: "USBGuard".into(),
                status: Status::Pass(format!("active, {count} devices allowed")),
            }
        }
        None => CheckResult {
            label: "USBGuard".into(),
            status: Status::Warn("active, IPC needs sudo".into()),
        },
    }
}

/// Classification of a single `ss` listener line.
#[derive(Debug, PartialEq, Eq)]
pub enum ListenerKind {
    /// Bound to wildcard (0.0.0.0 / [::]) — exposed to all interfaces.
    Exposed(String),
    /// Loopback or interface-bound — not externally reachable.
    Local,
    /// Could not parse.
    Unknown,
}

/// Pure classifier for a single `ss -tlnH` line's local-address field.
/// Extracted so it can be unit-tested without shelling out to `ss`.
pub fn classify_listener(local: &str) -> ListenerKind {
    let is_wildcard = local.starts_with("0.0.0.0:") || local.starts_with("[::]:");
    if is_wildcard {
        let port = local.rsplit(':').next().unwrap_or("?");
        return ListenerKind::Exposed(port.to_string());
    }
    ListenerKind::Local
}

/// Listening TCP services via `ss -tlnH`. Counts wildcard-bound listeners
/// (0.0.0.0 / [::]) as exposed attack surface. No sudo required.
/// Pass = 0, Warn = 1-2, Fail = >2.
pub fn listening_services() -> CheckResult {
    match run_cmd_loose("ss", &["-tlnH"]) {
        Some(out) => parse_listening(&out),
        None => CheckResult {
            label: "Listening (TCP)".into(),
            status: Status::Unknown("ss unavailable".into()),
        },
    }
}

/// Pure parser for `ss -tlnH` output. Dedups IPv4+IPv6 bindings of same port.
pub fn parse_listening(ss_output: &str) -> CheckResult {
    let mut exposed: Vec<String> = Vec::new();

    for line in ss_output.lines() {
        let local = line.split_whitespace().nth(3).unwrap_or("");
        if let ListenerKind::Exposed(port) = classify_listener(local) {
            if !exposed.contains(&port) {
                exposed.push(port);
            }
        }
    }

    let count = exposed.len();
    let status = match count {
        0 => Status::Pass("no wildcard listeners".into()),
        1 | 2 => Status::Warn(format!("exposed: {}", exposed.join(", "))),
        _ => Status::Fail(format!("{} exposed: {}", count, exposed.join(", "))),
    };

    CheckResult {
        label: "Listening (TCP)".into(),
        status,
    }
}

/// AppArmor enforcement state via /sys/module/apparmor/parameters/enabled.
/// Pure file read, no sudo. Pass = enabled, Fail = disabled, Unknown = not present.
pub fn apparmor() -> CheckResult {
    let contents = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .ok()
        .map(|s| s.trim().to_string());
    parse_apparmor(contents.as_deref())
}

/// Pure parser for the contents of the apparmor `enabled` parameter file.
pub fn parse_apparmor(file_contents: Option<&str>) -> CheckResult {
    match file_contents.map(|s| s.trim()) {
        Some("Y") => CheckResult {
            label: "AppArmor".into(),
            status: Status::Pass("enabled".into()),
        },
        Some("N") => CheckResult {
            label: "AppArmor".into(),
            status: Status::Fail("disabled".into()),
        },
        None => CheckResult {
            label: "AppArmor".into(),
            status: Status::Unknown("module not loaded".into()),
        },
        Some(other) => CheckResult {
            label: "AppArmor".into(),
            status: Status::Unknown(format!("state: {other}")),
        },
    }
}

/// Failed login attempts in the last 24h via `journalctl --grep`.
/// Works as normal user on Arch (journald grants read access to per-user
/// messages and PAM logind events). Threshold: 0 = pass, <=5 = warn, >5 = fail.
pub fn failed_logins() -> CheckResult {
    match run_cmd(
        "journalctl",
        &["--since", "24h ago", "--grep", "authentication failure|invalid user|Failed password", "--no-pager"],
    ) {
        Some(out) => parse_failed_logins(&out),
        None => CheckResult {
            label: "Failed logins (24h)".into(),
            status: Status::Unknown("journalctl unavailable".into()),
        },
    }
}

/// Pure parser for journalctl --grep output.
/// Filters boot-separator lines (`-- Boot ...`) and empty lines.
pub fn parse_failed_logins(journal_output: &str) -> CheckResult {
    let count = journal_output
        .lines()
        .filter(|l| !l.starts_with("-- ") && !l.is_empty())
        .count();

    let status = match count {
        0 => Status::Pass("0 attempts".into()),
        n if n <= 5 => Status::Warn(format!("{n} attempts")),
        n => Status::Fail(format!("{n} attempts")),
    };

    CheckResult {
        label: "Failed logins (24h)".into(),
        status,
    }
}

/// nftables status: service active + ruleset non-empty + default-deny on input.
/// `nft list ruleset` requires root; we try direct first, then `sudo -n` (no
/// password prompt). If neither works, we report what we can from systemctl
/// alone and degrade to Warn.
pub fn nftables_status() -> CheckResult {
    let service_state = run_cmd_loose("systemctl", &["is-active", "nftables.service"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let ruleset = run_cmd("nft", &["list", "ruleset"])
        .or_else(|| run_cmd("sudo", &["-n", "nft", "list", "ruleset"]));

    parse_nftables(&service_state, ruleset.as_deref())
}

/// Pure parser: takes service state + optional ruleset (None = needs sudo).
pub fn parse_nftables(service_state: &str, ruleset: Option<&str>) -> CheckResult {
    let label = "nftables";
    let state = service_state.trim();

    let ruleset = match ruleset {
        Some(r) => r,
        None => {
            let msg = if state == "active" {
                "service active, ruleset needs sudo".to_string()
            } else if state.is_empty() {
                "service unknown, ruleset needs sudo".to_string()
            } else {
                format!("service {state}, ruleset needs sudo")
            };
            return CheckResult {
                label: label.into(),
                status: Status::Warn(msg),
            };
        }
    };

    if state != "active" {
        return CheckResult {
            label: label.into(),
            status: Status::Fail(format!("service {state}, ruleset present")),
        };
    }

    let non_empty: Vec<&str> = ruleset
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if non_empty.is_empty() {
        return CheckResult {
            label: label.into(),
            status: Status::Fail("service active, ruleset empty".into()),
        };
    }

    let has_default_deny = ruleset
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#'))
        .any(|l| l.contains("policy drop") && l.contains("input"));

    let count = non_empty.len();
    let status = if has_default_deny {
        Status::Pass(format!("{count} rules, input policy drop"))
    } else {
        Status::Warn(format!("{count} rules, input policy not drop"))
    };

    CheckResult {
        label: label.into(),
        status,
    }
}
