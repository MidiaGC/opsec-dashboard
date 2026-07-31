//! Checks backed by system services: DNS, firewall, sshd, USBGuard.

use crate::checks::CheckResult;
use crate::exec;

/// `systemctl is-active` exits non-zero for every state that is not "active",
/// but the state itself is on stdout — so the exit code is deliberately
/// ignored here and only a genuinely unavailable `systemctl` yields "".
fn service_state(unit: &str) -> String {
    exec::run("systemctl", &["is-active", unit])
        .stdout()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// DNS / dnscrypt-proxy
// ---------------------------------------------------------------------------

const DNS_ID: &str = "dns";
const DNS_LABEL: &str = "DNS (dnscrypt)";

pub fn dns_status() -> CheckResult {
    let state = service_state("dnscrypt-proxy.service");
    let resolv = std::fs::read_to_string("/etc/resolv.conf").ok();
    parse_dns(&state, resolv.as_deref())
}

/// Backwards-compatible entry point: service state only, no resolver check.
pub fn parse_dnscrypt(active_state: &str) -> CheckResult {
    parse_dns(active_state, None)
}

/// Pure parser for the dnscrypt-proxy posture.
///
/// A running dnscrypt-proxy proves nothing on its own: if `/etc/resolv.conf`
/// points somewhere else, every query bypasses it. Both facts are needed.
pub fn parse_dns(active_state: &str, resolv_conf: Option<&str>) -> CheckResult {
    let state = active_state.trim();

    if state.is_empty() {
        return CheckResult::unknown(DNS_ID, DNS_LABEL, "systemctl unavailable");
    }
    if state != "active" {
        return CheckResult::fail(DNS_ID, DNS_LABEL, format!("service {state}"))
            .with_hint("DNS queries are currently leaving in the clear.")
            .with_fix("sudo systemctl enable --now dnscrypt-proxy");
    }

    let Some(resolv) = resolv_conf else {
        return CheckResult::pass(DNS_ID, DNS_LABEL, "service active");
    };

    let nameservers = resolv_nameservers(resolv);
    if nameservers.is_empty() {
        return CheckResult::warn(
            DNS_ID,
            DNS_LABEL,
            "service active, no nameserver in resolv.conf",
        )
        .with_hint("Point /etc/resolv.conf at 127.0.0.1 so queries reach dnscrypt-proxy.");
    }

    let bypassing: Vec<&str> = nameservers
        .iter()
        .copied()
        .filter(|ns| !is_loopback_addr(ns))
        .collect();

    if bypassing.is_empty() {
        CheckResult::pass(
            DNS_ID,
            DNS_LABEL,
            format!("service active, resolv.conf → {}", nameservers.join(", ")),
        )
    } else {
        CheckResult::warn(
            DNS_ID,
            DNS_LABEL,
            format!("service active but resolv.conf → {}", bypassing.join(", ")),
        )
        .with_hint("Queries are bypassing dnscrypt-proxy. Set `nameserver 127.0.0.1`.")
    }
}

/// Nameserver addresses declared in a resolv.conf, ignoring comments.
pub fn resolv_nameservers(resolv_conf: &str) -> Vec<&str> {
    resolv_conf
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| l.strip_prefix("nameserver"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_loopback_addr(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1"
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

const NFT_ID: &str = "nftables";
const NFT_LABEL: &str = "nftables";

pub fn nftables_status() -> CheckResult {
    let state = service_state("nftables.service");
    let ruleset = exec::run_privileged("nft", &["list", "ruleset"]);
    parse_nftables(&state, ruleset.success_stdout())
}

/// Pure parser: service state plus the ruleset (`None` when it could not be
/// read, which normally means root is required).
pub fn parse_nftables(service_state: &str, ruleset: Option<&str>) -> CheckResult {
    let state = service_state.trim();

    let Some(ruleset) = ruleset else {
        // Without the ruleset we cannot prove the firewall is broken, so this
        // degrades to a warning rather than a failure.
        let msg = if state.is_empty() {
            "service unknown, ruleset needs sudo".to_string()
        } else {
            format!("service {state}, ruleset needs sudo")
        };
        return CheckResult::warn(NFT_ID, NFT_LABEL, msg)
            .with_hint("Run the dashboard with sudo, or grant `nft list ruleset` via sudoers.");
    };

    if state != "active" {
        return CheckResult::fail(
            NFT_ID,
            NFT_LABEL,
            format!("service {state}, ruleset present"),
        )
        .with_hint("The loaded rules will not survive a reboot.")
        .with_fix("sudo systemctl enable --now nftables");
    }

    let rules = count_rules(ruleset);
    if rules == 0 {
        return CheckResult::fail(NFT_ID, NFT_LABEL, "service active, ruleset empty")
            .with_hint("An empty ruleset accepts everything. Load a base policy.");
    }

    if has_input_default_deny(ruleset) {
        CheckResult::pass(
            NFT_ID,
            NFT_LABEL,
            format!("{rules} rules, input policy drop"),
        )
    } else {
        CheckResult::warn(
            NFT_ID,
            NFT_LABEL,
            format!("{rules} rules, input policy not drop"),
        )
        .with_hint("Set `policy drop` on the input hook and allow only what you need.")
    }
}

/// Strip a `#` comment from a ruleset line.
fn uncomment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

/// Number of meaningful lines in a ruleset, excluding comments, blanks and
/// bare braces.
fn count_rules(ruleset: &str) -> usize {
    ruleset
        .lines()
        .map(uncomment)
        .filter(|l| !l.is_empty() && *l != "}" && *l != "{")
        .count()
}

/// Whether some chain attached to the **input** hook has `policy drop`.
///
/// Tracks chain context instead of matching "input" and "policy drop" anywhere
/// on the same line, so a `policy drop` on the output chain — or the words
/// appearing in a comment — cannot produce a false pass. The policy is
/// accepted either on the `type ... hook input ...` line itself (how `nft`
/// prints it) or on any later line of the same chain.
pub fn has_input_default_deny(ruleset: &str) -> bool {
    let mut depth = 0usize;
    let mut input_chain_depth: Option<usize> = None;

    for line in ruleset.lines() {
        let line = uncomment(line);
        if line.is_empty() {
            continue;
        }

        let is_input_hook = line.contains("hook input");
        let has_drop = line.contains("policy drop");

        if is_input_hook {
            input_chain_depth = Some(depth);
            if has_drop {
                return true;
            }
        } else if has_drop && input_chain_depth == Some(depth) {
            return true;
        }

        depth += line.matches('{').count();
        let closes = line.matches('}').count();
        depth = depth.saturating_sub(closes);

        if closes > 0 && input_chain_depth.is_some_and(|chain| depth < chain) {
            input_chain_depth = None;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// SSH daemon
// ---------------------------------------------------------------------------

const SSH_ID: &str = "ssh";
const SSH_LABEL: &str = "SSH daemon";

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_CONFIG_DIR: &str = "/etc/ssh/sshd_config.d";

pub fn ssh_hardening() -> CheckResult {
    // Arch names the unit sshd.service, Debian/Ubuntu ssh.service.
    let mut state = service_state("sshd.service");
    if state != "active" {
        let alt = service_state("ssh.service");
        if alt == "active" {
            state = alt;
        }
    }
    parse_ssh(&state, read_sshd_config().as_deref())
}

/// Concatenate the drop-in directory ahead of the main config, mirroring the
/// `Include /etc/ssh/sshd_config.d/*.conf` line distributions put at the top —
/// sshd honours the *first* value it sees for a keyword.
fn read_sshd_config() -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(SSHD_CONFIG_DIR) {
        let mut files: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "conf"))
            .collect();
        files.sort();
        for path in files {
            if let Ok(text) = std::fs::read_to_string(&path) {
                parts.push(text);
            }
        }
    }

    if let Ok(text) = std::fs::read_to_string(SSHD_CONFIG) {
        parts.push(text);
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// First effective value for an sshd keyword (case-insensitive), matching
/// sshd's "first obtained value wins" rule.
pub fn sshd_option<'a>(config: &'a str, keyword: &str) -> Option<&'a str> {
    config
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .find_map(|l| {
            let (key, value) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            key.eq_ignore_ascii_case(keyword)
                .then(|| value.trim_start_matches('=').trim())
                .filter(|v| !v.is_empty())
        })
}

/// Pure parser for the sshd posture.
///
/// When sshd is not running there is no remote surface to harden, so the check
/// passes — reporting a config problem for a daemon nobody can reach is noise.
pub fn parse_ssh(service_state: &str, config: Option<&str>) -> CheckResult {
    let state = service_state.trim();

    if state.is_empty() {
        return CheckResult::unknown(SSH_ID, SSH_LABEL, "systemctl unavailable");
    }
    if state != "active" {
        return CheckResult::pass(
            SSH_ID,
            SSH_LABEL,
            format!("sshd {state} (no remote surface)"),
        );
    }

    let Some(config) = config else {
        return CheckResult::warn(SSH_ID, SSH_LABEL, "running, sshd_config unreadable")
            .with_hint("Cannot verify root-login or password-auth policy without the config.");
    };

    // sshd's own defaults apply when a keyword is absent.
    let root_login = sshd_option(config, "PermitRootLogin").unwrap_or("prohibit-password");
    let password_auth = sshd_option(config, "PasswordAuthentication").unwrap_or("yes");

    let mut critical: Vec<String> = Vec::new();
    let mut advisory: Vec<String> = Vec::new();

    if root_login.eq_ignore_ascii_case("yes") {
        critical.push("PermitRootLogin yes".to_string());
    } else if !root_login.eq_ignore_ascii_case("no") {
        advisory.push(format!("PermitRootLogin {root_login}"));
    }

    if password_auth.eq_ignore_ascii_case("yes") {
        critical.push("PasswordAuthentication yes".to_string());
    }

    let hint = "Set `PermitRootLogin no` and `PasswordAuthentication no`, then use keys only.";

    if !critical.is_empty() {
        CheckResult::fail(
            SSH_ID,
            SSH_LABEL,
            format!("running — {}", critical.join(", ")),
        )
        .with_hint(hint)
    } else if !advisory.is_empty() {
        CheckResult::warn(
            SSH_ID,
            SSH_LABEL,
            format!("running — {}", advisory.join(", ")),
        )
        .with_hint(hint)
    } else {
        CheckResult::pass(SSH_ID, SSH_LABEL, "running, key-only, root login denied")
    }
}

// ---------------------------------------------------------------------------
// USBGuard
// ---------------------------------------------------------------------------

const USB_ID: &str = "usbguard";
const USB_LABEL: &str = "USBGuard";

pub fn usbguard() -> CheckResult {
    let state = service_state("usbguard.service");
    let devices = exec::run_privileged("usbguard", &["list-devices"]);
    parse_usbguard(&state, devices.success_stdout())
}

/// Tally of device authorisation targets reported by `usbguard list-devices`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceTally {
    pub allowed: usize,
    pub blocked: usize,
    pub other: usize,
}

/// Count devices by authorisation target.
///
/// Lines look like `10: allow id 8087:0032 serial "" name "" hash "…"`, and
/// crucially they are *not* all allowed — blocked and rejected devices appear
/// in the same listing.
pub fn tally_devices(list_output: &str) -> DeviceTally {
    let mut tally = DeviceTally::default();
    for line in list_output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip the `N:` index, then read the target.
        let target = line
            .split_once(':')
            .map(|(_, rest)| rest.trim())
            .unwrap_or(line)
            .split_whitespace()
            .next()
            .unwrap_or("");
        match target {
            "allow" => tally.allowed += 1,
            "block" | "reject" => tally.blocked += 1,
            _ => tally.other += 1,
        }
    }
    tally
}

/// Pure parser: service state plus optional IPC output (`None` when the daemon
/// could not be reached).
pub fn parse_usbguard(service_state: &str, ipc_output: Option<&str>) -> CheckResult {
    let state = service_state.trim();

    if state.is_empty() {
        return CheckResult::unknown(USB_ID, USB_LABEL, "systemctl unavailable");
    }
    if state != "active" {
        return CheckResult::fail(USB_ID, USB_LABEL, format!("service {state}"))
            .with_hint("USB devices are unrestricted.")
            .with_fix("sudo systemctl enable --now usbguard");
    }

    let Some(output) = ipc_output else {
        return CheckResult::warn(USB_ID, USB_LABEL, "active, IPC needs sudo").with_hint(
            "Add your user to the `usbguard` group to read the device list without sudo.",
        );
    };

    let tally = tally_devices(output);
    let mut msg = format!("active, {} allowed", tally.allowed);
    if tally.blocked > 0 {
        msg.push_str(&format!(", {} blocked", tally.blocked));
    }
    CheckResult::pass(USB_ID, USB_LABEL, msg)
}
