//! Checks that only make sense in relation to something else: leaks around an
//! active tunnel, data at rest outside the encrypted volume, and surface that
//! is on purely because nobody turned it off.

use crate::checks::network::{is_vpn_interface, parse_ip_link_line};
use crate::checks::{CheckResult, Status};
use crate::exec::{self, Outcome};

// ---------------------------------------------------------------------------
// IPv6 leak
// ---------------------------------------------------------------------------

const V6_ID: &str = "ipv6-leak";
const V6_LABEL: &str = "IPv6 leak";

pub fn ipv6_leak() -> CheckResult {
    let links = exec::run("ip", &["-o", "link"]);
    let routes = exec::run("ip", &["-6", "route", "show", "default"]);
    let disabled = exec::read_trimmed("/proc/sys/net/ipv6/conf/all/disable_ipv6");

    parse_ipv6_leak(
        links.success_stdout().unwrap_or(""),
        routes.success_stdout(),
        disabled.as_deref(),
    )
}

/// Pure parser: are there IPv6 default routes that leave outside the tunnel?
///
/// This is the classic VPN leak. A tunnel that only carries IPv4 while the host
/// still has a working IPv6 default route through the physical interface will
/// happily send IPv6 traffic straight to the ISP, and every other check will
/// keep reporting the VPN as up.
pub fn parse_ipv6_leak(
    ip_link_output: &str,
    v6_default_routes: Option<&str>,
    disable_ipv6: Option<&str>,
) -> CheckResult {
    let vpn_up = ip_link_output.lines().any(|line| {
        parse_ip_link_line(line).is_some_and(|l| is_vpn_interface(&l.name) && l.is_up())
    });

    if disable_ipv6.map(str::trim) == Some("1") {
        return CheckResult::pass(V6_ID, V6_LABEL, "IPv6 disabled system-wide");
    }

    let Some(routes) = v6_default_routes else {
        return CheckResult::unknown(V6_ID, V6_LABEL, "could not read IPv6 routes");
    };

    let outside: Vec<String> = routes
        .lines()
        .filter_map(route_device)
        .filter(|device| !is_vpn_interface(device))
        .collect();

    if !vpn_up {
        // No tunnel means nothing to leak *out of*; IPv6 going to the ISP is
        // simply how the machine is connected.
        return CheckResult::pass(V6_ID, V6_LABEL, "no tunnel active, nothing to leak");
    }

    if outside.is_empty() {
        CheckResult::pass(V6_ID, V6_LABEL, "IPv6 default route inside the tunnel")
    } else {
        CheckResult::fail(
            V6_ID,
            V6_LABEL,
            format!(
                "VPN up but IPv6 default route via {}",
                dedup(outside).join(", ")
            ),
        )
        .with_hint(
            "IPv6 traffic is bypassing the tunnel. Disable IPv6 or route it through the VPN.",
        )
        .with_fix("sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    }
}

/// The `dev <name>` of an `ip route` line.
fn route_device(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_string);
        }
    }
    None
}

fn dedup(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

const KILL_ID: &str = "kill-switch";
const KILL_LABEL: &str = "VPN kill switch";

pub fn kill_switch() -> CheckResult {
    let links = exec::run("ip", &["-o", "link"]);
    let ruleset = exec::run_privileged("nft", &["list", "ruleset"]);
    parse_kill_switch(
        links.success_stdout().unwrap_or(""),
        ruleset.success_stdout(),
    )
}

/// Pure parser: does the firewall stop traffic if the tunnel drops?
///
/// Two accepted shapes, both of which survive the tunnel going away:
/// an output chain with `policy drop`, or an explicit rule dropping traffic
/// leaving on anything other than the tunnel interface.
pub fn parse_kill_switch(ip_link_output: &str, ruleset: Option<&str>) -> CheckResult {
    let vpn_up = ip_link_output.lines().any(|line| {
        parse_ip_link_line(line).is_some_and(|l| is_vpn_interface(&l.name) && l.is_up())
    });

    let Some(ruleset) = ruleset else {
        return CheckResult::warn(KILL_ID, KILL_LABEL, "ruleset needs sudo")
            .with_hint("Cannot verify egress protection without reading the nftables ruleset.");
    };

    if has_output_default_deny(ruleset) {
        return CheckResult::pass(KILL_ID, KILL_LABEL, "output policy drop");
    }
    if let Some(rule) = explicit_egress_block(ruleset) {
        return CheckResult::pass(KILL_ID, KILL_LABEL, format!("egress restricted: {rule}"));
    }

    let message = "no egress restriction — traffic escapes if the tunnel drops";
    let hint = "Add `oifname != \"<tunnel>\" drop` to the output chain, or set its policy to drop.";

    // Without a tunnel there is nothing being protected yet, so this is advice
    // rather than an active failure.
    if vpn_up {
        CheckResult::fail(KILL_ID, KILL_LABEL, message).with_hint(hint)
    } else {
        CheckResult::warn(KILL_ID, KILL_LABEL, format!("{message} (no tunnel up)")).with_hint(hint)
    }
}

fn uncomment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

/// A chain on the output hook whose policy is drop.
pub fn has_output_default_deny(ruleset: &str) -> bool {
    ruleset
        .lines()
        .map(uncomment)
        .any(|l| l.contains("hook output") && l.contains("policy drop"))
}

/// A rule that drops or rejects traffic leaving on a non-tunnel interface.
pub fn explicit_egress_block(ruleset: &str) -> Option<String> {
    ruleset
        .lines()
        .map(uncomment)
        .find(|l| {
            l.contains("oifname")
                && l.contains("!=")
                && (l.contains("drop") || l.contains("reject"))
        })
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Swap
// ---------------------------------------------------------------------------

const SWAP_ID: &str = "swap";
const SWAP_LABEL: &str = "Swap encryption";

pub fn swap_encryption() -> CheckResult {
    let swaps = std::fs::read_to_string("/proc/swaps").ok();
    let lsblk = exec::run("lsblk", &["-rno", "NAME,TYPE"]);
    parse_swap(swaps.as_deref(), lsblk.success_stdout())
}

/// Pure parser for `/proc/swaps` cross-referenced against `lsblk`.
///
/// Swap is where the kernel writes whatever was in RAM — keys, passphrases,
/// decrypted documents. On an unencrypted partition that survives a reboot and
/// is readable from any live USB.
pub fn parse_swap(proc_swaps: Option<&str>, lsblk_output: Option<&str>) -> CheckResult {
    let Some(swaps) = proc_swaps else {
        return CheckResult::unknown(SWAP_ID, SWAP_LABEL, "could not read /proc/swaps");
    };

    let crypt_devices: Vec<&str> = lsblk_output
        .unwrap_or("")
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            (fields.next()? == "crypt").then_some(name)
        })
        .collect();

    let mut protected: Vec<String> = Vec::new();
    let mut exposed: Vec<String> = Vec::new();

    // Skip the header line.
    for line in swaps.lines().skip(1) {
        let Some(device) = line.split_whitespace().next() else {
            continue;
        };
        if device.is_empty() {
            continue;
        }
        let name = device.rsplit('/').next().unwrap_or(device);

        // zram and zswap live in RAM and never touch the disk.
        let in_memory = name.starts_with("zram");
        let encrypted = crypt_devices.contains(&name) || name.contains("crypt");

        if in_memory || encrypted {
            protected.push(name.to_string());
        } else {
            exposed.push(name.to_string());
        }
    }

    if !exposed.is_empty() {
        CheckResult::fail(
            SWAP_ID,
            SWAP_LABEL,
            format!("unencrypted swap: {}", exposed.join(", ")),
        )
        .with_hint("Memory contents are written to disk in the clear. Use zram or encrypted swap.")
    } else if !protected.is_empty() {
        CheckResult::pass(
            SWAP_ID,
            SWAP_LABEL,
            format!("swap protected: {}", protected.join(", ")),
        )
    } else {
        CheckResult::pass(SWAP_ID, SWAP_LABEL, "no swap configured")
    }
}

// ---------------------------------------------------------------------------
// Core dumps
// ---------------------------------------------------------------------------

const CORE_ID: &str = "core-dumps";
const CORE_LABEL: &str = "Core dumps";

pub fn core_dumps() -> CheckResult {
    parse_core_dumps(
        exec::read_trimmed("/proc/sys/kernel/core_pattern").as_deref(),
        exec::read_trimmed("/proc/sys/fs/suid_dumpable").as_deref(),
    )
}

/// Pure parser for the core-dump configuration.
///
/// A core dump is a copy of a process's memory on disk. For anything holding
/// keys — a password manager, an SSH agent, the browser — that is the entire
/// secret, written out unencrypted at the moment it crashes.
pub fn parse_core_dumps(core_pattern: Option<&str>, suid_dumpable: Option<&str>) -> CheckResult {
    let Some(pattern) = core_pattern.map(str::trim) else {
        return CheckResult::unknown(CORE_ID, CORE_LABEL, "could not read core_pattern");
    };

    let mut problems: Vec<String> = Vec::new();

    // `core_pattern = |/bin/false` (or an empty pattern) means dumps go nowhere.
    let dumps_discarded = pattern.is_empty()
        || pattern.contains("/bin/false")
        || pattern.contains("/dev/null")
        || pattern == "|/bin/true";

    if !dumps_discarded {
        problems.push(format!("core_pattern={pattern}"));
    }
    if suid_dumpable.map(str::trim).is_some_and(|v| v != "0") {
        problems.push(format!(
            "fs.suid_dumpable={}",
            suid_dumpable.unwrap_or("?").trim()
        ));
    }

    if problems.is_empty() {
        CheckResult::pass(CORE_ID, CORE_LABEL, "dumps discarded")
    } else {
        CheckResult::warn(CORE_ID, CORE_LABEL, problems.join(", "))
            .with_hint("A crash can write process memory — including keys — to disk.")
            .with_fix("sudo sysctl -w kernel.core_pattern=|/bin/false fs.suid_dumpable=0")
    }
}

// ---------------------------------------------------------------------------
// Bluetooth
// ---------------------------------------------------------------------------

const BT_ID: &str = "bluetooth";
const BT_LABEL: &str = "Bluetooth";

pub fn bluetooth() -> CheckResult {
    let state = exec::run("systemctl", &["is-active", "bluetooth.service"])
        .stdout()
        .trim()
        .to_string();
    let devices = exec::run("bluetoothctl", &["devices", "Connected"]);
    parse_bluetooth(&state, devices.success_stdout())
}

/// Pure parser for the Bluetooth posture.
///
/// A powered radio is a persistent, remotely-addressable identifier and an
/// attack surface. Running with nothing connected is the case worth flagging —
/// it is surface nobody is using.
pub fn parse_bluetooth(service_state: &str, connected: Option<&str>) -> CheckResult {
    let state = service_state.trim();

    if state.is_empty() {
        return CheckResult::unknown(BT_ID, BT_LABEL, "systemctl unavailable");
    }
    if state != "active" {
        return CheckResult::pass(BT_ID, BT_LABEL, format!("service {state}"));
    }

    let count = connected
        .map(|out| {
            out.lines()
                .filter(|l| l.trim().starts_with("Device"))
                .count()
        })
        .unwrap_or(0);

    if count > 0 {
        CheckResult::warn(
            BT_ID,
            BT_LABEL,
            format!("radio on, {count} device(s) connected"),
        )
        .with_hint("In use, but the radio is still a trackable identifier in public.")
    } else {
        CheckResult::warn(BT_ID, BT_LABEL, "radio on, nothing connected")
            .with_hint("Unused radio surface. Turn it off when you are not pairing anything.")
            .with_fix("sudo systemctl stop bluetooth.service")
    }
}

// ---------------------------------------------------------------------------
// Time synchronisation
// ---------------------------------------------------------------------------

const TIME_ID: &str = "time-sync";
const TIME_LABEL: &str = "Time sync";

pub fn time_sync() -> CheckResult {
    parse_time_sync(&exec::run(
        "timedatectl",
        &["show", "-p", "NTPSynchronized", "-p", "NTP"],
    ))
}

/// Pure parser for `timedatectl show` key=value output.
///
/// A clock that has drifted breaks TLS certificate validation in both
/// directions: expired certificates start looking valid, and valid ones start
/// looking expired.
pub fn parse_time_sync(outcome: &Outcome) -> CheckResult {
    let Some(output) = outcome.success_stdout() else {
        return CheckResult::unknown(
            TIME_ID,
            TIME_LABEL,
            outcome
                .unavailable_reason()
                .unwrap_or_else(|| "timedatectl unavailable".to_string()),
        );
    };

    let value = |key: &str| -> Option<String> {
        output.lines().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };

    let synchronized = value("NTPSynchronized");
    let ntp_enabled = value("NTP");

    match synchronized.as_deref() {
        Some("yes") => CheckResult::pass(TIME_ID, TIME_LABEL, "clock synchronised"),
        Some("no") => {
            let detail = match ntp_enabled.as_deref() {
                Some("no") => "not synchronised, NTP disabled",
                _ => "not synchronised",
            };
            CheckResult::warn(TIME_ID, TIME_LABEL, detail)
                .with_hint("A drifted clock breaks TLS certificate validation.")
                .with_fix("sudo timedatectl set-ntp true")
        }
        _ => CheckResult::unknown(TIME_ID, TIME_LABEL, "could not read NTP state"),
    }
}

// ---------------------------------------------------------------------------
// Pending updates
// ---------------------------------------------------------------------------

const UPD_ID: &str = "updates";
const UPD_LABEL: &str = "Pending updates";

pub fn pending_updates() -> CheckResult {
    // `pacman -Qu` reads the local database only: no network, no sync, so it
    // is safe to run on every refresh. It reports what a sync has already
    // found, which is exactly the question "am I behind?".
    parse_pending_updates(&exec::run("pacman", &["-Qu"]))
}

/// Pure parser for `pacman -Qu`.
///
/// pacman exits non-zero when there is nothing to upgrade, so a failed run with
/// empty stdout is the *good* case and must not be reported as an error.
pub fn parse_pending_updates(outcome: &Outcome) -> CheckResult {
    if let Some(reason) = outcome.unavailable_reason() {
        return CheckResult::unknown(UPD_ID, UPD_LABEL, reason);
    }

    let count = outcome
        .stdout()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();

    if count == 0 {
        return CheckResult::pass(UPD_ID, UPD_LABEL, "up to date");
    }

    let status = if count > 50 {
        Status::Fail(format!("{count} packages behind"))
    } else {
        Status::Warn(format!("{count} packages behind"))
    };

    CheckResult::new(UPD_ID, UPD_LABEL, status)
        .with_hint("Unpatched packages are the most commonly exploited weakness on a desktop.")
        .with_fix("sudo pacman -Syu")
}
