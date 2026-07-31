//! Network-facing checks: VPN, MAC randomization, listening sockets.

use crate::checks::{CheckResult, Status};
use crate::config::{self, Thresholds};
use crate::exec::{self, Outcome};

// ---------------------------------------------------------------------------
// `ip -o link` parsing
// ---------------------------------------------------------------------------

/// One interface as reported by `ip -o link`.
///
/// `-o` folds each interface onto a single line, so the format is
/// `INDEX: NAME[@PARENT]: <FLAG,FLAG,...> mtu N ... state STATE ...`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpLink<'a> {
    pub name: String,
    pub flags: Vec<&'a str>,
    pub state: Option<&'a str>,
    pub raw: &'a str,
}

impl IpLink<'_> {
    /// Administratively up. Note this is the `UP` *flag*, not `state UP`:
    /// tunnel devices legitimately sit at `state UNKNOWN` while carrying
    /// traffic, so `state` alone would misreport every VPN.
    pub fn is_up(&self) -> bool {
        self.flags.iter().any(|f| f.eq_ignore_ascii_case("UP"))
    }

    pub fn is_loopback(&self) -> bool {
        self.name == "lo"
            || self
                .flags
                .iter()
                .any(|f| f.eq_ignore_ascii_case("LOOPBACK"))
    }
}

/// Parse a single `ip -o link` line. `None` for lines that do not have the
/// expected `index: name:` shape.
pub fn parse_ip_link_line(line: &str) -> Option<IpLink<'_>> {
    let (_index, rest) = line.split_once(':')?;
    let (name_raw, tail) = rest.split_once(':')?;
    // `veth0@if12` / `wg0@peer` — the part after `@` is the peer, not the name.
    let name = name_raw
        .trim()
        .split('@')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        return None;
    }

    let flags = tail
        .split_once('<')
        .and_then(|(_, r)| r.split_once('>'))
        .map(|(inner, _)| {
            inner
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    Some(IpLink {
        name,
        flags,
        state: field(line, "state"),
        raw: line,
    })
}

/// Value of the token following `field` in a whitespace-separated line.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let mut tokens = line.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == name {
            return tokens.next();
        }
    }
    None
}

/// Value of the token following `field`, as an owned `String`.
pub fn extract_field(line: &str, field_name: &str) -> Option<String> {
    field(line, field_name).map(str::to_string)
}

// ---------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------

/// Interface name prefixes that indicate a tunnel, matched as
/// `<prefix><digit>` (tun0, wg0) or `<prefix>-<name>` (wg-home), never as a
/// bare substring — otherwise an interface called `tunnelup` would read as a
/// live VPN.
const VPN_PREFIXES: &[&str] = &[
    "tun",
    "tap",
    "wg",
    "ppp",
    "pppoe",
    "ipsec",
    "tailscale",
    "wgpia",
    "proton",
];

/// Tunnel interfaces whose vendors do not number them.
const VPN_EXACT: &[&str] = &["nordlynx", "mullvad", "wgpia", "utun"];

const VPN_ID: &str = "vpn";
const VPN_LABEL: &str = "VPN";

/// True if `name` looks like a tunnel interface.
pub fn is_vpn_interface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if VPN_EXACT.contains(&name.as_str()) {
        return true;
    }
    VPN_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_ascii_digit() || c == '-')
    })
}

pub fn vpn_status() -> CheckResult {
    parse_vpn_outcome(&exec::run("ip", &["-o", "link"]))
}

/// Interpret the `ip -o link` invocation, including its failure modes.
pub fn parse_vpn_outcome(outcome: &Outcome) -> CheckResult {
    match outcome.success_stdout() {
        Some(out) => parse_vpn(out),
        None => CheckResult::unknown(
            VPN_ID,
            VPN_LABEL,
            outcome
                .unavailable_reason()
                .unwrap_or_else(|| "ip -o link failed".to_string()),
        ),
    }
}

/// Pure parser for `ip -o link` output.
///
/// A tunnel interface that exists but is **down** is reported as a warning, not
/// a pass: the config is there, the tunnel is not.
pub fn parse_vpn(ip_output: &str) -> CheckResult {
    let mut up: Vec<String> = Vec::new();
    let mut down: Vec<String> = Vec::new();

    for line in ip_output.lines() {
        let Some(link) = parse_ip_link_line(line) else {
            continue;
        };
        if !is_vpn_interface(&link.name) {
            continue;
        }
        if link.is_up() {
            up.push(link.name);
        } else {
            down.push(link.name);
        }
    }

    if !up.is_empty() {
        return CheckResult::pass(VPN_ID, VPN_LABEL, format!("ACTIVE: {}", up.join(", ")));
    }
    if !down.is_empty() {
        return CheckResult::warn(
            VPN_ID,
            VPN_LABEL,
            format!("{} present but down", down.join(", ")),
        )
        .with_hint("Bring the tunnel up (`wg-quick up <iface>`, `tailscale up`, …).");
    }
    CheckResult::fail(VPN_ID, VPN_LABEL, "no VPN interface")
        .with_hint("Traffic is leaving unencrypted over your ISP link. Start your VPN.")
}

// ---------------------------------------------------------------------------
// MAC randomization
// ---------------------------------------------------------------------------

const MAC_ID: &str = "mac";
const MAC_LABEL: &str = "MAC randomization";

pub fn mac_randomization() -> CheckResult {
    parse_mac_outcome(&exec::run("ip", &["-o", "link"]))
}

pub fn parse_mac_outcome(outcome: &Outcome) -> CheckResult {
    match outcome.success_stdout() {
        Some(out) => parse_mac(out),
        None => CheckResult::unknown(
            MAC_ID,
            MAC_LABEL,
            outcome
                .unavailable_reason()
                .unwrap_or_else(|| "ip -o link failed".to_string()),
        ),
    }
}

/// Interface name prefixes for software devices. Their MACs are generated by
/// the kernel or by the container runtime and say nothing about the machine's
/// identity, so including them would bury the interfaces that matter.
const VIRTUAL_PREFIXES: &[&str] = &[
    "docker", "br-", "veth", "virbr", "vmnet", "bond", "dummy", "vnet", "kube",
];

fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether a MAC has the locally-administered bit set — the marker every
/// randomization implementation uses. Globally-unique addresses come from the
/// vendor OUI and identify the hardware.
///
/// The bit is 0x02 of the first octet.
pub fn is_locally_administered(mac: &str) -> Option<bool> {
    let first = mac.split(':').next()?;
    let octet = u8::from_str_radix(first, 16).ok()?;
    Some(octet & 0b0000_0010 != 0)
}

/// Pure parser for `ip -o link`.
///
/// Two signals, in order of confidence:
///
/// 1. `permaddr` — present only once the MAC has actually been changed, so
///    `link/ether != permaddr` is proof of randomization and equality is proof
///    of exposure.
/// 2. The locally-administered bit — the fallback when there is no `permaddr`
///    at all. This case matters: with randomization switched off the kernel
///    stops reporting `permaddr` entirely, and treating that as "nothing to
///    check" would report the least private configuration as harmless.
pub fn parse_mac(ip_output: &str) -> CheckResult {
    let mut randomized: Vec<String> = Vec::new();
    let mut exposed: Vec<String> = Vec::new();

    for line in ip_output.lines() {
        let Some(link) = parse_ip_link_line(line) else {
            continue;
        };
        if link.is_loopback() || is_virtual_interface(&link.name) {
            continue;
        }

        let Some(current) = field(line, "link/ether") else {
            continue; // link/none — tunnels and the like have no MAC.
        };

        match field(line, "permaddr") {
            Some(permanent) if permanent != current => {
                randomized.push(format!("{}: {current} ≠ {permanent}", link.name));
            }
            Some(_) => exposed.push(link.name),
            None => match is_locally_administered(current) {
                Some(true) => randomized.push(format!("{}: {current} (local bit)", link.name)),
                Some(false) => exposed.push(format!("{} ({current})", link.name)),
                None => {}
            },
        }
    }

    // One exposed interface is a leak even if another is randomized, so the
    // worst case wins rather than the first one found.
    if !exposed.is_empty() {
        let mut msg = format!("exposed: {}", exposed.join(", "));
        if !randomized.is_empty() {
            msg.push_str(&format!("  (randomized: {})", randomized.join("  ")));
        }
        return CheckResult::fail(MAC_ID, MAC_LABEL, msg).with_hint(
            "Enable MAC randomization for these interfaces \
             (NetworkManager: wifi.cloned-mac-address=random).",
        );
    }
    if !randomized.is_empty() {
        return CheckResult::pass(MAC_ID, MAC_LABEL, randomized.join("  "));
    }
    CheckResult::warn(MAC_ID, MAC_LABEL, "no physical interfaces to check")
        .with_hint("No interface reports a hardware address, so randomization cannot be verified.")
}

// ---------------------------------------------------------------------------
// Listening sockets
// ---------------------------------------------------------------------------

/// What a socket's local address says about its reachability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    /// Bound to a wildcard address (`0.0.0.0`, `[::]`, `*`) — reachable from
    /// every network the host is attached to.
    Exposed(String),
    /// Bound to a specific non-loopback address — reachable from that LAN.
    Lan(String),
    /// Loopback only.
    Local,
    /// Could not be parsed; deliberately *not* treated as safe.
    Unknown,
}

/// Pure classifier for the local-address field of an `ss -lnH` line.
pub fn classify_listener(local: &str) -> ListenerKind {
    let local = local.trim();
    if local.is_empty() {
        return ListenerKind::Unknown;
    }
    let Some((host, port)) = local.rsplit_once(':') else {
        return ListenerKind::Unknown;
    };
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit() || c == '*') {
        return ListenerKind::Unknown;
    }

    // Normalise `[::1]` and link-local scopes like `[fe80::1%wlan0]`.
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split('%')
        .next()
        .unwrap_or("");

    match host {
        "0.0.0.0" | "::" | "*" | "" => ListenerKind::Exposed(port.to_string()),
        "::1" => ListenerKind::Local,
        h if h.starts_with("127.") => ListenerKind::Local,
        _ => ListenerKind::Lan(port.to_string()),
    }
}

/// Transport protocol for the listening-socket checks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn id(self) -> &'static str {
        match self {
            Proto::Tcp => "listening-tcp",
            Proto::Udp => "listening-udp",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "Listening (TCP)",
            Proto::Udp => "Listening (UDP)",
        }
    }

    fn ss_flags(self) -> &'static str {
        match self {
            Proto::Tcp => "-tlnH",
            Proto::Udp => "-ulnH",
        }
    }
}

pub fn listening_tcp() -> CheckResult {
    listening_services(Proto::Tcp)
}

pub fn listening_udp() -> CheckResult {
    listening_services(Proto::Udp)
}

pub fn listening_services(proto: Proto) -> CheckResult {
    parse_listening_outcome(proto, &exec::run("ss", &[proto.ss_flags()]))
}

pub fn parse_listening_outcome(proto: Proto, outcome: &Outcome) -> CheckResult {
    match outcome.success_stdout() {
        Some(out) => parse_listening(proto, out),
        None => CheckResult::unknown(
            proto.id(),
            proto.label(),
            outcome
                .unavailable_reason()
                .unwrap_or_else(|| "ss failed".to_string()),
        ),
    }
}

/// Pure parser for `ss -tlnH` / `ss -ulnH`.
///
/// IPv4 and IPv6 bindings of the same port are deduplicated — they are one
/// service, not two.
pub fn parse_listening(proto: Proto, ss_output: &str) -> CheckResult {
    parse_listening_with(proto, ss_output, config::thresholds())
}

/// Pure parser with explicit thresholds.
pub fn parse_listening_with(proto: Proto, ss_output: &str, thresholds: Thresholds) -> CheckResult {
    let mut exposed: Vec<String> = Vec::new();
    let mut lan: Vec<String> = Vec::new();
    let mut unparsed = 0usize;

    for line in ss_output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // State Recv-Q Send-Q Local:Port Peer:Port [Process]
        let Some(local) = line.split_whitespace().nth(3) else {
            unparsed += 1;
            continue;
        };
        match classify_listener(local) {
            ListenerKind::Exposed(port) => push_unique(&mut exposed, port),
            ListenerKind::Lan(port) => push_unique(&mut lan, port),
            ListenerKind::Local => {}
            ListenerKind::Unknown => unparsed += 1,
        }
    }

    let suffix = if unparsed > 0 {
        format!("  ({unparsed} unparsed)")
    } else {
        String::new()
    };
    let hint = "Bind these services to 127.0.0.1, or block the ports at the firewall.";

    let count = exposed.len();
    let status = if count > thresholds.listening_fail_above {
        Status::Fail(format!("{count} exposed: {}{suffix}", exposed.join(", ")))
    } else if count > thresholds.listening_warn_above {
        Status::Warn(format!("exposed: {}{suffix}", exposed.join(", ")))
    } else if !lan.is_empty() {
        Status::Warn(format!("LAN-bound: {}{suffix}", lan.join(", ")))
    } else if unparsed > 0 {
        Status::Unknown(format!("no wildcard listeners{suffix}"))
    } else {
        Status::Pass("no externally-bound listeners".to_string())
    };

    CheckResult::new(proto.id(), proto.label(), status).with_hint(hint)
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}
