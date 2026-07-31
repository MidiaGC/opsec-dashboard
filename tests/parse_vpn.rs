use opsec_dashboard::checks::{Status, is_vpn_interface, parse_vpn, parse_vpn_outcome};
use opsec_dashboard::exec::Outcome;

const IP_LINK_REAL: &str = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000\\    link/ether 64:1c:67:f5:65:e5 brd ff:ff:ff:ff:ff:ff\\    altname enx641c67f565e5
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\\    link/ether ea:91:11:3a:61:47 brd ff:ff:ff:ff:ff:ff permaddr 58:ce:2a:63:95:52
5: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
6: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default \\    link/ether ee:7a:10:cc:52:09 brd ff:ff:ff:ff:ff:ff";

#[test]
fn real_machine_detects_tailscale() {
    let msg = match parse_vpn(IP_LINK_REAL).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("tailscale0"), "expected tailscale0 in {msg}");
}

#[test]
fn detects_tun_interface() {
    let input = "1: lo: <LOOPBACK> link/loopback 00:00:00:00:00:00
2: enp3s0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff
3: tun0: <POINTOPOINT,MULTICAST,UP> link/none";
    let msg = match parse_vpn(input).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("tun0"));
}

#[test]
fn detects_wg_interface() {
    let r = parse_vpn("5: wg0: <POINTOPOINT,NOARP,UP> link/none");
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn reports_every_active_tunnel() {
    let input = "3: tun0: <POINTOPOINT,UP> link/none
5: wg0: <POINTOPOINT,UP> link/none";
    let msg = match parse_vpn(input).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("tun0") && msg.contains("wg0"), "got {msg}");
}

#[test]
fn no_vpn_interface_fails() {
    let input = "1: lo: <LOOPBACK> link/loopback 00:00:00:00:00:00
2: enp3s0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff";
    assert!(matches!(parse_vpn(input).status, Status::Fail(_)));
}

#[test]
fn empty_output_fails() {
    assert!(matches!(parse_vpn("").status, Status::Fail(_)));
}

#[test]
fn loopback_only_fails() {
    let r = parse_vpn("1: lo: <LOOPBACK,UP,LOWER_UP> link/loopback 00:00:00:00:00:00");
    assert!(matches!(r.status, Status::Fail(_)));
}

// Regression: a configured-but-down tunnel used to read as ACTIVE, which is the
// most dangerous possible false positive for this check.
#[test]
fn down_tunnel_warns_instead_of_passing() {
    let input =
        "3: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT\\    link/none";
    let msg = match parse_vpn(input).status {
        Status::Warn(m) => m,
        other => panic!("a down tunnel must not pass, got {other:?}"),
    };
    assert!(msg.contains("wg0") && msg.contains("down"), "got {msg}");
}

#[test]
fn down_tunnel_alongside_up_tunnel_passes() {
    let input = "3: wg0: <POINTOPOINT,NOARP> state DOWN\\    link/none
4: tun0: <POINTOPOINT,UP> link/none";
    assert!(matches!(parse_vpn(input).status, Status::Pass(_)));
}

#[test]
fn does_not_match_substring_named_interface() {
    // "tunnelup" must not read as a live "tun" device.
    let r = parse_vpn("2: tunnelup: <BROADCAST,UP> link/ether aa:bb:cc:dd:ee:ff");
    assert!(matches!(r.status, Status::Fail(_)), "got {:?}", r.status);
}

#[test]
fn strips_at_suffix_from_name() {
    let msg = match parse_vpn("3: wg0@if12: <POINTOPOINT,UP> link/none").status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("wg0"), "expected wg0 in {msg}");
    assert!(!msg.contains('@'), "@ not stripped: {msg}");
}

#[test]
fn interface_name_matching() {
    assert!(is_vpn_interface("tun0"));
    assert!(is_vpn_interface("wg0"));
    assert!(is_vpn_interface("tailscale0"));
    assert!(is_vpn_interface("pppoe0"));
    // wg-quick names tunnels after the config file.
    assert!(is_vpn_interface("wg-home"));
    // Vendors that do not number their device.
    assert!(is_vpn_interface("nordlynx"));

    assert!(!is_vpn_interface("tun"), "bare tun is not a real device");
    assert!(!is_vpn_interface("tunnelup"));
    assert!(!is_vpn_interface("wlan0"));
    assert!(!is_vpn_interface("docker0"));
}

// Orchestration failure modes — previously untestable without mocking Command.
#[test]
fn missing_ip_binary_is_unknown_not_fail() {
    let msg = match parse_vpn_outcome(&Outcome::NotFound).status {
        Status::Unknown(m) => m,
        other => panic!("expected Unknown, got {other:?}"),
    };
    assert!(msg.contains("not installed"), "got {msg}");
}

#[test]
fn timed_out_ip_is_unknown() {
    assert!(matches!(
        parse_vpn_outcome(&Outcome::TimedOut).status,
        Status::Unknown(_)
    ));
}

#[test]
fn nonzero_exit_is_unknown_not_fail() {
    // A failing `ip` that prints nothing must never be read as "no VPN".
    let r = parse_vpn_outcome(&Outcome::failed_with("", "Cannot open netlink socket"));
    assert!(matches!(r.status, Status::Unknown(_)), "got {:?}", r.status);
}
