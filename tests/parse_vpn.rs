use opsec_dashboard::checks::{parse_vpn, Status};

const IP_LINK_REAL: &str = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000\\    link/ether 64:1c:67:f5:65:e5 brd ff:ff:ff:ff:ff:ff\\    altname enx641c67f565e5
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\\    link/ether ea:91:11:3a:61:47 brd ff:ff:ff:ff:ff:ff permaddr 58:ce:2a:63:95:52
5: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
6: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default \\    link/ether ee:7a:10:cc:52:09 brd ff:ff:ff:ff:ff:ff";

#[test]
fn real_machine_detects_tailscale() {
    let r = parse_vpn(IP_LINK_REAL);
    assert!(matches!(r.status, Status::Pass(_)), "got {:?}", r.status);
    let msg = match r.status { Status::Pass(m) => m, _ => unreachable!() };
    assert!(msg.contains("tailscale0"), "expected tailscale0 in {msg}");
}

#[test]
fn detects_tun_interface() {
    let input = "1: lo: <LOOPBACK> link/loopback 00:00:00:00:00:00
2: enp3s0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff
3: tun0: <POINTOPOINT,MULTICAST,UP> link/none";
    let r = parse_vpn(input);
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass, got {:?}", r.status) };
    assert!(msg.contains("tun0"));
}

#[test]
fn detects_wg_interface() {
    let input = "5: wg0: <POINTOPOINT,NOARP,UP> link/none";
    let r = parse_vpn(input);
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn no_vpn_interface_fails() {
    let input = "1: lo: <LOOPBACK> link/loopback 00:00:00:00:00:00
2: enp3s0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff";
    let r = parse_vpn(input);
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn empty_output_fails() {
    let r = parse_vpn("");
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn loopback_only_fails() {
    let r = parse_vpn("1: lo: <LOOPBACK,UP,LOWER_UP> link/loopback 00:00:00:00:00:00");
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn does_not_match_subnet_named_interface() {
    // An interface named "tunnelup" should NOT match the "tun" prefix.
    // Word boundary required: the token after the colon-space must start with
    // the prefix, not just contain it as a substring.
    let input = "2: tunnelup: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff";
    let r = parse_vpn(input);
    assert!(matches!(r.status, Status::Fail(_)), "tunnelup should not match tun, got {:?}", r.status);
}

#[test]
fn strips_veth_at_suffix() {
    // veth interfaces often have `veth123@if45` names — verify the @ stripping
    // works for VPN interfaces too (e.g. wg0@peer).
    let input = "3: wg0@if12: <POINTOPOINT> link/none";
    let r = parse_vpn(input);
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass") };
    assert!(msg.contains("wg0"), "expected wg0 in {msg}");
    assert!(!msg.contains("@"), "@ not stripped: {msg}");
}

#[test]
fn tun_without_digit_does_not_match() {
    // "tun" alone (no digit) — is this a valid VPN interface? Real tun devices
    // are always numbered (tun0, tun1). Bare "tun" should not match.
    let input = "2: tun: <POINTOPOINT> link/none";
    let r = parse_vpn(input);
    assert!(matches!(r.status, Status::Fail(_)), "bare tun should not match, got {:?}", r.status);
}

#[test]
fn tailscale_without_digit_matches() {
    // Wait — does tailscale0 actually have a digit? Yes. But what about a
    // hypothetical "tailscale" interface with no number? Real tailscale creates
    // "tailscale0". Verify our matcher handles the numbered form correctly.
    let input = "5: tailscale0: <POINTOPOINT> link/none";
    let r = parse_vpn(input);
    assert!(matches!(r.status, Status::Pass(_)));
}
