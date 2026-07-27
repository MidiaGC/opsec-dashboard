use opsec_dashboard::checks::{parse_mac, Status};

const IP_LINK_REAL: &str = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000\\    link/ether 64:1c:67:f5:65:e5 brd ff:ff:ff:ff:ff:ff\\    altname enx641c67f565e5
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\\    link/ether ea:91:11:3a:61:47 brd ff:ff:ff:ff:ff:ff permaddr 58:ce:2a:63:95:52
5: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
6: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default \\    link/ether ee:7a:10:cc:52:09 brd ff:ff:ff:ff:ff:ff";

#[test]
fn real_machine_wlan0_randomized() {
    let r = parse_mac(IP_LINK_REAL);
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass, got {:?}", r.status) };
    assert!(msg.contains("wlan0"), "wlan0 not in: {msg}");
    assert!(msg.contains("≠"), "expected ≠ separator in: {msg}");
}

#[test]
fn mac_exposed_when_matches_permaddr() {
    let input = "4: wlan0: <BROADCAST> link/ether 58:ce:2a:63:95:52 permaddr 58:ce:2a:63:95:52";
    let r = parse_mac(input);
    let msg = match r.status { Status::Fail(m) => m, _ => panic!("expected Fail, got {:?}", r.status) };
    assert!(msg.contains("wlan0"));
}

#[test]
fn no_permaddr_warns() {
    let input = "2: enp3s0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff";
    let r = parse_mac(input);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn loopback_ignored() {
    let input = "1: lo: <LOOPBACK,UP> link/loopback 00:00:00:00:00:00";
    let r = parse_mac(input);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn empty_input_warns() {
    let r = parse_mac("");
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn multiple_randomized_interfaces() {
    let input = "2: wlan0: <BROADCAST> link/ether aa:aa:aa:aa:aa:aa permaddr 11:11:11:11:11:11
3: wlan1: <BROADCAST> link/ether bb:bb:bb:bb:bb:bb permaddr 22:22:22:22:22:22";
    let r = parse_mac(input);
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass") };
    assert!(msg.contains("wlan0"));
    assert!(msg.contains("wlan1"));
}

#[test]
fn mixed_randomized_and_exposed_reports_randomized_first() {
    let input = "2: wlan0: <BROADCAST> link/ether aa:aa:aa:aa:aa:aa permaddr 11:11:11:11:11:11
3: wlan1: <BROADCAST> link/ether 22:22:22:22:22:22 permaddr 22:22:22:22:22:22";
    let r = parse_mac(input);
    // Per current logic: randomized takes priority over exposed.
    assert!(matches!(r.status, Status::Pass(_)));
}
