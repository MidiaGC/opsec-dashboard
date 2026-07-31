use opsec_dashboard::checks::{Status, extract_field, parse_mac, parse_mac_outcome};
use opsec_dashboard::exec::Outcome;

const IP_LINK_REAL: &str = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000\\    link/ether 64:1c:67:f5:65:e5 brd ff:ff:ff:ff:ff:ff\\    altname enx641c67f565e5
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\\    link/ether ea:91:11:3a:61:47 brd ff:ff:ff:ff:ff:ff permaddr 58:ce:2a:63:95:52
5: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
6: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default \\    link/ether ee:7a:10:cc:52:09 brd ff:ff:ff:ff:ff:ff";

#[test]
fn real_machine_wlan0_randomized_but_ethernet_exposed() {
    let msg = match parse_mac(IP_LINK_REAL).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    // wlan0 is randomized (link/ether differs from permaddr)...
    assert!(msg.contains("wlan0"), "wlan0 not in: {msg}");
    assert!(msg.contains('≠'), "expected ≠ separator in: {msg}");
    // ...but enp4s0 still carries its vendor MAC, and that is the finding.
    assert!(
        msg.contains("enp4s0"),
        "exposed ethernet missing from: {msg}"
    );
}

#[test]
fn mac_exposed_when_matches_permaddr() {
    let input = "4: wlan0: <BROADCAST> link/ether 58:ce:2a:63:95:52 permaddr 58:ce:2a:63:95:52";
    let msg = match parse_mac(input).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    assert!(msg.contains("wlan0"));
}

// Regression: with randomization switched off the kernel stops reporting
// `permaddr` at all, so "no permaddr" used to be reported as "nothing to
// check" — the least private configuration read as harmless.
#[test]
fn vendor_mac_without_permaddr_is_exposed() {
    // 0x64: the locally-administered bit is clear, so this is a vendor OUI.
    let msg = match parse_mac("2: enp3s0: <BROADCAST> link/ether 64:1c:67:f5:65:e5").status {
        Status::Fail(m) => m,
        other => panic!("a vendor MAC in use must not pass, got {other:?}"),
    };
    assert!(msg.contains("enp3s0"), "got {msg}");
}

#[test]
fn locally_administered_mac_without_permaddr_counts_as_randomized() {
    // 0xaa has the 0x02 bit set — a randomized address.
    let r = parse_mac("2: enp3s0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff");
    assert!(matches!(r.status, Status::Pass(_)), "got {:?}", r.status);
}

#[test]
fn locally_administered_bit_detection() {
    use opsec_dashboard::checks::is_locally_administered;
    assert_eq!(is_locally_administered("64:1c:67:f5:65:e5"), Some(false));
    assert_eq!(is_locally_administered("aa:bb:cc:dd:ee:ff"), Some(true));
    assert_eq!(is_locally_administered("ea:91:11:3a:61:47"), Some(true));
    assert_eq!(is_locally_administered("zz:bb:cc"), None);
}

// Software interfaces get kernel-generated MACs that reveal nothing, and would
// otherwise drown out the interfaces that matter.
#[test]
fn virtual_interfaces_are_ignored() {
    let input = "6: docker0: <BROADCAST> link/ether 02:42:ac:11:00:02
7: br-5c9ddce: <BROADCAST> link/ether 86:7c:80:ff:4c:2d
8: vethbe000@if2: <BROADCAST> link/ether ce:81:ca:25:d8:e8";
    assert!(matches!(parse_mac(input).status, Status::Warn(_)));
}

#[test]
fn interfaces_without_a_hardware_address_are_skipped() {
    let r = parse_mac("5: tailscale0: <POINTOPOINT,UP> link/none");
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn loopback_ignored() {
    let r = parse_mac("1: lo: <LOOPBACK,UP> link/loopback 00:00:00:00:00:00");
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn empty_input_warns() {
    assert!(matches!(parse_mac("").status, Status::Warn(_)));
}

#[test]
fn multiple_randomized_interfaces() {
    let input = "2: wlan0: <BROADCAST> link/ether aa:aa:aa:aa:aa:aa permaddr 11:11:11:11:11:11
3: wlan1: <BROADCAST> link/ether bb:bb:bb:bb:bb:bb permaddr 22:22:22:22:22:22";
    let msg = match parse_mac(input).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("wlan0") && msg.contains("wlan1"));
}

// Regression: one randomized interface used to mask an exposed one, because the
// Pass branch was evaluated first. A leaking interface is a leak regardless of
// what the others are doing.
#[test]
fn mixed_randomized_and_exposed_reports_the_exposure() {
    let input = "2: wlan0: <BROADCAST> link/ether aa:aa:aa:aa:aa:aa permaddr 11:11:11:11:11:11
3: wlan1: <BROADCAST> link/ether 22:22:22:22:22:22 permaddr 22:22:22:22:22:22";
    let msg = match parse_mac(input).status {
        Status::Fail(m) => m,
        other => panic!("an exposed MAC must not be masked by a randomized one, got {other:?}"),
    };
    assert!(
        msg.contains("wlan1"),
        "exposed interface missing from {msg}"
    );
    assert!(
        msg.contains("wlan0"),
        "randomized context missing from {msg}"
    );
}

#[test]
fn missing_ip_binary_is_unknown() {
    assert!(matches!(
        parse_mac_outcome(&Outcome::NotFound).status,
        Status::Unknown(_)
    ));
}

// ---------- extract_field ----------

#[test]
fn finds_field_value() {
    let line = "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff";
    assert_eq!(
        extract_field(line, "link/ether"),
        Some("aa:bb:cc:dd:ee:ff".into())
    );
}

#[test]
fn finds_permaddr() {
    let line = "link/ether aa:bb:cc:dd:ee:ff permaddr 11:22:33:44:55:66";
    assert_eq!(
        extract_field(line, "permaddr"),
        Some("11:22:33:44:55:66".into())
    );
}

#[test]
fn missing_field_returns_none() {
    assert_eq!(
        extract_field("link/ether aa:bb:cc:dd:ee:ff", "permaddr"),
        None
    );
}

#[test]
fn empty_line_returns_none() {
    assert_eq!(extract_field("", "link/ether"), None);
}

#[test]
fn field_with_no_value_returns_none() {
    assert_eq!(extract_field("some stuff link/ether", "link/ether"), None);
}

#[test]
fn field_name_as_substring_does_not_match() {
    // "link/ethernet" must not satisfy a lookup for "link/ether".
    assert_eq!(
        extract_field("link/ethernet aa:bb:cc:dd:ee:ff", "link/ether"),
        None
    );
}
