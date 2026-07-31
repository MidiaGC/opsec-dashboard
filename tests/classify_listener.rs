use opsec_dashboard::checks::{
    ListenerKind, Proto, Status, classify_listener, parse_listening, parse_listening_outcome,
};
use opsec_dashboard::exec::Outcome;

fn exposed(port: &str) -> ListenerKind {
    ListenerKind::Exposed(port.to_string())
}

#[test]
fn classifies_wildcard_ipv4() {
    assert_eq!(classify_listener("0.0.0.0:22"), exposed("22"));
}

#[test]
fn classifies_wildcard_ipv6() {
    assert_eq!(classify_listener("[::]:443"), exposed("443"));
}

#[test]
fn classifies_bare_star_wildcard() {
    // Some `ss` versions print `*:port` for a dual-stack wildcard bind.
    assert_eq!(classify_listener("*:8080"), exposed("8080"));
}

#[test]
fn classifies_loopback_as_local() {
    assert_eq!(classify_listener("127.0.0.1:631"), ListenerKind::Local);
    assert_eq!(classify_listener("127.0.0.53:53"), ListenerKind::Local);
    assert_eq!(classify_listener("[::1]:8080"), ListenerKind::Local);
}

// Regression: a socket bound to the LAN address is reachable by every other
// host on that network. Reporting it as "Local" hid real exposure.
#[test]
fn classifies_interface_bound_as_lan() {
    assert_eq!(
        classify_listener("192.168.1.5:53"),
        ListenerKind::Lan("53".to_string())
    );
}

#[test]
fn strips_ipv6_zone_index() {
    assert_eq!(
        classify_listener("[fe80::1%wlan0]:546"),
        ListenerKind::Lan("546".to_string())
    );
}

// Regression: the Unknown variant existed but was never constructed, so an
// unparseable address silently counted as safe.
#[test]
fn unparseable_addresses_are_unknown_not_local() {
    assert_eq!(classify_listener(""), ListenerKind::Unknown);
    assert_eq!(classify_listener("garbage"), ListenerKind::Unknown);
    assert_eq!(classify_listener("0.0.0.0:"), ListenerKind::Unknown);
    assert_eq!(classify_listener("0.0.0.0:http"), ListenerKind::Unknown);
}

// ---------- parse_listening ----------

#[test]
fn dedups_ipv4_and_ipv6_bindings_of_the_same_port() {
    let output = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 [::]:22 [::]:*
LISTEN 0 128 0.0.0.0:5355 0.0.0.0:*
LISTEN 0 128 [::]:5355 [::]:*
LISTEN 0 128 127.0.0.1:631 0.0.0.0:*";
    let msg = match parse_listening(Proto::Tcp, output).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn for 2 exposed ports, got {other:?}"),
    };
    assert!(msg.contains("22") && msg.contains("5355"), "got {msg}");
}

#[test]
fn no_listeners_passes() {
    assert!(matches!(
        parse_listening(Proto::Tcp, "").status,
        Status::Pass(_)
    ));
}

#[test]
fn loopback_only_passes() {
    let output = "LISTEN 0 128 127.0.0.1:631 0.0.0.0:*
LISTEN 0 128 [::1]:9050 [::]:*";
    assert!(matches!(
        parse_listening(Proto::Tcp, output).status,
        Status::Pass(_)
    ));
}

#[test]
fn three_or_more_exposed_ports_fail() {
    let output = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 0.0.0.0:80 0.0.0.0:*
LISTEN 0 128 0.0.0.0:443 0.0.0.0:*";
    let msg = match parse_listening(Proto::Tcp, output).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    assert!(msg.starts_with('3'), "expected the count first in {msg}");
}

#[test]
fn lan_bound_only_warns() {
    let output = "LISTEN 0 128 192.168.1.5:8000 0.0.0.0:*";
    assert!(matches!(
        parse_listening(Proto::Tcp, output).status,
        Status::Warn(_)
    ));
}

#[test]
fn udp_check_carries_its_own_identity() {
    let tcp = parse_listening(Proto::Tcp, "");
    let udp = parse_listening(Proto::Udp, "");
    assert_ne!(tcp.id, udp.id);
    assert!(udp.label.contains("UDP"));
}

#[test]
fn missing_ss_binary_is_unknown() {
    assert!(matches!(
        parse_listening_outcome(Proto::Tcp, &Outcome::NotFound).status,
        Status::Unknown(_)
    ));
}
