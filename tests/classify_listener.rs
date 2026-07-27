use opsec_dashboard::checks::{classify_listener, ListenerKind};

#[test]
fn classifies_wildcard_ipv4() {
    assert_eq!(classify_listener("0.0.0.0:22"), ListenerKind::Exposed("22".into()));
}

#[test]
fn classifies_wildcard_ipv6() {
    assert_eq!(classify_listener("[::]:443"), ListenerKind::Exposed("443".into()));
}

#[test]
fn classifies_loopback_as_local() {
    assert_eq!(classify_listener("127.0.0.1:631"), ListenerKind::Local);
}

#[test]
fn classifies_interface_bound_as_local() {
    assert_eq!(classify_listener("192.168.1.5:53"), ListenerKind::Local);
}

#[test]
fn classifies_loopback_ipv6_as_local() {
    assert_eq!(classify_listener("[::1]:8080"), ListenerKind::Local);
}

#[test]
fn classifies_empty_as_local() {
    assert_eq!(classify_listener(""), ListenerKind::Local);
}

#[test]
fn dedup_logic_ipv4_and_ipv6_same_port() {
    // Simulate the dedup loop in listening_services: IPv4 and IPv6 bindings
    // of the same port should count as one exposed port.
    let lines = [
        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
        "LISTEN 0 128 [::]:22 [::]:*",
        "LISTEN 0 128 0.0.0.0:5355 0.0.0.0:*",
        "LISTEN 0 128 [::]:5355 [::]:*",
        "LISTEN 0 128 127.0.0.1:631 0.0.0.0:*",
    ];
    let mut exposed: Vec<String> = Vec::new();
    for line in lines {
        let local = line.split_whitespace().nth(3).unwrap_or("");
        if let ListenerKind::Exposed(port) = classify_listener(local) {
            if !exposed.contains(&port) {
                exposed.push(port);
            }
        }
    }
    assert_eq!(exposed, vec!["22".to_string(), "5355".to_string()]);
}
