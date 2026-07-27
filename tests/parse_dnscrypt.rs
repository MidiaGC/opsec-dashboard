use opsec_dashboard::checks::{parse_dnscrypt, Status};

#[test]
fn active_service_passes() {
    let r = parse_dnscrypt("active\n");
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn inactive_service_fails() {
    let r = parse_dnscrypt("inactive\n");
    let msg = match r.status { Status::Fail(m) => m, _ => panic!("expected Fail") };
    assert!(msg.contains("inactive"));
}

#[test]
fn failed_service_fails() {
    let r = parse_dnscrypt("failed\n");
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn empty_state_is_unknown() {
    let r = parse_dnscrypt("");
    assert!(matches!(r.status, Status::Unknown(_)));
}

#[test]
fn whitespace_only_state_is_unknown() {
    let r = parse_dnscrypt("   \n  ");
    assert!(matches!(r.status, Status::Unknown(_)));
}

#[test]
fn activating_state_fails() {
    let r = parse_dnscrypt("activating\n");
    assert!(matches!(r.status, Status::Fail(_)));
}
