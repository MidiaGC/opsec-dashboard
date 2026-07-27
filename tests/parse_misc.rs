use opsec_dashboard::checks::{parse_secure_boot, parse_apparmor, parse_usbguard, Status};

// ---------- secure_boot ----------

#[test]
fn secure_boot_enabled_passes() {
    let r = parse_secure_boot("   Secure Boot: enabled\n   Driver: ...");
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass") };
    assert!(msg.contains("enabled"));
}

#[test]
fn secure_boot_disabled_fails() {
    let r = parse_secure_boot("   Secure Boot: disabled\n");
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn secure_boot_setup_warns() {
    // Real machine output: "Secure Boot: disabled (setup)"
    // Secure Boot is OFF (not enforcing) — this is a security failure.
    // The "(setup)" suffix just means it COULD be enabled (not locked).
    // Fixed behavior: disabled takes priority over setup → Fail.
    let r = parse_secure_boot("   Secure Boot: disabled (setup)\n");
    assert!(matches!(r.status, Status::Fail(_)), "disabled+setup should Fail, got {:?}", r.status);
}

#[test]
fn secure_boot_setup_only_warns() {
    let r = parse_secure_boot("   Secure Boot: setup\n");
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn secure_boot_no_match_unknown() {
    let r = parse_secure_boot("   some other line\n");
    assert!(matches!(r.status, Status::Unknown(_)));
}

#[test]
fn secure_boot_case_insensitive() {
    let r = parse_secure_boot("   SECURE BOOT: ENABLED\n");
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn secure_boot_empty_unknown() {
    let r = parse_secure_boot("");
    assert!(matches!(r.status, Status::Unknown(_)));
}

// ---------- apparmor ----------

#[test]
fn apparmor_y_passes() {
    let r = parse_apparmor(Some("Y\n"));
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn apparmor_n_fails() {
    let r = parse_apparmor(Some("N\n"));
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn apparmor_missing_file_unknown() {
    let r = parse_apparmor(None);
    let msg = match r.status { Status::Unknown(m) => m, _ => panic!("expected Unknown") };
    assert!(msg.contains("not loaded"));
}

#[test]
fn apparmor_unexpected_value_unknown() {
    let r = parse_apparmor(Some("X\n"));
    assert!(matches!(r.status, Status::Unknown(_)));
}

#[test]
fn apparmor_trims_whitespace() {
    let r = parse_apparmor(Some("  Y  \n"));
    assert!(matches!(r.status, Status::Pass(_)));
}

// ---------- usbguard ----------

#[test]
fn usbguard_active_with_devices_passes() {
    let ipc = "1: allow id 1234:5678 serial \"ABC\" name \"Mouse\"\n2: allow id 90ab:cdef serial \"XYZ\" name \"KB\"";
    let r = parse_usbguard("active", Some(ipc));
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass") };
    assert!(msg.contains("2 devices"));
}

#[test]
fn usbguard_active_no_sudo_warns() {
    let r = parse_usbguard("active", None);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn usbguard_inactive_fails() {
    let r = parse_usbguard("inactive", None);
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn usbguard_empty_state_unknown() {
    let r = parse_usbguard("", None);
    assert!(matches!(r.status, Status::Unknown(_)));
}

#[test]
fn usbguard_active_empty_ipc_passes_zero() {
    // Service active, IPC reachable, no devices allowed.
    let r = parse_usbguard("active", Some(""));
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass") };
    assert!(msg.contains("0 devices"));
}

#[test]
fn usbguard_state_trimmed() {
    let r = parse_usbguard("active\n", None);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn usbguard_failed_state_fails() {
    let r = parse_usbguard("failed", None);
    let msg = match r.status { Status::Fail(m) => m, _ => panic!("expected Fail") };
    assert!(msg.contains("failed"));
}
