use opsec_dashboard::checks::{
    Status, Sysctl, Want, parse_apparmor, parse_disk_encryption, parse_kernel_hardening, parse_lsm,
    parse_secure_boot, parse_ssh, parse_usbguard, root_device_name, sshd_option, tally_devices,
};

// ---------- secure boot ----------

#[test]
fn secure_boot_enabled_passes() {
    let msg = match parse_secure_boot("   Secure Boot: enabled\n   Driver: ...").status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("enabled"));
}

#[test]
fn secure_boot_disabled_fails() {
    assert!(matches!(
        parse_secure_boot("   Secure Boot: disabled\n").status,
        Status::Fail(_)
    ));
}

#[test]
fn secure_boot_disabled_in_setup_mode_still_fails() {
    // Real firmware prints "Secure Boot: disabled (setup)". Setup mode only
    // says keys *can* be enrolled — nothing is being enforced right now.
    let msg = match parse_secure_boot("   Secure Boot: disabled (setup)\n").status {
        Status::Fail(m) => m,
        other => panic!("disabled+setup must fail, got {other:?}"),
    };
    assert!(msg.contains("setup"), "setup mode should be noted: {msg}");
}

#[test]
fn secure_boot_setup_only_warns() {
    assert!(matches!(
        parse_secure_boot("   Secure Boot: setup\n").status,
        Status::Warn(_)
    ));
}

#[test]
fn secure_boot_unparseable_is_unknown() {
    assert!(matches!(
        parse_secure_boot("   some other line\n").status,
        Status::Unknown(_)
    ));
    assert!(matches!(parse_secure_boot("").status, Status::Unknown(_)));
}

#[test]
fn secure_boot_is_case_insensitive() {
    assert!(matches!(
        parse_secure_boot("   SECURE BOOT: ENABLED\n").status,
        Status::Pass(_)
    ));
}

// ---------- apparmor / lsm ----------

#[test]
fn apparmor_y_passes() {
    assert!(matches!(
        parse_apparmor(Some("Y\n")).status,
        Status::Pass(_)
    ));
}

#[test]
fn apparmor_n_fails() {
    assert!(matches!(
        parse_apparmor(Some("N\n")).status,
        Status::Fail(_)
    ));
}

#[test]
fn apparmor_missing_file_unknown() {
    let msg = match parse_apparmor(None).status {
        Status::Unknown(m) => m,
        other => panic!("expected Unknown, got {other:?}"),
    };
    assert!(msg.contains("not loaded"));
}

#[test]
fn apparmor_unexpected_value_unknown() {
    assert!(matches!(
        parse_apparmor(Some("X\n")).status,
        Status::Unknown(_)
    ));
}

#[test]
fn apparmor_trims_whitespace() {
    assert!(matches!(
        parse_apparmor(Some("  Y  \n")).status,
        Status::Pass(_)
    ));
}

// A SELinux host has mandatory access control even without AppArmor, and must
// not be reported as unprotected.
#[test]
fn selinux_counts_as_mandatory_access_control() {
    let msg = match parse_lsm(Some("capability,landlock,lockdown,yama,selinux,bpf")).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass for a SELinux host, got {other:?}"),
    };
    assert!(msg.contains("selinux"));
}

#[test]
fn lsm_without_any_mac_module_fails() {
    assert!(matches!(
        parse_lsm(Some("capability,landlock,lockdown,bpf")).status,
        Status::Fail(_)
    ));
}

#[test]
fn missing_lsm_list_is_unknown() {
    assert!(matches!(parse_lsm(None).status, Status::Unknown(_)));
    assert!(matches!(parse_lsm(Some("  ")).status, Status::Unknown(_)));
}

// ---------- usbguard ----------

#[test]
fn usbguard_counts_only_allowed_devices() {
    // Regression: every line used to count as "allowed", including the ones
    // USBGuard had blocked.
    let ipc = "1: allow id 1234:5678 serial \"ABC\" name \"Mouse\"
2: block id 90ab:cdef serial \"XYZ\" name \"Unknown stick\"
3: allow id 1111:2222 serial \"\" name \"Keyboard\"";
    let msg = match parse_usbguard("active", Some(ipc)).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("2 allowed"), "got {msg}");
    assert!(
        msg.contains("1 blocked"),
        "blocked devices missing from {msg}"
    );
}

#[test]
fn device_tally_by_target() {
    let tally = tally_devices("1: allow id a\n2: block id b\n3: reject id c\n4: allow id d");
    assert_eq!(tally.allowed, 2);
    assert_eq!(tally.blocked, 2);
    assert_eq!(tally.other, 0);
}

#[test]
fn usbguard_active_no_sudo_warns() {
    assert!(matches!(
        parse_usbguard("active", None).status,
        Status::Warn(_)
    ));
}

#[test]
fn usbguard_inactive_fails() {
    assert!(matches!(
        parse_usbguard("inactive", None).status,
        Status::Fail(_)
    ));
}

#[test]
fn usbguard_empty_state_unknown() {
    assert!(matches!(
        parse_usbguard("", None).status,
        Status::Unknown(_)
    ));
}

#[test]
fn usbguard_active_empty_ipc_passes_zero() {
    let msg = match parse_usbguard("active", Some("")).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("0 allowed"));
}

#[test]
fn usbguard_state_trimmed() {
    assert!(matches!(
        parse_usbguard("active\n", None).status,
        Status::Warn(_)
    ));
}

// ---------- disk encryption ----------

#[test]
fn root_on_dmcrypt_passes() {
    let lsblk = "nvme0n1 disk
nvme0n1p1 part /boot
nvme0n1p2 part
cryptroot crypt /";
    assert!(matches!(
        parse_disk_encryption(lsblk, None).status,
        Status::Pass(_)
    ));
}

#[test]
fn root_on_lvm_over_luks_passes() {
    let lsblk = "sda disk
sda2 part
luks-abcd crypt
vg0-root lvm /";
    assert!(matches!(
        parse_disk_encryption(lsblk, None).status,
        Status::Pass(_)
    ));
}

#[test]
fn plain_root_partition_fails() {
    let lsblk = "sda disk
sda1 part /boot
sda2 part /";
    let msg = match parse_disk_encryption(lsblk, None).status {
        Status::Fail(m) => m,
        other => panic!("an unencrypted root must fail, got {other:?}"),
    };
    assert!(msg.contains("no dm-crypt"), "got {msg}");
}

#[test]
fn luks_present_but_root_plain_warns() {
    let lsblk = "sda disk
sda1 part /
sdb1 part
backup crypt /mnt/backup";
    assert!(matches!(
        parse_disk_encryption(lsblk, None).status,
        Status::Warn(_)
    ));
}

#[test]
fn empty_lsblk_output_is_unknown() {
    assert!(matches!(
        parse_disk_encryption("", None).status,
        Status::Unknown(_)
    ));
}

// Regression: lsblk's MOUNTPOINT column shows only one mount per device. On a
// btrfs-subvolume layout the root device is listed against some other mount and
// `/` never appears, so a fully encrypted machine reported "could not
// determine". findmnt supplies the missing link.
#[test]
fn btrfs_subvolume_root_is_resolved_through_findmnt() {
    let lsblk = "zram0 disk [SWAP]
nvme0n1 disk
nvme0n1p1 part /boot
nvme0n1p2 part
cryptlvm crypt
ArchinstallVg-root lvm /var/log";
    let plain = parse_disk_encryption(lsblk, None);
    assert!(
        matches!(plain.status, Status::Warn(_)),
        "without findmnt the root cannot be located: {:?}",
        plain.status
    );

    let resolved = parse_disk_encryption(lsblk, Some("/dev/mapper/ArchinstallVg-root[/@]\n"));
    let msg = match resolved.status {
        Status::Pass(m) => m,
        other => panic!("LVM over LUKS must pass, got {other:?}"),
    };
    assert!(msg.contains("cryptlvm"), "got {msg}");
}

#[test]
fn root_device_name_strips_subvolume_and_path() {
    assert_eq!(
        root_device_name("/dev/mapper/vg-root[/@]"),
        Some("vg-root".to_string())
    );
    assert_eq!(
        root_device_name("/dev/nvme0n1p2\n"),
        Some("nvme0n1p2".to_string())
    );
    assert_eq!(root_device_name("  "), None);
    assert_eq!(root_device_name(""), None);
}

// ---------- kernel hardening ----------

const KPTR: Sysctl = Sysctl {
    path: "/proc/sys/kernel/kptr_restrict",
    name: "kernel.kptr_restrict",
    want: Want::AtLeast(1),
};
const DMESG: Sysctl = Sysctl {
    path: "/proc/sys/kernel/dmesg_restrict",
    name: "kernel.dmesg_restrict",
    want: Want::Exactly(1),
};
const ASLR: Sysctl = Sysctl {
    path: "/proc/sys/kernel/randomize_va_space",
    name: "kernel.randomize_va_space",
    want: Want::Exactly(2),
};

#[test]
fn want_semantics() {
    assert!(Want::AtLeast(1).satisfied_by(2));
    assert!(!Want::AtLeast(1).satisfied_by(0));
    assert!(Want::Exactly(2).satisfied_by(2));
    assert!(!Want::Exactly(2).satisfied_by(3));
}

#[test]
fn all_sysctls_set_passes() {
    let readings = [
        (&KPTR, Some("2".to_string())),
        (&DMESG, Some("1".to_string())),
        (&ASLR, Some("2".to_string())),
    ];
    let msg = match parse_kernel_hardening(&readings).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("3/3"), "got {msg}");
}

#[test]
fn one_bad_sysctl_warns_and_names_it() {
    let readings = [
        (&KPTR, Some("0".to_string())),
        (&DMESG, Some("1".to_string())),
        (&ASLR, Some("2".to_string())),
    ];
    let msg = match parse_kernel_hardening(&readings).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains("kernel.kptr_restrict=0"), "got {msg}");
    assert!(msg.contains(">=1"), "expectation missing from {msg}");
}

#[test]
fn three_bad_sysctls_fail() {
    let readings = [
        (&KPTR, Some("0".to_string())),
        (&DMESG, Some("0".to_string())),
        (&ASLR, Some("0".to_string())),
    ];
    assert!(matches!(
        parse_kernel_hardening(&readings).status,
        Status::Fail(_)
    ));
}

// "Not present on this kernel" is a different fact from "explicitly disabled".
#[test]
fn unreadable_sysctls_warn_rather_than_fail() {
    let readings = [
        (&KPTR, Some("2".to_string())),
        (&DMESG, None),
        (&ASLR, Some("nonsense".to_string())),
    ];
    let msg = match parse_kernel_hardening(&readings).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains("2 unavailable"), "got {msg}");
}

// ---------- sshd ----------

#[test]
fn sshd_not_running_passes() {
    let msg = match parse_ssh("inactive", None).status {
        Status::Pass(m) => m,
        other => panic!("no listening sshd means no remote surface, got {other:?}"),
    };
    assert!(msg.contains("inactive"));
}

#[test]
fn sshd_running_with_key_only_config_passes() {
    let config = "PermitRootLogin no\nPasswordAuthentication no\n";
    assert!(matches!(
        parse_ssh("active", Some(config)).status,
        Status::Pass(_)
    ));
}

#[test]
fn sshd_permitting_root_password_login_fails() {
    let config = "PermitRootLogin yes\nPasswordAuthentication yes\n";
    let msg = match parse_ssh("active", Some(config)).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    assert!(msg.contains("PermitRootLogin yes"));
    assert!(msg.contains("PasswordAuthentication yes"));
}

// sshd's own defaults apply to absent keywords — and its default for
// PasswordAuthentication is "yes".
#[test]
fn sshd_defaults_are_applied_when_keywords_are_absent() {
    let msg = match parse_ssh("active", Some("Port 22\n")).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail from the implicit defaults, got {other:?}"),
    };
    assert!(msg.contains("PasswordAuthentication yes"), "got {msg}");
}

#[test]
fn sshd_prohibit_password_root_login_is_advisory() {
    let config = "PermitRootLogin prohibit-password\nPasswordAuthentication no\n";
    assert!(matches!(
        parse_ssh("active", Some(config)).status,
        Status::Warn(_)
    ));
}

#[test]
fn sshd_unreadable_config_warns() {
    assert!(matches!(parse_ssh("active", None).status, Status::Warn(_)));
}

#[test]
fn sshd_option_lookup() {
    let config = "# PermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication=no\n";
    // Commented lines are not directives.
    assert_eq!(sshd_option(config, "PermitRootLogin"), Some("no"));
    // Keyword matching is case-insensitive; `key=value` form is accepted.
    assert_eq!(sshd_option(config, "passwordauthentication"), Some("no"));
    assert_eq!(sshd_option(config, "Port"), None);
}

#[test]
fn sshd_option_takes_the_first_value() {
    // sshd honours the first obtained value, not the last.
    let config = "PermitRootLogin no\nPermitRootLogin yes\n";
    assert_eq!(sshd_option(config, "PermitRootLogin"), Some("no"));
}
