//! Host-level checks: boot integrity, mandatory access control, disk
//! encryption and kernel hardening.

use crate::checks::{CheckResult, Status};
use crate::exec::{self, Outcome};

// ---------------------------------------------------------------------------
// Secure Boot
// ---------------------------------------------------------------------------

const SB_ID: &str = "secure-boot";
const SB_LABEL: &str = "Secure Boot";

pub fn secure_boot() -> CheckResult {
    parse_secure_boot_outcome(&exec::run("bootctl", &["status"]))
}

/// `bootctl status` exits non-zero on a non-systemd-boot host but still prints
/// the firmware's Secure Boot line, so stdout is used regardless of exit code.
pub fn parse_secure_boot_outcome(outcome: &Outcome) -> CheckResult {
    match outcome {
        Outcome::Completed { stdout, .. } => parse_secure_boot(stdout),
        other => CheckResult::unknown(
            SB_ID,
            SB_LABEL,
            other
                .unavailable_reason()
                .unwrap_or_else(|| "bootctl unavailable".to_string()),
        ),
    }
}

/// Pure parser for `bootctl status` output.
///
/// Real firmware reports things like `Secure Boot: disabled (setup)`. Setup
/// mode is only interesting as a footnote — what matters is whether signatures
/// are being enforced right now, so `disabled` is decided first.
pub fn parse_secure_boot(bootctl_output: &str) -> CheckResult {
    let line = bootctl_output
        .lines()
        .find(|l| l.to_ascii_lowercase().contains("secure boot:"))
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    let setup_note = if line.contains("setup") {
        " (setup mode)"
    } else {
        ""
    };

    if line.contains("disabled") {
        CheckResult::fail(SB_ID, SB_LABEL, format!("disabled{setup_note}"))
            .with_hint("Enrol your keys and enable Secure Boot in firmware (see `sbctl`).")
    } else if line.contains("enabled") {
        CheckResult::pass(SB_ID, SB_LABEL, format!("enabled{setup_note}"))
    } else if line.contains("setup") {
        CheckResult::warn(SB_ID, SB_LABEL, "setup mode (not enforced)")
            .with_hint("Keys can be enrolled without a firmware password — do it now.")
    } else {
        CheckResult::unknown(SB_ID, SB_LABEL, "could not parse bootctl output")
    }
}

// ---------------------------------------------------------------------------
// AppArmor / LSM
// ---------------------------------------------------------------------------

const AA_ID: &str = "apparmor";
const AA_LABEL: &str = "AppArmor / LSM";

const APPARMOR_PARAM: &str = "/sys/module/apparmor/parameters/enabled";
const LSM_LIST: &str = "/sys/kernel/security/lsm";

pub fn apparmor() -> CheckResult {
    match exec::read_trimmed(APPARMOR_PARAM) {
        Some(value) => parse_apparmor(Some(&value)),
        // AppArmor absent is not automatically a failure — the host may be
        // running SELinux instead, which is an equivalent control.
        None => parse_lsm(exec::read_trimmed(LSM_LIST).as_deref()),
    }
}

/// Pure parser for `/sys/module/apparmor/parameters/enabled`.
pub fn parse_apparmor(file_contents: Option<&str>) -> CheckResult {
    match file_contents.map(str::trim) {
        Some("Y") => CheckResult::pass(AA_ID, AA_LABEL, "enabled"),
        Some("N") => CheckResult::fail(AA_ID, AA_LABEL, "disabled")
            .with_hint("Add `lsm=landlock,lockdown,yama,apparmor,bpf` to the kernel cmdline."),
        None => CheckResult::unknown(AA_ID, AA_LABEL, "module not loaded"),
        Some(other) => CheckResult::unknown(AA_ID, AA_LABEL, format!("state: {other}")),
    }
}

/// Fallback when AppArmor is not present: consult the kernel's active LSM list.
pub fn parse_lsm(lsm_list: Option<&str>) -> CheckResult {
    let Some(list) = lsm_list.map(str::trim).filter(|s| !s.is_empty()) else {
        return CheckResult::unknown(AA_ID, AA_LABEL, "module not loaded")
            .with_hint("Neither AppArmor nor an LSM list is exposed by this kernel.");
    };

    let modules: Vec<&str> = list.split(',').map(str::trim).collect();
    if let Some(mac) = modules
        .iter()
        .find(|m| matches!(**m, "selinux" | "apparmor" | "smack" | "tomoyo"))
    {
        CheckResult::pass(AA_ID, AA_LABEL, format!("{mac} active (lsm: {list})"))
    } else {
        CheckResult::fail(AA_ID, AA_LABEL, format!("no MAC module (lsm: {list})"))
            .with_hint("No mandatory access control is active — confined-process isolation is off.")
    }
}

// ---------------------------------------------------------------------------
// Disk encryption
// ---------------------------------------------------------------------------

const DISK_ID: &str = "disk-encryption";
const DISK_LABEL: &str = "Disk encryption";

pub fn disk_encryption() -> CheckResult {
    let lsblk = exec::run("lsblk", &["-rno", "NAME,TYPE,MOUNTPOINT"]);
    let root = exec::run("findmnt", &["-no", "SOURCE", "/"]);
    parse_disk_encryption_outcome(&lsblk, root.success_stdout())
}

pub fn parse_disk_encryption_outcome(outcome: &Outcome, root_source: Option<&str>) -> CheckResult {
    match outcome.success_stdout() {
        Some(out) => parse_disk_encryption(out, root_source),
        None => CheckResult::unknown(
            DISK_ID,
            DISK_LABEL,
            outcome
                .unavailable_reason()
                .unwrap_or_else(|| "lsblk failed".to_string()),
        ),
    }
}

/// Device name backing `/`, from a `findmnt -no SOURCE /` line.
///
/// btrfs reports the subvolume in brackets (`/dev/mapper/vg-root[/@]`), and a
/// leading `/dev/mapper/` or `/dev/` has to come off to match `lsblk`'s NAME
/// column.
pub fn root_device_name(findmnt_source: &str) -> Option<String> {
    let source = findmnt_source.trim();
    if source.is_empty() {
        return None;
    }
    let source = source.split('[').next().unwrap_or(source).trim_end();
    let name = source.rsplit('/').next().unwrap_or(source);
    (!name.is_empty()).then(|| name.to_string())
}

/// Pure parser for `lsblk -rno NAME,TYPE,MOUNTPOINT` plus the device backing
/// `/` as reported by `findmnt`.
///
/// `findmnt` is needed because lsblk's MOUNTPOINT column only shows one mount
/// per device: on a btrfs-subvolume layout the root device can appear against
/// `/var/log` while `/` is nowhere in the output. Relying on lsblk alone made
/// a fully encrypted machine read as "could not determine".
pub fn parse_disk_encryption(lsblk_output: &str, root_source: Option<&str>) -> CheckResult {
    let mut crypt_devices: Vec<&str> = Vec::new();
    let mut root_type: Option<&str> = None;
    let mut saw_any = false;

    let root_name = root_source.and_then(root_device_name);

    for line in lsblk_output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        saw_any = true;
        let mountpoint = fields.next();

        if kind == "crypt" {
            crypt_devices.push(name);
        }
        if mountpoint == Some("/") || root_name.as_deref() == Some(name) {
            root_type = Some(kind);
        }
    }

    if !saw_any {
        return CheckResult::unknown(DISK_ID, DISK_LABEL, "no block devices reported");
    }

    match (root_type, crypt_devices.is_empty()) {
        (Some("crypt"), _) => CheckResult::pass(DISK_ID, DISK_LABEL, "/ on dm-crypt (LUKS)"),
        (Some("lvm"), false) => CheckResult::pass(
            DISK_ID,
            DISK_LABEL,
            format!("/ on LVM over dm-crypt ({})", crypt_devices.join(", ")),
        ),
        (Some(kind), false) => CheckResult::warn(
            DISK_ID,
            DISK_LABEL,
            format!(
                "LUKS present ({}) but / is {kind}",
                crypt_devices.join(", ")
            ),
        )
        .with_hint("Data outside the encrypted volume is readable from any live USB."),
        (Some(kind), true) => CheckResult::fail(
            DISK_ID,
            DISK_LABEL,
            format!("/ is {kind}, no dm-crypt device"),
        )
        .with_hint("The root filesystem is unencrypted at rest."),
        (None, false) => CheckResult::warn(
            DISK_ID,
            DISK_LABEL,
            format!(
                "dm-crypt present ({}), / not reported",
                crypt_devices.join(", ")
            ),
        ),
        (None, true) => CheckResult::unknown(DISK_ID, DISK_LABEL, "could not determine / device"),
    }
}

// ---------------------------------------------------------------------------
// Kernel hardening
// ---------------------------------------------------------------------------

const KERN_ID: &str = "kernel-hardening";
const KERN_LABEL: &str = "Kernel hardening";

/// The condition a hardening sysctl must satisfy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Want {
    AtLeast(i64),
    Exactly(i64),
}

impl Want {
    pub fn satisfied_by(self, value: i64) -> bool {
        match self {
            Want::AtLeast(n) => value >= n,
            Want::Exactly(n) => value == n,
        }
    }

    pub fn describe(self) -> String {
        match self {
            Want::AtLeast(n) => format!(">={n}"),
            Want::Exactly(n) => format!("={n}"),
        }
    }
}

/// A single hardening knob and the value we expect it to hold.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sysctl {
    pub path: &'static str,
    pub name: &'static str,
    pub want: Want,
}

/// The baseline. Deliberately conservative: every entry here is safe to enable
/// on a desktop and is recommended by the kernel self-protection project.
pub static SYSCTLS: &[Sysctl] = &[
    Sysctl {
        path: "/proc/sys/kernel/kptr_restrict",
        name: "kernel.kptr_restrict",
        want: Want::AtLeast(1),
    },
    Sysctl {
        path: "/proc/sys/kernel/dmesg_restrict",
        name: "kernel.dmesg_restrict",
        want: Want::Exactly(1),
    },
    Sysctl {
        path: "/proc/sys/kernel/yama/ptrace_scope",
        name: "kernel.yama.ptrace_scope",
        want: Want::AtLeast(1),
    },
    Sysctl {
        path: "/proc/sys/kernel/randomize_va_space",
        name: "kernel.randomize_va_space",
        want: Want::Exactly(2),
    },
    Sysctl {
        path: "/proc/sys/kernel/unprivileged_bpf_disabled",
        name: "kernel.unprivileged_bpf_disabled",
        want: Want::AtLeast(1),
    },
    Sysctl {
        path: "/proc/sys/net/ipv4/tcp_syncookies",
        name: "net.ipv4.tcp_syncookies",
        want: Want::Exactly(1),
    },
    Sysctl {
        path: "/proc/sys/net/ipv4/conf/all/rp_filter",
        name: "net.ipv4.conf.all.rp_filter",
        want: Want::AtLeast(1),
    },
];

pub fn kernel_hardening() -> CheckResult {
    let readings: Vec<(&'static Sysctl, Option<String>)> = SYSCTLS
        .iter()
        .map(|s| (s, exec::read_trimmed(s.path)))
        .collect();
    parse_kernel_hardening(&readings)
}

/// Pure parser over the sysctl readings. Unreadable knobs are counted
/// separately from misconfigured ones — "not present on this kernel" is not
/// the same failure as "explicitly turned off".
pub fn parse_kernel_hardening(readings: &[(&'static Sysctl, Option<String>)]) -> CheckResult {
    let mut bad: Vec<String> = Vec::new();
    let mut missing = 0usize;
    let mut ok = 0usize;

    for (sysctl, value) in readings {
        match value.as_deref().map(str::trim).map(str::parse::<i64>) {
            Some(Ok(v)) if sysctl.want.satisfied_by(v) => ok += 1,
            Some(Ok(v)) => bad.push(format!(
                "{}={v} (want {})",
                sysctl.name,
                sysctl.want.describe()
            )),
            Some(Err(_)) => missing += 1,
            None => missing += 1,
        }
    }

    let total = readings.len();
    let hint = "Set the listed keys in /etc/sysctl.d/99-hardening.conf and run `sysctl --system`.";

    let status = if bad.is_empty() && missing == 0 {
        Status::Pass(format!("{ok}/{total} hardening sysctls set"))
    } else if bad.is_empty() {
        Status::Warn(format!("{ok}/{total} set, {missing} unavailable"))
    } else if bad.len() <= 2 {
        Status::Warn(format!("{ok}/{total} set — {}", bad.join(", ")))
    } else {
        Status::Fail(format!("{ok}/{total} set — {}", bad.join(", ")))
    };

    CheckResult::new(KERN_ID, KERN_LABEL, status).with_hint(hint)
}
