use opsec_dashboard::checks::{
    Status, explicit_egress_block, has_output_default_deny, parse_bluetooth, parse_core_dumps,
    parse_ipv6_leak, parse_kill_switch, parse_pending_updates, parse_swap, parse_time_sync,
};
use opsec_dashboard::exec::Outcome;

const VPN_UP: &str = "4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> link/ether aa:bb:cc:dd:ee:ff
5: wg0: <POINTOPOINT,NOARP,UP> link/none";
const NO_VPN: &str = "4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> link/ether aa:bb:cc:dd:ee:ff";

// ---------- IPv6 leak ----------

// The classic leak: an IPv4-only tunnel while IPv6 still exits via the ISP.
#[test]
fn ipv6_default_route_outside_the_tunnel_is_a_leak() {
    let routes = "default via fe80::1 dev wlan0 proto ra metric 1024";
    let msg = match parse_ipv6_leak(VPN_UP, Some(routes), Some("0")).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    assert!(msg.contains("wlan0"), "got {msg}");
}

#[test]
fn ipv6_default_route_inside_the_tunnel_passes() {
    let routes = "default dev wg0 metric 1024";
    assert!(matches!(
        parse_ipv6_leak(VPN_UP, Some(routes), Some("0")).status,
        Status::Pass(_)
    ));
}

#[test]
fn ipv6_disabled_system_wide_passes() {
    let routes = "default via fe80::1 dev wlan0";
    assert!(matches!(
        parse_ipv6_leak(VPN_UP, Some(routes), Some("1")).status,
        Status::Pass(_)
    ));
}

// Without a tunnel there is nothing to leak out of.
#[test]
fn no_tunnel_means_nothing_to_leak() {
    let routes = "default via fe80::1 dev wlan0";
    assert!(matches!(
        parse_ipv6_leak(NO_VPN, Some(routes), Some("0")).status,
        Status::Pass(_)
    ));
}

#[test]
fn no_ipv6_default_route_at_all_passes() {
    assert!(matches!(
        parse_ipv6_leak(VPN_UP, Some(""), Some("0")).status,
        Status::Pass(_)
    ));
}

#[test]
fn unreadable_routes_are_unknown() {
    assert!(matches!(
        parse_ipv6_leak(VPN_UP, None, Some("0")).status,
        Status::Unknown(_)
    ));
}

// ---------- kill switch ----------

#[test]
fn output_policy_drop_is_a_kill_switch() {
    let ruleset = "table inet filter {
    chain output {
        type filter hook output priority 0; policy drop;
    }
}";
    assert!(has_output_default_deny(ruleset));
    assert!(matches!(
        parse_kill_switch(VPN_UP, Some(ruleset)).status,
        Status::Pass(_)
    ));
}

#[test]
fn an_explicit_non_tunnel_egress_drop_is_a_kill_switch() {
    let ruleset = "table inet filter {
    chain output {
        type filter hook output priority 0; policy accept;
        oifname != \"wg0\" drop
    }
}";
    assert!(explicit_egress_block(ruleset).is_some());
    assert!(matches!(
        parse_kill_switch(VPN_UP, Some(ruleset)).status,
        Status::Pass(_)
    ));
}

#[test]
fn an_open_output_chain_with_a_tunnel_up_fails() {
    let ruleset = "table inet filter {
    chain output {
        type filter hook output priority 0; policy accept;
    }
}";
    assert!(matches!(
        parse_kill_switch(VPN_UP, Some(ruleset)).status,
        Status::Fail(_)
    ));
}

// No tunnel yet means there is nothing being protected — advice, not a failure.
#[test]
fn an_open_output_chain_without_a_tunnel_only_warns() {
    let ruleset = "chain output { type filter hook output priority 0; policy accept; }";
    assert!(matches!(
        parse_kill_switch(NO_VPN, Some(ruleset)).status,
        Status::Warn(_)
    ));
}

#[test]
fn an_unreadable_ruleset_warns() {
    assert!(matches!(
        parse_kill_switch(VPN_UP, None).status,
        Status::Warn(_)
    ));
}

#[test]
fn a_commented_out_drop_is_not_a_kill_switch() {
    let ruleset = "# oifname != \"wg0\" drop\nchain output { policy accept; }";
    assert!(!has_output_default_deny(ruleset));
    assert!(explicit_egress_block(ruleset).is_none());
}

// ---------- swap ----------

const SWAPS_HEADER: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority";

#[test]
fn a_plain_swap_partition_fails() {
    let swaps = format!(
        "{SWAPS_HEADER}\n/dev/nvme0n1p3                          partition\t8388604\t\t0\t\t-2"
    );
    let msg = match parse_swap(Some(&swaps), Some("nvme0n1p3 part")).status {
        Status::Fail(m) => m,
        other => panic!("unencrypted swap must fail, got {other:?}"),
    };
    assert!(msg.contains("nvme0n1p3"), "got {msg}");
}

// zram lives in RAM and never touches the disk.
#[test]
fn zram_swap_passes() {
    let swaps = format!(
        "{SWAPS_HEADER}\n/dev/zram0                              partition\t8388604\t\t0\t\t100"
    );
    assert!(matches!(
        parse_swap(Some(&swaps), Some("zram0 disk")).status,
        Status::Pass(_)
    ));
}

#[test]
fn swap_on_a_crypt_device_passes() {
    let swaps = format!(
        "{SWAPS_HEADER}\n/dev/mapper/cryptswap                   partition\t8388604\t\t0\t\t-2"
    );
    assert!(matches!(
        parse_swap(Some(&swaps), Some("cryptswap crypt")).status,
        Status::Pass(_)
    ));
}

#[test]
fn no_swap_at_all_passes() {
    assert!(matches!(
        parse_swap(Some(SWAPS_HEADER), Some("")).status,
        Status::Pass(_)
    ));
}

#[test]
fn unreadable_proc_swaps_is_unknown() {
    assert!(matches!(parse_swap(None, None).status, Status::Unknown(_)));
}

// ---------- core dumps ----------

#[test]
fn discarded_core_dumps_pass() {
    assert!(matches!(
        parse_core_dumps(Some("|/bin/false"), Some("0")).status,
        Status::Pass(_)
    ));
}

#[test]
fn dumps_written_to_disk_warn() {
    let msg =
        match parse_core_dumps(Some("|/usr/lib/systemd/systemd-coredump %P"), Some("0")).status {
            Status::Warn(m) => m,
            other => panic!("expected Warn, got {other:?}"),
        };
    assert!(msg.contains("core_pattern"), "got {msg}");
}

#[test]
fn suid_dumpable_is_flagged_on_its_own() {
    let msg = match parse_core_dumps(Some("|/bin/false"), Some("1")).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains("suid_dumpable"), "got {msg}");
}

#[test]
fn unreadable_core_pattern_is_unknown() {
    assert!(matches!(
        parse_core_dumps(None, Some("0")).status,
        Status::Unknown(_)
    ));
}

// ---------- bluetooth ----------

#[test]
fn bluetooth_off_passes() {
    assert!(matches!(
        parse_bluetooth("inactive", None).status,
        Status::Pass(_)
    ));
}

#[test]
fn bluetooth_on_with_nothing_connected_offers_a_fix() {
    let result = parse_bluetooth("active", Some(""));
    assert!(matches!(result.status, Status::Warn(_)));
    assert!(
        result.fix.is_some(),
        "unused radio should be switchable off"
    );
}

#[test]
fn bluetooth_in_use_warns_without_offering_to_cut_it_off() {
    let connected = "Device AA:BB:CC:DD:EE:FF Headphones";
    let result = parse_bluetooth("active", Some(connected));
    let msg = match result.status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains('1'), "got {msg}");
    assert!(
        result.fix.is_none(),
        "must not offer to kill a device in use"
    );
}

#[test]
fn bluetooth_without_systemctl_is_unknown() {
    assert!(matches!(
        parse_bluetooth("", None).status,
        Status::Unknown(_)
    ));
}

// ---------- time sync ----------

#[test]
fn a_synchronised_clock_passes() {
    let out = Outcome::ok("NTP=yes\nNTPSynchronized=yes\n");
    assert!(matches!(parse_time_sync(&out).status, Status::Pass(_)));
}

#[test]
fn an_unsynchronised_clock_warns() {
    let out = Outcome::ok("NTP=no\nNTPSynchronized=no\n");
    let msg = match parse_time_sync(&out).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains("NTP disabled"), "got {msg}");
}

#[test]
fn missing_timedatectl_is_unknown() {
    assert!(matches!(
        parse_time_sync(&Outcome::NotFound).status,
        Status::Unknown(_)
    ));
}

// ---------- pending updates ----------

// pacman exits non-zero when there is nothing to upgrade: the *good* case.
#[test]
fn nothing_to_upgrade_passes_despite_a_nonzero_exit() {
    let out = Outcome::failed_with("", "");
    assert!(matches!(
        parse_pending_updates(&out).status,
        Status::Pass(_)
    ));
}

#[test]
fn a_handful_of_updates_warns() {
    let out = Outcome::ok("linux 6.9.1-1 -> 6.9.2-1\nopenssl 3.3.0-1 -> 3.3.1-1\n");
    let msg = match parse_pending_updates(&out).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains('2'), "got {msg}");
}

#[test]
fn a_long_backlog_fails() {
    let out = Outcome::ok(
        &(0..60)
            .map(|i| format!("pkg{i} 1 -> 2\n"))
            .collect::<String>(),
    );
    assert!(matches!(
        parse_pending_updates(&out).status,
        Status::Fail(_)
    ));
}

// On a non-Arch host pacman simply is not there; that is not a security finding.
#[test]
fn a_missing_package_manager_is_unknown() {
    assert!(matches!(
        parse_pending_updates(&Outcome::NotFound).status,
        Status::Unknown(_)
    ));
}
