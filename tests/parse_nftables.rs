use opsec_dashboard::checks::{parse_nftables, Status};

#[test]
fn active_with_ruleset_and_drop_passes() {
    let ruleset = "table inet filter {
        chain input {
            type filter hook input priority 0; policy drop;
            ct state established accept
            iif lo accept
        }
    }";
    let r = parse_nftables("active", Some(ruleset));
    let msg = match r.status { Status::Pass(m) => m, _ => panic!("expected Pass, got {:?}", r.status) };
    assert!(msg.contains("policy drop"));
}

#[test]
fn active_with_ruleset_no_drop_warns() {
    let ruleset = "table inet filter {
        chain input {
            type filter hook input priority 0; policy accept;
        }
    }";
    let r = parse_nftables("active", Some(ruleset));
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn active_empty_ruleset_fails() {
    let r = parse_nftables("active", Some(""));
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn active_only_comments_fails() {
    let r = parse_nftables("active", Some("# comment\n# another\n"));
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn inactive_with_ruleset_present_fails() {
    let r = parse_nftables("inactive", Some("table inet filter {}"));
    let msg = match r.status { Status::Fail(m) => m, _ => panic!("expected Fail") };
    assert!(msg.contains("ruleset present"));
}

#[test]
fn active_no_sudo_warns() {
    let r = parse_nftables("active", None);
    let msg = match r.status { Status::Warn(m) => m, _ => panic!("expected Warn") };
    assert!(msg.contains("needs sudo"));
}

#[test]
fn inactive_no_sudo_warns_not_fails() {
    // Key behavior: if we can't read the ruleset, we can't say for sure the
    // firewall is broken — degrade to Warn, not Fail.
    let r = parse_nftables("inactive", None);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn empty_state_no_sudo_warns() {
    let r = parse_nftables("", None);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn state_is_trimmed() {
    let r = parse_nftables("active\n", None);
    let msg = match r.status { Status::Warn(m) => m, _ => panic!("expected Warn, got {:?}", r.status) };
    assert!(msg.contains("active"), "msg should contain trimmed state: {msg}");
}

#[test]
fn drop_on_output_chain_not_counted_as_input_drop() {
    // Regression: `policy drop` on output or forward chain should NOT count
    // as input default-deny.
    let ruleset = "table inet filter {
        chain output {
            type filter hook output priority 0; policy drop;
        }
        chain input {
            type filter hook input priority 0; policy accept;
        }
    }";
    let r = parse_nftables("active", Some(ruleset));
    // Current matcher is `line.contains("policy drop") && line.contains("input")`.
    // The output chain line contains "policy drop" but not "input" → won't match.
    // The input chain line contains "input" but "policy accept" not "policy drop".
    // So has_default_deny = false → Warn. Correct behavior.
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn drop_and_input_on_same_line_in_comment_edge_case() {
    // Edge case: comment line containing both "input" and "policy drop" words.
    // Comments must be stripped before matching — otherwise this false-positives.
    let ruleset = "# input policy drop is configured elsewhere
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
}";
    let r = parse_nftables("active", Some(ruleset));
    // Fixed behavior: comments stripped, real input chain has policy accept → Warn.
    assert!(matches!(r.status, Status::Warn(_)), "comment should not trigger false Pass, got {:?}", r.status);
}
