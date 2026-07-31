use opsec_dashboard::checks::{Status, has_input_default_deny, parse_nftables};

#[test]
fn active_with_ruleset_and_drop_passes() {
    let ruleset = "table inet filter {
        chain input {
            type filter hook input priority 0; policy drop;
            ct state established accept
            iif lo accept
        }
    }";
    let msg = match parse_nftables("active", Some(ruleset)).status {
        Status::Pass(m) => m,
        other => panic!("expected Pass, got {other:?}"),
    };
    assert!(msg.contains("policy drop"));
}

#[test]
fn active_with_ruleset_no_drop_warns() {
    let ruleset = "table inet filter {
        chain input {
            type filter hook input priority 0; policy accept;
        }
    }";
    assert!(matches!(
        parse_nftables("active", Some(ruleset)).status,
        Status::Warn(_)
    ));
}

#[test]
fn active_empty_ruleset_fails() {
    assert!(matches!(
        parse_nftables("active", Some("")).status,
        Status::Fail(_)
    ));
}

#[test]
fn active_only_comments_fails() {
    assert!(matches!(
        parse_nftables("active", Some("# comment\n# another\n")).status,
        Status::Fail(_)
    ));
}

#[test]
fn inactive_with_ruleset_present_fails() {
    let msg = match parse_nftables("inactive", Some("table inet filter {}")).status {
        Status::Fail(m) => m,
        other => panic!("expected Fail, got {other:?}"),
    };
    assert!(msg.contains("ruleset present"));
}

#[test]
fn active_no_sudo_warns() {
    let msg = match parse_nftables("active", None).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains("needs sudo"));
}

#[test]
fn inactive_no_sudo_warns_not_fails() {
    // Without the ruleset we cannot prove the firewall is broken.
    assert!(matches!(
        parse_nftables("inactive", None).status,
        Status::Warn(_)
    ));
}

#[test]
fn empty_state_no_sudo_warns() {
    assert!(matches!(parse_nftables("", None).status, Status::Warn(_)));
}

#[test]
fn state_is_trimmed() {
    let msg = match parse_nftables("active\n", None).status {
        Status::Warn(m) => m,
        other => panic!("expected Warn, got {other:?}"),
    };
    assert!(msg.contains("active"), "state not trimmed: {msg}");
}

// ---------- default-deny detection ----------

#[test]
fn detects_drop_on_the_hook_line() {
    let ruleset = "table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
    }
}";
    assert!(has_input_default_deny(ruleset));
}

#[test]
fn detects_drop_declared_after_the_hook_line() {
    let ruleset = "table inet filter {
    chain input {
        type filter hook input priority filter;
        policy drop;
    }
}";
    assert!(has_input_default_deny(ruleset));
}

#[test]
fn drop_on_output_chain_is_not_an_input_drop() {
    let ruleset = "table inet filter {
    chain output {
        type filter hook output priority 0; policy drop;
    }
    chain input {
        type filter hook input priority 0; policy accept;
    }
}";
    assert!(!has_input_default_deny(ruleset));
    assert!(matches!(
        parse_nftables("active", Some(ruleset)).status,
        Status::Warn(_)
    ));
}

// Regression: a chain that merely mentions "input" used to satisfy the matcher.
#[test]
fn drop_in_a_chain_named_input_forward_is_not_an_input_drop() {
    let ruleset = "table inet filter {
    chain input_forward {
        type filter hook forward priority 0; policy drop;
    }
    chain input {
        type filter hook input priority 0; policy accept;
    }
}";
    assert!(!has_input_default_deny(ruleset));
}

#[test]
fn comments_cannot_fake_a_default_deny() {
    let ruleset = "# input policy drop is configured elsewhere
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept; # policy drop later
    }
}";
    assert!(!has_input_default_deny(ruleset));
    assert!(
        matches!(
            parse_nftables("active", Some(ruleset)).status,
            Status::Warn(_)
        ),
        "a comment must not produce a false Pass"
    );
}

#[test]
fn drop_after_the_input_chain_closes_does_not_count() {
    let ruleset = "table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        policy drop;
    }
}";
    assert!(!has_input_default_deny(ruleset));
}
