use opsec_dashboard::checks::{parse_failed_logins, Status};

#[test]
fn zero_attempts_passes() {
    let r = parse_failed_logins("");
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn only_boot_separators_passes() {
    let input = "-- Boot abc123 --
-- Boot def456 --";
    let r = parse_failed_logins(input);
    assert!(matches!(r.status, Status::Pass(_)));
}

#[test]
fn one_attempt_warns() {
    let input = "Jul 25 22:16:39 host sudo[123]: pam_unix(sudo:auth): authentication failure";
    let r = parse_failed_logins(input);
    let msg = match r.status { Status::Warn(m) => m, _ => panic!("expected Warn, got {:?}", r.status) };
    assert!(msg.contains("1"));
}

#[test]
fn five_attempts_warns() {
    let line = "Jul 25 22:16:39 host sudo[123]: pam_unix(sudo:auth): authentication failure";
    let input = (0..5).map(|_| line).collect::<Vec<_>>().join("\n");
    let r = parse_failed_logins(&input);
    assert!(matches!(r.status, Status::Warn(_)));
}

#[test]
fn six_attempts_fails() {
    let line = "Jul 25 22:16:39 host sudo[123]: pam_unix(sudo:auth): authentication failure";
    let input = (0..6).map(|_| line).collect::<Vec<_>>().join("\n");
    let r = parse_failed_logins(&input);
    assert!(matches!(r.status, Status::Fail(_)));
}

#[test]
fn thousands_of_attempts_fails() {
    let line = "Jul 25 22:16:39 host sshd[123]: Failed password for invalid user admin";
    let input = (0..5000).map(|_| line).collect::<Vec<_>>().join("\n");
    let r = parse_failed_logins(&input);
    let msg = match r.status { Status::Fail(m) => m, _ => panic!("expected Fail") };
    assert!(msg.contains("5000"));
}

#[test]
fn mixed_boot_separators_and_real_lines() {
    let input = "-- Boot abc123 --
Jul 25 22:16:39 host sudo[123]: authentication failure
-- Boot def456 --
Jul 25 22:17:00 host sshd[456]: Failed password for invalid user root";
    let r = parse_failed_logins(input);
    let msg = match r.status { Status::Warn(m) => m, _ => panic!("expected Warn, got {:?}", r.status) };
    assert!(msg.contains("2"), "expected 2 attempts, got: {msg}");
}

#[test]
fn empty_lines_ignored() {
    let input = "

Jul 25 22:16:39 host sudo[123]: authentication failure

";
    let r = parse_failed_logins(input);
    let msg = match r.status { Status::Warn(m) => m, _ => panic!("expected Warn") };
    assert!(msg.contains("1"));
}

#[test]
fn real_machine_output() {
    let input = "-- Boot 81e889ca81884049afd981d746d7cac9 --
-- Boot b7144ab49d454b639ae0cc5f94ed7ffe --
-- Boot 05121e3d007747809be939dcd21b81d5 --
Jul 25 22:16:39 archlinux hyprlock[18272]: pam_unix(hyprlock:auth): authentication failure; logname=kalex uid=1000 euid=1000 tty= ruser= rhost=  user=kalex";
    let r = parse_failed_logins(input);
    let msg = match r.status { Status::Warn(m) => m, _ => panic!("expected Warn, got {:?}", r.status) };
    assert!(msg.contains("1"));
}
