use opsec_dashboard::checks::extract_field;

#[test]
fn finds_field_value() {
    let line = "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff";
    assert_eq!(extract_field(line, "link/ether"), Some("aa:bb:cc:dd:ee:ff".into()));
}

#[test]
fn finds_permaddr() {
    let line = "link/ether aa:bb:cc:dd:ee:ff permaddr 11:22:33:44:55:66";
    assert_eq!(extract_field(line, "permaddr"), Some("11:22:33:44:55:66".into()));
}

#[test]
fn missing_field_returns_none() {
    let line = "link/ether aa:bb:cc:dd:ee:ff";
    assert_eq!(extract_field(line, "permaddr"), None);
}

#[test]
fn empty_line_returns_none() {
    assert_eq!(extract_field("", "link/ether"), None);
}

#[test]
fn field_at_end_of_line() {
    let line = "something permaddr 11:22:33:44:55:66";
    assert_eq!(extract_field(line, "permaddr"), Some("11:22:33:44:55:66".into()));
}

#[test]
fn field_with_no_value_returns_none() {
    // "link/ether" is the last token, no value follows.
    let line = "some stuff link/ether";
    assert_eq!(extract_field(line, "link/ether"), None);
}

#[test]
fn field_name_as_substring_does_not_match() {
    // "link/ethernet" should not match "link/ether" — must be exact token.
    let line = "link/ethernet aa:bb:cc:dd:ee:ff";
    assert_eq!(extract_field(line, "link/ether"), None);
}
