use quantova_qcore::signing_summary;

const CONTRACT: &str = "Q1PVRQ8DQ6YYUEDH68QEM3PWT6JC9U9TP95V2QHU2PFDF2ZVNH5NQQRNM92J";

fn call(index: u64, signer: &str, args: &str, meter: &str) -> String {
    signing_summary(
        "call".to_string(),
        qcore::testnet_chain_id(),
        CONTRACT.to_string(),
        "0".to_string(),
        "1000".to_string(),
        String::new(),
        index,
        signer.to_string(),
        args.to_string(),
        meter.to_string(),
    )
    .unwrap()
}

#[test]
fn two_different_calls_from_two_accounts_never_show_the_same_prompt() {
    let a = call(0, "", "a9059cbb0000000000000001", "100000");
    let b = call(7, "", "dd62ed3e00000000000000ff", "100000");
    assert_ne!(a, b);
    assert!(a.contains("From account 0") && b.contains("From account 7"));
    assert!(a.contains("Function a9059cbb") && b.contains("Function dd62ed3e"));
    assert!(a.contains("0000000000000001") && b.contains("00000000000000ff"));
    assert!(a.contains("Meter limit 100000"));
}

#[test]
fn long_arguments_are_shown_by_length_and_fingerprint() {
    let long = format!("a9059cbb{}", "11".repeat(200));
    let other = format!("a9059cbb{}", "12".repeat(200));
    let a = call(0, "", &long, "5");
    let b = call(0, "", &other, "5");
    assert!(a.contains("Arguments 200 bytes, fingerprint"));
    assert_ne!(a, b);
}

#[test]
fn malformed_call_arguments_are_refused() {
    for bad in ["", "abc", "zz112233", "aabbcc"] {
        assert!(
            signing_summary(
                "call".to_string(),
                qcore::testnet_chain_id(),
                CONTRACT.to_string(),
                "0".to_string(),
                "1000".to_string(),
                String::new(),
                0,
                String::new(),
                bad.to_string(),
                "1".to_string()
            )
            .is_err(),
            "{bad}"
        );
    }
}
