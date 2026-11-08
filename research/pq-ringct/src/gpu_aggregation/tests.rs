use super::*;
#[test]
fn command_rejects_unbounded_ambiguous_and_inconsistent_options() {
    let parse = |args: &[&str]| Options::parse(args.iter().map(|s| s.to_string()));
    assert!(parse(&["run", "--input-bundle", "x", "--output", "proof"]).is_ok());
    for tail in [
        vec!["--timeout-seconds", "601"],
        vec!["--group-width", "3"],
        vec!["--pipeline", "lookahead"],
        vec!["--identity", "gpu-batched"],
        vec!["--case", "n5"],
        vec!["--max-components", "0"],
    ] {
        let mut args = vec!["plan", "--input-bundle", "x"];
        args.extend(tail);
        assert!(parse(&args).is_err());
    }
    assert!(parse(&[
        "plan",
        "--input-bundle",
        "x",
        "--case",
        "n3",
        "--case",
        "n4"
    ])
    .is_err());
    assert!(parse(&["run", "--input-bundle", "x"]).is_err());
}
