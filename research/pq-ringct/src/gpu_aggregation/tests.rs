use super::*;
#[test]
fn archive_inputs_require_explicit_readonly_sha_preflight() {
    let parse=|command:&str,family:&str,width:&str,mode:&str|Options::parse([
        command,"--input-bundle","unused","--screen-family",family,"--request","1",
        "--group-width",width,"--native-source",mode,
    ].into_iter().map(str::to_owned));
    assert!(parse("preflight-groups","shake","4","revalidate-archive").is_ok());
    assert!(parse("architecture-proof","shake","4","revalidate-archive").is_ok());
    assert!(parse("architecture-proof","shake","4","current").is_err());
    assert!(parse("architecture-proof","graph","4","revalidate-archive").is_err());
    for repetitions in ["1", "2", "3"] {
        assert!(Options::parse(["architecture-proof", "--input-bundle", "unused", "--request", "6",
            "--native-source", "revalidate-archive", "--repetitions", repetitions].into_iter().map(str::to_owned)).is_ok());
    }
    for command in ["screen","run","prepare-inputs","plan"] {
        assert!(parse(command,"shake","4","revalidate-archive").is_err());
    }
    assert!(parse("preflight-groups","graph","4","revalidate-archive").is_err());
    assert!(parse("preflight-groups","shake","8","revalidate-archive").is_err());
    assert!(parse("preflight-groups","shake","4","skip-verification").is_err());
}
#[test]
fn consuming_profile_keeps_existing_rows_and_requires_cpu_lookahead() {
    let options = |profile: &str, pipeline: &str, identity: &str| {
        Options::parse(
            [
                "screen",
                "--input-bundle",
                "unused",
                "--profile",
                profile,
                "--pipeline",
                pipeline,
                "--identity",
                identity,
            ]
            .into_iter()
            .map(str::to_owned),
        )
    };
    assert_eq!(
        options("grouped-v2", "lookahead", "cpu")
            .unwrap()
            .max_rows(),
        1 << 18
    );
    assert_eq!(
        options("grouped-v3", "lookahead", "cpu")
            .unwrap()
            .max_rows(),
        1 << 19
    );
    assert!(options("grouped-v3", "serial", "cpu").is_err());
    assert!(options("grouped-v3", "lookahead", "gpu-batched").is_err());
}

#[test]
#[ignore = "requires the exclusive pinned OpenCL aggregation guard"]
fn gpu_consuming_aggregation_produces_fresh_verified_proofs_and_rejects_bad_publics() {
    use lattica_prover_p3::block_v2::machine::ProgramBuilder;
    use p3_field::PrimeCharacteristicRing;
    use std::sync::Arc;
    let options = Options::parse(
        [
            "screen",
            "--case",
            "n4",
            "--input-bundle",
            "unused",
            "--profile",
            "grouped-v3",
            "--pipeline",
            "lookahead",
        ]
        .into_iter()
        .map(str::to_owned),
    )
    .unwrap();
    let execution = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 32 << 30,
        device_bytes: 8 << 30,
        max_rows: options.max_rows(),
    })
    .unwrap();
    execution.configure_consuming_aggregation().unwrap();
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public_wire = builder.public(0).unwrap();
    let input = builder.input();
    let three = builder.constant(lattica_prover_p3::config::Val::from_u64(3));
    let sum = builder.add(input, three);
    builder.assert_equal(public_wire, sum);
    let program = Arc::new(builder.finish(Some(64)).unwrap());
    let public = vec![lattica_prover_p3::config::Val::from_u64(8)];
    let witness = vec![lattica_prover_p3::config::Val::from_u64(5)];
    assert!(execution
        .prove_aggregation_once(Arc::clone(&program), &Vec::new(), &witness)
        .is_err());
    let authority = execution.aggregation_cpu_authority();
    let (prefix, report) = authority.prepare_cpu_only(&program, 512 << 20).unwrap();
    execution
        .install_aggregation_cpu_prefixes(vec![(Arc::clone(&program), prefix, report)])
        .unwrap();
    let first = execution
        .prove_aggregation_once(Arc::clone(&program), &public, &witness)
        .unwrap();
    let second = execution
        .prove_aggregation_once(program, &public, &witness)
        .unwrap();
    first.verifier.verify(&first.proof, &public).unwrap();
    second.verifier.verify(&second.proof, &public).unwrap();
    assert!(first
        .verifier
        .verify(&first.proof, &[lattica_prover_p3::config::Val::from_u64(9)])
        .is_err());
    assert_eq!(first.cap, second.cap);
    assert_ne!(
        postcard::to_allocvec(&first.proof).unwrap(),
        postcard::to_allocvec(&second.proof).unwrap()
    );
    drop((first, second));
    execution.aggregation_identity_report().unwrap();
    execution.finish().unwrap();
}
#[test]
fn command_rejects_unbounded_ambiguous_and_inconsistent_options() {
    let parse = |args: &[&str]| Options::parse(args.iter().map(|s| s.to_string()));
    assert!(parse(&["run", "--input-bundle", "x", "--output", "proof"]).is_ok());
    for tail in [
        vec!["--timeout-seconds", "601"],
        vec!["--group-width", "3"],
        vec!["--pipeline", "serial"],
        vec!["--identity", "gpu-batched"],
        vec!["--case", "n5"],
        vec!["--max-components", "0"],
    ] {
        let mut args = vec!["plan", "--input-bundle", "x"];
        args.extend(tail);
        assert!(parse(&args).is_err(), "unexpectedly accepted {args:?}");
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
