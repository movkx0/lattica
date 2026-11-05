//! Complete CPU generation measurements; no GPU or recursive workflow startup.
use lattica_pq_ringct_research::native::{
    self,
    cpu_generation::{Configuration, Generator},
    FixtureAmounts,
};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, error::Error, time::Instant};

fn nanos(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn seed(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("expected 64 hexadecimal digits".into());
    }
    let mut out = [0; 32];
    for (i, x) in out.iter_mut().enumerate() {
        *x = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
pub(super) fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    if cfg!(any(
        feature = "opencl",
        feature = "native-generation-oracle",
        feature = "native-spend-oracle"
    )) {
        return Err("generation benchmark requires a CPU-only native-matrict build without diagnostic entropy".into());
    }
    let mut opts = BTreeMap::new();
    if args.len() % 2 != 0 {
        return Err("generation options require values".into());
    }
    for pair in args.chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--transactions"
                | "--samples"
                | "--setup-seed"
                | "--context"
                | "--aes-lanes"
                | "--cache-public-parameters"
                | "--reuse-workspace"
        ) || opts.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("unknown or repeated generation option".into());
        }
    }
    let count: usize = opts.get("--transactions").unwrap_or(&"1").parse()?;
    let samples: usize = opts.get("--samples").unwrap_or(&"100").parse()?;
    let lanes: u32 = opts.get("--aes-lanes").unwrap_or(&"1").parse()?;
    let cache = match *opts.get("--cache-public-parameters").unwrap_or(&"0") {
        "0" => false,
        "1" => true,
        _ => return Err("cache must be 0 or 1".into()),
    };
    let reuse = match *opts.get("--reuse-workspace").unwrap_or(&"1") {
        "0" => false,
        "1" => true,
        _ => return Err("reuse must be 0 or 1".into()),
    };
    if !matches!(count, 1 | 3 | 4) || !(1..=1000).contains(&samples) {
        return Err("generation requires N1/N3/N4 and 1..1000 samples".into());
    }
    let setup = seed(
        opts.get("--setup-seed")
            .unwrap_or(&"1111111111111111111111111111111111111111111111111111111111111111"),
    )?;
    let context = seed(
        opts.get("--context")
            .unwrap_or(&"2222222222222222222222222222222222222222222222222222222222222222"),
    )?;
    let config = Configuration {
        aes_lanes: lanes,
        cache_public_parameters: cache,
        ..Configuration::default()
    };
    let mut records = Vec::with_capacity(samples);
    for sample in 0..samples {
        let start = Instant::now();
        let mut owner = if reuse {
            Some(Generator::new(setup, context, config)?)
        } else {
            None
        };
        let mut outputs = Vec::with_capacity(count);
        for ordinal in 0..count {
            let tx_start = Instant::now();
            if owner.is_none() {
                owner = Some(Generator::new(setup, context, config)?);
            }
            let index = (sample * count + ordinal) as u64;
            let output = owner.as_mut().unwrap().generate(
                index % native::RING_PAIRS,
                FixtureAmounts {
                    input: [7 + index, 11],
                    output: [9, 9 + index],
                },
            )?;
            let verification = Instant::now();
            if !native::verify(&context, &output.statement, &output.proof)? {
                return Err("independent CPU verification rejected generated spend".into());
            }
            let verification_ns = nanos(verification);
            if !reuse {
                drop(owner.take());
            }
            let elapsed_ns = nanos(tx_start);
            outputs.push((output, verification_ns, elapsed_ns));
        }
        drop(owner); // Private state already wiped; public workspace retirement is timed too.
        let whole_stage_ns = nanos(start);
        // Hash/report construction is outside the generation stage. Public
        // output is retained as it would be for downstream metadata planning.
        let transactions: Vec<Value> = outputs
            .into_iter()
            .map(|(out, verification, elapsed)| {
                let mut digest = Sha3_256::new();
                digest.update(&out.statement);
                digest.update(&out.proof);
                json!({"whole_transaction_ns":elapsed,"generation_ns":out.generation_ns,
                "verification_ns":verification,"statistics":out.statistics,
                "output_sha3_256":hex(&digest.finalize()),"verified":true})
            })
            .collect();
        records.push(
            json!({"sample":sample,"whole_stage_ns":whole_stage_ns,"transactions":transactions}),
        );
    }
    let report = json!({"schema":"lattica-cpu-generation-profile-v1", "backend":"cpu",
        "private_entropy":"os-fresh", "gpu_contexts":0, "gpu_generation_calls":0,
        "recursive_workflow_started":false,"transactions":count,"samples":samples,
        "setup_seed":hex(&setup),"context":hex(&context),"aes_lanes":lanes,
        "cache_public_parameters":cache,"reuse_workspace":reuse,"context_lifetime":"cold-per-sample",
        "workspace_bytes":Generator::allocation_bytes()?,"records":records});
    println!("CPU_GENERATION_PROFILE {report}");
    Ok(())
}
