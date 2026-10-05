//! Component timings only: these are not proof throughput measurements.
use lattica_prover_p3::cpu_sme2::{self, MODULUS};
use p3_field::{Field, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use std::{hint::black_box, time::Instant};

fn main() -> Result<(), String> {
    let mut backend = "all".to_owned();
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--backend" => backend = args.next().ok_or("missing backend")?,
            "--out" => out = Some(args.next().ok_or("missing output path")?),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if !["all", "scalar", "p3", "sme2"].contains(&backend.as_str()) {
        return Err("backend must be all, scalar, p3, or sme2".into());
    }
    let lanes = if backend == "all" || backend == "sme2" {
        Some(cpu_sme2::streaming_lanes()?)
    } else {
        None
    };
    type Packing = <Goldilocks as Field>::Packing;
    let mut records = Vec::new();
    for n in [32, 1024, 65536, 1048576] {
        let a: Vec<u64> = (0..n)
            .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % MODULUS)
            .collect();
        let b: Vec<u64> = (0..n)
            .map(|i| (i as u64 + 7).wrapping_mul(0xd1b54a32d192ed03) % MODULUS)
            .collect();
        let fa: Vec<_> = a.iter().map(|&x| Goldilocks::from_u64(x)).collect();
        let fb: Vec<_> = b.iter().map(|&x| Goldilocks::from_u64(x)).collect();
        let mut field_out = vec![Goldilocks::ZERO; n];
        let mut integer_out = vec![0u64; n];
        let expected: Vec<_> = a
            .iter()
            .zip(&b)
            .map(|(&x, &y)| ((x as u128 * y as u128) % MODULUS as u128) as u64)
            .collect();
        let iterations = (16_777_216 / n).max(8);
        for repeat in 0..7 {
            let order = if repeat % 2 == 0 {
                ["scalar", "p3", "sme2"]
            } else {
                ["sme2", "p3", "scalar"]
            };
            for selected in order {
                if backend != "all" && backend != selected {
                    continue;
                }
                let mut run = || match selected {
                    "scalar" => {
                        for ((x, y), o) in black_box(&a)
                            .iter()
                            .zip(black_box(&b))
                            .zip(black_box(&mut integer_out))
                        {
                            *o = ((*x as u128 * *y as u128) % MODULUS as u128) as u64;
                        }
                    }
                    "p3" => {
                        for ((x, y), o) in black_box(&fa)
                            .chunks_exact(Packing::WIDTH)
                            .zip(black_box(&fb).chunks_exact(Packing::WIDTH))
                            .zip(black_box(&mut field_out).chunks_exact_mut(Packing::WIDTH))
                        {
                            *Packing::from_slice_mut(o) =
                                *Packing::from_slice(x) * *Packing::from_slice(y);
                        }
                    }
                    "sme2" => cpu_sme2::multiply(
                        black_box(&a),
                        black_box(&b),
                        black_box(&mut integer_out),
                    )
                    .unwrap(),
                    _ => unreachable!(),
                };
                run(); // Warm-up, excluded from all samples.
                let start = Instant::now();
                for _ in 0..iterations {
                    run();
                }
                let elapsed = start.elapsed();
                if selected == "p3" {
                    for (value, expected) in field_out.iter().zip(&expected) {
                        assert_eq!(value.as_canonical_u64(), *expected);
                    }
                } else {
                    assert_eq!(integer_out, expected);
                }
                records.push(serde_json::json!({"backend": selected, "elements":n, "iterations":iterations,
                    "repeat":repeat+1, "elapsed_ns":elapsed.as_nanos().to_string(),
                    "ns_per_element":elapsed.as_secs_f64()*1e9/(n*iterations) as f64, "verified":true}));
                eprintln!(
                    "PASS {selected} elements={n} repeat={} {:.3} ns/element",
                    repeat + 1,
                    elapsed.as_secs_f64() * 1e9 / (n * iterations) as f64
                );
            }
        }
    }
    let report = serde_json::json!({"schema":"apple-field-component-v1", "status":"PASS", "kind":"component",
        "operation":"exact canonical Goldilocks multiplication", "cpu_threads":1,
        "sme2_available":cpu_sme2::available(), "streaming_u64_lanes":lanes,
        "p3_packing_width":Packing::WIDTH, "samples":records,
        "limitations":["Component experiment; no prover backend change or proof-throughput claim.",
            "Allocations, input conversion and output verification are outside timed loops; SME streaming transitions and C ABI calls are inside.",
            "Scalar u128 modular reduction is the correctness oracle, not the optimized CPU baseline; use Plonky3 packing for that comparison."]});
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    if let Some(path) = out {
        std::fs::write(path, json + "\n").map_err(|e| e.to_string())?;
    } else {
        println!("{json}");
    }
    Ok(())
}
