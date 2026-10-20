//! Public fixtures exercise the maintained ABI and Rust routes. The saved
//! artifacts are independently checked by a separate CPU-only test image.
use crate::config::Val;
use crate::{
    batch_htlc_air as bh, batch_joinsplit_air as bj, htlc_air as htlc, joinsplit_air as js,
};
use p3_field::PrimeCharacteristicRing;

fn directory() -> std::path::PathBuf {
    let path =
        std::path::PathBuf::from(std::env::var_os("LATTICA_CUDA_BATCH_ARTIFACT_DIR").unwrap());
    assert!(path.is_absolute() && path.is_dir());
    path
}
fn joinsplits(count: usize) -> Vec<js::Witness> {
    (0..count)
        .map(|i| {
            let mut w = js::demo_witness();
            w.tx_binding = [
                Val::from_u64(i as u64 + 7),
                Val::ONE,
                Val::ZERO,
                Val::from_u64(19),
            ];
            w
        })
        .collect()
}
fn htlcs(count: usize) -> Vec<htlc::Witness> {
    (0..count)
        .map(|i| {
            let mut w = htlc::demo_htlc_witness();
            w.tx_binding = [
                Val::from_u64(i as u64 + 11),
                Val::ZERO,
                Val::ONE,
                Val::from_u64(29),
            ];
            w
        })
        .collect()
}
fn verify(kind: usize, count: usize, proof: &[u8], root: &[Val]) -> bool {
    match kind {
        0 => bj::verify_batch_bytes(proof, root),
        1 => bh::verify_batch_bytes(proof, root),
        2 => crate::verify_joinsplit_tree_bytes(proof, root, count),
        _ => panic!("unknown fixture"),
    }
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda")))]
#[ignore = "separate CPU-only auditor for saved CUDA batch/tree artifacts"]
fn saved_cuda_batch_tree_outputs_pass_cpu_audit() {
    assert_eq!(
        crate::proving::Request::from_env().unwrap().policy,
        crate::proving::Policy::CpuRequired
    );
    assert!(std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_none());
    let dir = directory();
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(dir.join("cases.json")).unwrap()).unwrap();
    assert_eq!(cases.len(), 11);
    for (index, case) in cases.iter().enumerate() {
        let kind = case["kind"].as_u64().unwrap() as usize;
        let count = case["count"].as_u64().unwrap() as usize;
        let proof = std::fs::read(dir.join(format!("{index}.proof"))).unwrap();
        let root =
            crate::parse_root_digest(&std::fs::read(dir.join(format!("{index}.root"))).unwrap())
                .unwrap();
        let expected = if kind == 1 {
            bh::batch_root(&htlcs(count))
        } else {
            bj::batch_root(&joinsplits(count))
        };
        assert_eq!(root, expected);
        assert!(verify(kind, count, &proof, &root));
        let mut changed_root = root.clone();
        changed_root[0] += Val::ONE;
        assert!(!verify(kind, count, &proof, &changed_root));
        let mut changed = proof.clone();
        if kind == 2 {
            // Alter a public leaf, preserving the container's framing.
            changed[crate::TREE_MAGIC.len() + 4 + crate::DIGEST_BYTES] ^= 1;
            assert!(!verify(kind, count + 1, &proof, &root));
            if count > 1 {
                let start = crate::TREE_MAGIC.len() + 4 + crate::DIGEST_BYTES;
                let end = |at: usize| {
                    let length_at = at + crate::JS_PUBLIC_INPUTS_LEN;
                    length_at
                        + 4
                        + u32::from_le_bytes(proof[length_at..length_at + 4].try_into().unwrap())
                            as usize
                };
                let first = end(start);
                let second = end(first);
                let mut swapped = proof[..start].to_vec();
                swapped.extend_from_slice(&proof[first..second]);
                swapped.extend_from_slice(&proof[start..first]);
                swapped.extend_from_slice(&proof[second..]);
                assert!(!verify(kind, count, &swapped, &root));
            }
        } else {
            let mut decoded: p3_uni_stark::Proof<crate::config::MyConfig> =
                postcard::from_bytes(&proof).unwrap();
            decoded.opened_values.trace_local[0] += crate::config::Challenge::ONE;
            changed = postcard::to_allocvec(&decoded).unwrap();
        }
        assert!(!verify(kind, count, &changed, &root));
    }
    assert_ne!(
        std::fs::read(dir.join("9.proof")).unwrap(),
        std::fs::read(dir.join("10.proof")).unwrap()
    );
    eprintln!("cuda_batch_tree_cpu_audit accepted=11 altered_statements_rejected=11 altered_proofs_rejected=11 altered_counts_rejected=3 altered_orders_rejected=2");
}

#[test]
#[cfg(feature = "gpu-cuda")]
#[ignore = "release native CUDA wallet service with 7 GiB managed GPU and 3 GiB host caps"]
fn native_cuda_batch_tree_routes_preserve_admission_and_wire_formats() {
    use crate::{
        block_v2::cuda_wallet,
        proving::{CoverageScope, Policy, Request},
    };
    use cuda_wallet::tests::{snapshot, Boundary};
    type Abi = unsafe extern "C" fn(
        *const u8,
        usize,
        usize,
        *mut u8,
        usize,
        *mut usize,
        *mut u8,
        usize,
        *mut usize,
    ) -> i32;
    let functions: [Abi; 3] = [
        crate::lattica_batch_prove,
        crate::lattica_htlc_batch_prove,
        crate::lattica_joinsplit_tree_prove,
    ];
    let cases = [
        (0, 1, "abi"),
        (0, 3, "abi"),
        (1, 1, "abi"),
        (1, 3, "abi"),
        (0, 0, "rust"),
        (1, 0, "rust"),
        (0, 8, "rust"),
        (1, 8, "rust"),
        (2, 1, "abi"),
        (2, 3, "abi"),
        (2, 3, "rust"),
    ];
    let expected: Vec<_> = cases
        .iter()
        .map(|&(kind, count, _)| {
            if kind == 1 {
                bh::batch_root(&htlcs(count))
            } else {
                bj::batch_root(&joinsplits(count))
            }
        })
        .collect();
    let js_inputs: Vec<_> = (0..9).map(joinsplits).collect();
    let ht_inputs: Vec<_> = (0..9).map(htlcs).collect();
    let encoded_js: Vec<Vec<u8>> = js_inputs
        .iter()
        .map(|ws| {
            ws.iter()
                .flat_map(crate::encode_joinsplit_witness)
                .collect()
        })
        .collect();
    let encoded_ht: Vec<Vec<u8>> = ht_inputs
        .iter()
        .map(|ws| ws.iter().flat_map(crate::encode_htlc_witness).collect())
        .collect();
    let mut invalid = joinsplits(2);
    invalid[1].fee += 1;
    let invalid: Vec<_> = invalid
        .iter()
        .flat_map(crate::encode_joinsplit_witness)
        .collect();
    let dir = directory();
    assert!(!dir.join("cases.json").exists());
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 0);
    let probe = Boundary::new();
    let before = crate::proving::cpu_witness_oracle_calls();
    // Every native route rejects a forbidden public assignment and a policy
    // downgrade before reaching the private parser or modifying outputs.
    for (variable, value) in [
        ("LATTICA_V2_WORKER_BUDGET", "/forbidden-public-worker"),
        ("LATTICA_PROVING_POLICY", "compatible"),
    ] {
        let old = std::env::var_os(variable);
        std::env::set_var(variable, value);
        let baseline = snapshot();
        let decoded = probe.calls();
        for (kind, call) in functions.iter().enumerate() {
            let input = if kind == 1 {
                &encoded_ht[1]
            } else {
                &encoded_js[1]
            };
            let mut proof = [0xa5; 8];
            let mut root = [0xa5; 32];
            let (mut pl, mut rl) = (123, 123);
            assert_eq!(
                unsafe {
                    call(
                        input.as_ptr(),
                        input.len(),
                        1,
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut pl,
                        root.as_mut_ptr(),
                        root.len(),
                        &mut rl,
                    )
                },
                1
            );
            assert_eq!((proof, root, pl, rl), ([0xa5; 8], [0xa5; 32], 123, 123));
        }
        assert_eq!(probe.calls(), decoded);
        assert_eq!(snapshot(), baseline);
        match old {
            Some(old) => std::env::set_var(variable, old),
            None => std::env::remove_var(variable),
        }
    }
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    };
    let mut records = Vec::new();
    for (index, &(kind, count, api)) in cases.iter().enumerate() {
        eprintln!("cuda_batch_tree_case_begin index={index} kind={kind} count={count} api={api}");
        let decoded = probe.calls();
        let (proof, root) = if api == "abi" {
            let input = if kind == 1 {
                &encoded_ht[count]
            } else {
                &encoded_js[count]
            };
            let capacity = if kind == 2 {
                44 + count * (crate::MAX_PROOF_LEN + crate::JS_PUBLIC_INPUTS_LEN + 4)
            } else {
                crate::MAX_PROOF_LEN
            };
            let mut proof = vec![0xa5; capacity];
            let mut root = [0xa5; 32];
            let (mut pl, mut rl) = (123, 123);
            assert_eq!(
                unsafe {
                    functions[kind](
                        input.as_ptr(),
                        input.len(),
                        count,
                        proof.as_mut_ptr(),
                        proof.len(),
                        &mut pl,
                        root.as_mut_ptr(),
                        root.len(),
                        &mut rl,
                    )
                },
                0,
                "case {index}"
            );
            assert_eq!(rl, 32);
            proof.truncate(pl);
            assert_eq!(probe.calls() - decoded, count);
            (proof, root.to_vec())
        } else if kind == 2 {
            let output = cuda_wallet::prove_joinsplit_tree(&js_inputs[count], request).unwrap();
            assert!(output.report.stage_coverage_complete);
            assert_eq!(output.report.capabilities.scope(), CoverageScope::Operation);
            (output.proof, crate::encode_digest(&output.root))
        } else {
            let (proof, report) = if kind == 0 {
                bj::prove_batch_to_bytes_with_request(&js_inputs[count], request)
            } else {
                bh::prove_batch_to_bytes_with_request(&ht_inputs[count], request)
            }
            .unwrap();
            assert!(report.stage_coverage_complete);
            assert_eq!(report.capabilities.scope(), CoverageScope::ProofRequest);
            assert_eq!(report.capabilities.stages().len(), 14);
            (proof, crate::encode_digest(&expected[index]))
        };
        assert_eq!(root, crate::encode_digest(&expected[index]));
        assert_eq!(crate::proving::cpu_witness_oracle_calls(), before);
        std::fs::write(dir.join(format!("{index}.proof")), proof).unwrap();
        std::fs::write(dir.join(format!("{index}.root")), root).unwrap();
        records.push(serde_json::json!({"kind":kind,"count":count,"api":api}));
        eprintln!("cuda_batch_tree_case_complete index={index}");
    }
    // Failed proving and insufficient caller capacity must leave every output
    // byte and both lengths unchanged, then release the calling-thread guard.
    // End with a prepared batch still cached, so shutdown also covers its
    // retained public program and periodic buffers.
    for kind in [2usize, 0] {
        let mut proof = [0xa5; 8];
        let mut root = [0xa5; 32];
        let (mut pl, mut rl) = (123, 123);
        assert_eq!(
            unsafe {
                functions[kind](
                    invalid.as_ptr(),
                    invalid.len(),
                    2,
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut pl,
                    root.as_mut_ptr(),
                    root.len(),
                    &mut rl,
                )
            },
            1
        );
        assert_eq!((proof, root, pl, rl), ([0xa5; 8], [0xa5; 32], 123, 123));
        let input = &encoded_js[1];
        assert_eq!(
            unsafe {
                functions[kind](
                    input.as_ptr(),
                    input.len(),
                    1,
                    proof.as_mut_ptr(),
                    proof.len(),
                    &mut pl,
                    root.as_mut_ptr(),
                    root.len(),
                    &mut rl,
                )
            },
            2
        );
        assert_eq!((proof, root, pl, rl), ([0xa5; 8], [0xa5; 32], 123, 123));
    }
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), before);
    std::fs::write(
        dir.join("cases.json"),
        serde_json::to_vec_pretty(&records).unwrap(),
    )
    .unwrap();
    let measured = snapshot();
    drop(probe);
    assert_eq!(crate::native_gpu::lattica_gpu_drain(), 0);
    assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 0);
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 1);
    assert!(std::thread::spawn(|| cuda_wallet::abi_admission().is_err())
        .join()
        .unwrap());
    std::fs::write(dir.join("measurements.json"),serde_json::to_vec_pretty(&serde_json::json!({"saved_outputs":records.len(),"managed_peak_bytes":measured.peak_bytes,"cpu_witness_oracle_calls":0})).unwrap()).unwrap();
    eprintln!(
        "native_cuda_batch_tree_qualified saved_outputs=11 cpu_witness_oracle_calls=0 retired=true"
    );
}
