use super::*;
use crate::block_v2::{recursive::WalletProof, typed_fixture};
use p3_symmetric::MerkleCap;
use serde_json::Value;

fn wallets() -> [WalletProof; 3] {
    [0, 1, 3].map(|index| typed_fixture::wallet(index).unwrap().0)
}

fn by_mode(wallets: &[WalletProof; 3], mode: u64) -> &WalletProof {
    &wallets[match mode {
        WRAPPER => 0,
        typed_programs::HTLC => 1,
        typed_programs::ISSUANCE => 2,
        _ => panic!("unexpected leaf mode"),
    }]
}

fn caps() -> typed_pairs::Caps {
    core::array::from_fn(|key| {
        (0..1 << profile::CAP_HEIGHT)
            .map(|row| {
                core::array::from_fn(|column| Val::from_usize(1 + key * 1024 + row * 4 + column))
            })
            .collect()
    })
}

fn prefix(height: usize, keys: usize) -> RegistryPrefix<'static> {
    RegistryPrefix::with_hash(height, keys, &mut |d, f| {
        commitment::hash_fields(d, f).map_err(|_| ERROR)
    })
    .unwrap()
}

fn copy(proof: &Proof<Config>) -> Proof<Config> {
    serde_json::from_value(serde_json::to_value(proof).unwrap()).unwrap()
}

fn colored(proof: &Proof<Config>, seed: u64) -> Proof<Config> {
    fn paint(value: &mut Value, counter: &mut u64) {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    if !matches!(key.as_str(), "degree_bits" | "log_arity") {
                        paint(child, counter);
                    }
                }
            }
            Value::Array(values) => {
                for child in values {
                    paint(child, counter);
                }
            }
            Value::Number(number) => {
                *counter += 1;
                *number = (*counter).into();
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(proof).unwrap();
    paint(&mut value, &mut (seed * 100000));
    serde_json::from_value(value).unwrap()
}

fn order_cases(height: usize) {
    let wallets = wallets();
    let caps = caps();
    let prefix = prefix(height, 12);
    for (mode, kinds) in typed_pairs::PAIRS {
        let shape = Shape::from_prefix(&prefix, height, mode).unwrap();
        let source = kinds.map(|kind| by_mode(&wallets, kind));
        let mut previous: Option<Compiled> = None;
        for seed in [17u64, 53] {
            let public: [Vec<Val>; 2] = core::array::from_fn(|slot| {
                (0..source[slot].public.len())
                    .map(|i| Val::from_u64(seed * 1000 + (slot * 100 + i) as u64))
                    .collect()
            });
            let proofs: [Proof<Config>; 2] =
                core::array::from_fn(|slot| colored(&source[slot].proof, seed + slot as u64));
            let inputs = [
                (public[0].as_slice(), &proofs[0]),
                (public[1].as_slice(), &proofs[1]),
            ];
            let compiled = typed_pairs::wrapper_pair_with_registry(
                height,
                &caps,
                mode,
                [&public[0], &public[1]],
                [&proofs[0], &proofs[1]],
                Some(&prefix),
            )
            .unwrap();
            let count = compiled.program.witness_values();
            let bytes = count * core::mem::size_of::<Val>();
            let bound = bind(&shape, &caps, inputs, count, bytes).unwrap();
            assert_eq!(bound, compiled.witness);
            assert_eq!(bound.capacity(), count);
            check_witness(&shape, &caps, inputs, &compiled.witness, bytes).unwrap();
            let mut wrong = compiled.witness.clone();
            wrong[count / 2] += Val::ONE;
            assert!(check_witness(&shape, &caps, inputs, &wrong, bytes).is_err());
            if let Some(old) = previous.take() {
                assert_eq!(
                    compiled.program, old.program,
                    "program depends on proof values"
                );
                assert_ne!(
                    compiled.witness, old.witness,
                    "witness values were retained"
                );
            }
            eprintln!("paired_input_order height={height} mode={mode} seed={seed} values={count} bytes={bytes}");
            previous = Some(compiled);
        }
    }
}

#[test]
fn binding_matches_all_nine_ordered_pair_compilers() {
    order_cases(2048);
}

#[test]
fn binding_matches_all_full_size_pair_compilers() {
    order_cases(1 << 21);
}

#[test]
fn trusted_pair_prefix_rejects_wrong_height_key_count_and_mode() {
    let p = prefix(2048, 12);
    for (mode, _) in typed_pairs::PAIRS {
        assert!(Shape::from_prefix(&p, 2048, mode).is_ok());
        assert!(Shape::from_prefix(&p, 4096, mode).is_err());
        assert!(Shape::from_prefix(&prefix(2048, 6), 2048, mode).is_err());
    }
    for mode in [0, EMPTY, MERGE, typed_pairs::FINALIZE, 13, u64::MAX] {
        assert!(Shape::from_prefix(&p, 2048, mode).is_err());
    }
}

#[test]
fn pair_binding_rejects_each_independent_budget_and_input_count() {
    let wallets = wallets();
    let caps = caps();
    let p = prefix(2048, 12);
    let shape = Shape::from_prefix(&p, 2048, 4).unwrap();
    let input = [
        (&wallets[0].public[..], &wallets[0].proof),
        (&wallets[1].public[..], &wallets[1].proof),
    ];
    let compiled = typed_pairs::wrapper_pair_with_registry(
        2048,
        &caps,
        4,
        [input[0].0, input[1].0],
        [input[0].1, input[1].1],
        Some(&p),
    )
    .unwrap();
    let count = compiled.witness.len();
    let bytes = count * core::mem::size_of::<Val>();
    for (expected, limit) in [
        (count, bytes - 1),
        (count, 0),
        (count - 1, bytes),
        (count + 1, bytes + 8),
        (usize::MAX, usize::MAX),
    ] {
        assert!(bind(&shape, &caps, input, expected, limit).is_err());
    }
    assert!(check_witness(&shape, &caps, input, &compiled.witness, bytes - 1).is_err());
    assert!(check_witness(&shape, &caps, input, &compiled.witness[..count - 1], bytes).is_err());
    let mut bad_caps = caps.clone();
    bad_caps[0].pop();
    assert!(bind(&shape, &bad_caps, input, count, bytes).is_err());
    let mut public = wallets[0].public.clone();
    public.pop();
    assert!(bind(
        &shape,
        &caps,
        [(&public, input[0].1), input[1]],
        count,
        bytes
    )
    .is_err());
    assert!(bind(
        &shape,
        &caps,
        [input[0], (&public, input[1].1)],
        count,
        bytes
    )
    .is_err());
    let changed = colored(input[1].1, 71);
    let fresh = bind(
        &shape,
        &caps,
        [input[0], (input[1].0, &changed)],
        count,
        bytes,
    )
    .unwrap();
    assert_ne!(
        fresh, compiled.witness,
        "right slot cannot reuse stale values, including padding"
    );
}

#[test]
fn malformed_uni_and_pcs_shapes_rejected_in_both_pair_slots() {
    let wallets = wallets();
    let caps = caps();
    let p = prefix(2048, 12);
    let mutations: &[fn(&mut Proof<Config>)] = &[
        |p| p.degree_bits += 1,
        |p| {
            p.opened_values.trace_local.pop();
        },
        |p| {
            p.opened_values.trace_next = if p.opened_values.trace_next.is_some() {
                None
            } else {
                Some(vec![])
            }
        },
        |p| p.opened_values.preprocessed_local = Some(vec![]),
        |p| p.opened_values.preprocessed_next = Some(vec![]),
        |p| {
            p.opened_values.quotient_chunks.pop();
        },
        |p| {
            p.opened_values.quotient_chunks[0].pop();
        },
        |p| p.opened_values.random = None,
        |p| {
            p.opened_values.random.as_mut().unwrap().pop();
        },
        |p| p.commitments.random = None,
        |p| p.commitments.trace = MerkleCap::new(vec![[Val::ZERO; 4]]),
        |p| p.commitments.quotient_chunks = MerkleCap::new(vec![[Val::ZERO; 4]]),
        |p| p.commitments.random = Some(MerkleCap::new(vec![[Val::ZERO; 4]])),
        |p| {
            p.opening_proof.0.pop();
        },
        |p| {
            p.opening_proof.0[0].pop();
        },
        |p| {
            p.opening_proof.0[0][0].pop();
        },
        |p| {
            p.opening_proof.0[0][0][0].pop();
        },
        |p| {
            p.opening_proof.1.commit_phase_commits.pop();
        },
        |p| p.opening_proof.1.commit_phase_commits[0] = MerkleCap::new(vec![[Val::ZERO; 4]]),
        |p| {
            p.opening_proof.1.commit_pow_witnesses.pop();
        },
        |p| {
            p.opening_proof.1.final_poly.pop();
        },
        |p| {
            p.opening_proof.1.query_proofs.pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].input_proof.pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].input_proof[0]
                .opened_values
                .pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0].pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .0
                .pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .0[0]
                .pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .1
                .pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0]
                .commit_phase_openings
                .pop();
        },
        |p| p.opening_proof.1.query_proofs[0].commit_phase_openings[0].log_arity = 2,
        |p| {
            p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .sibling_values
                .pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .opening_proof
                .0
                .pop();
        },
        |p| {
            p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .opening_proof
                .1
                .pop();
        },
    ];
    for mode in [4, 8] {
        let kinds = typed_pairs::leaf_modes(mode).unwrap();
        let w = kinds.map(|kind| by_mode(&wallets, kind));
        let shape = Shape::from_prefix(&p, 2048, mode).unwrap();
        let compiled = typed_pairs::wrapper_pair_with_registry(
            2048,
            &caps,
            mode,
            [&w[0].public, &w[1].public],
            [&w[0].proof, &w[1].proof],
            Some(&p),
        )
        .unwrap();
        let count = compiled.witness.len();
        for slot in 0..2 {
            for (case, mutate) in mutations.iter().enumerate() {
                let mut proof = copy(&w[slot].proof);
                mutate(&mut proof);
                let mut inputs = [
                    (&w[0].public[..], &w[0].proof),
                    (&w[1].public[..], &w[1].proof),
                ];
                inputs[slot].1 = &proof;
                assert!(
                    bind(&shape, &caps, inputs, count, count * 8).is_err(),
                    "mode={mode} slot={slot} case={case}"
                );
            }
        }
    }
    eprintln!(
        "paired_binding_malformed_rejections={}",
        mutations.len() * 4
    );
}
