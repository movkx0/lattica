use super::super::super::{typed_finalizer, typed_pairs};
use super::*;
use serde_json::Value;
use std::time::Instant;

fn colored(proof: &BatchProof<Config>, seed: u64) -> BatchProof<Config> {
    fn visit(value: &mut Value, counter: &mut u64) {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    if !matches!(key.as_str(), "degree_bits" | "log_arity") {
                        visit(child, counter);
                    }
                }
            }
            Value::Array(values) => {
                for child in values {
                    visit(child, counter);
                }
            }
            Value::Number(_) => {
                *counter += 1;
                *value = Value::from(*counter);
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(proof).unwrap();
    visit(&mut value, &mut (seed * 1_000_000));
    serde_json::from_value(value).unwrap()
}

fn caps<const N: usize>(seed: u64) -> Caps<N> {
    core::array::from_fn(|key| {
        (0..1 << profile::CAP_HEIGHT)
            .map(|row| {
                core::array::from_fn(|col| {
                    Val::from_u64(seed + (key * 1024 + row * 4 + col) as u64)
                })
            })
            .collect()
    })
}

fn statements(seed: u64) -> [[Val; PUBLIC_VALUES]; 2] {
    core::array::from_fn(|child| {
        core::array::from_fn(|field| Val::from_u64(seed + (child * 100 + field) as u64))
    })
}

fn compile<const N: usize>(
    height: usize,
    caps: &Caps<N>,
    public: &[[Val; PUBLIC_VALUES]; 2],
    proofs: &[BatchProof<Config>; 2],
    finalize: bool,
) -> Compiled {
    if !finalize {
        merge(
            height,
            caps,
            [&public[0], &public[1]],
            [&proofs[0], &proofs[1]],
        )
        .unwrap()
    } else if N == 6 {
        typed_finalizer::compile(
            height,
            caps.as_slice().try_into().unwrap(),
            &public[0],
            &proofs[0],
        )
        .unwrap()
    } else {
        assert_eq!(N, 12);
        typed_pairs::finalize(
            height,
            caps.as_slice().try_into().unwrap(),
            &public[0],
            &proofs[0],
        )
        .unwrap()
    }
}

fn order_cases<const N: usize>(height: usize, finalize: bool) {
    let shape = Shape::new(height).unwrap();
    let template = verifier::template::batch(&super::shape(height).unwrap()).unwrap();
    let mut previous: Option<Compiled> = None;
    for seed in [17, 53] {
        let caps = caps::<N>(seed);
        let public = statements(seed);
        let proofs = [colored(&template, seed), colored(&template, seed + 1)];
        let compiled = compile(height, &caps, &public, &proofs, finalize);
        let children = [(&public[0], &proofs[0]), (&public[1], &proofs[1])];
        let children = &children[..if finalize { 1 } else { 2 }];
        let count = compiled.program.witness_values();
        let exact = count * core::mem::size_of::<Val>();
        let bound = bind(&shape, &caps, children, count, exact).unwrap();
        assert_eq!(bound, compiled.witness);
        check_witness(&shape, &caps, children, &compiled.witness, exact).unwrap();
        assert!(check_witness(&shape, &caps, children, &compiled.witness, exact - 1).is_err());
        let mut wrong = compiled.witness.clone();
        wrong[count / 2] += Val::ONE;
        assert!(check_witness(&shape, &caps, children, &wrong, exact).is_err());
        assert_eq!(bound.capacity(), count);
        assert!(bind(&shape, &caps, children, count, exact - 1).is_err());
        if let Some(previous) = previous.take() {
            assert_eq!(
                compiled.program, previous.program,
                "public program depends on witness values"
            );
            assert_ne!(
                compiled.witness, previous.witness,
                "new inputs reused an old witness"
            );
        }
        eprintln!("recursive_input_order keys={N} height={height} finalize={finalize} seed={seed} values={count} bytes={exact}");
        previous = Some(compiled);
    }
}

#[test]
fn binding_matches_all_typed_recursive_registry_compilers() {
    order_cases::<5>(2048, false);
    order_cases::<6>(2048, false);
    order_cases::<6>(2048, true);
    order_cases::<12>(2048, false);
    order_cases::<12>(2048, true);
}

#[test]
fn trusted_prefix_rejects_foreign_height_and_registry_size() {
    let prefix = RegistryPrefix::with_hash(2048, 12, &mut |d, f| {
        commitment::hash_fields(d, f).map_err(|_| CompileError::Shape("test hash"))
    })
    .unwrap();
    assert!(Shape::from_prefix(&prefix, 2048, 12).is_ok());
    assert!(Shape::from_prefix(&prefix, 4096, 12).is_err());
    assert!(Shape::from_prefix(&prefix, 2048, 6).is_err());
}

#[test]
fn binding_matches_full_size_merge_and_finalizer_compilers() {
    order_cases::<12>(1 << 18, false);
    order_cases::<12>(1 << 18, true);
}

#[test]
fn binding_rejects_shape_and_budget_changes_before_returning_values() {
    let height = 2048;
    let shape = Shape::new(height).unwrap();
    let proof = verifier::template::batch(&super::shape(height).unwrap()).unwrap();
    let caps = caps::<12>(7);
    let public = statements(11);
    let mut count = 12 * (1 << profile::CAP_HEIGHT) * 4 + PUBLIC_VALUES;
    shape
        .walk(&proof, |values| {
            count += values.len();
            Ok(())
        })
        .unwrap();
    let bytes = count * core::mem::size_of::<Val>();
    let children = [(&public[0], &proof)];
    assert!(bind(&shape, &caps, &children, count, bytes).is_ok());
    for (expected, budget) in [
        (count - 1, bytes),
        (count + 1, bytes),
        (count, bytes - 1),
        (usize::MAX, usize::MAX),
        (count, 0),
    ] {
        assert!(bind(&shape, &caps, &children, expected, budget).is_err());
    }
    assert!(bind(&shape, &caps, &[], count, bytes).is_err());
    assert!(bind(&shape, &caps, &[children[0]; 3], count, bytes).is_err());
    assert!(bind(
        &Shape::new(height * 2).unwrap(),
        &caps,
        &children,
        count,
        bytes
    )
    .is_err());
    let mut bad_caps = caps.clone();
    bad_caps[0].pop();
    assert!(bind(&shape, &bad_caps, &children, count, bytes).is_err());

    type Mutation = (&'static str, Box<dyn Fn(&mut BatchProof<Config>)>);
    let changes: Vec<Mutation> = vec![
        ("degree", Box::new(|p| p.degree_bits[0] += 1)),
        ("instances", Box::new(|p| p.opened_values.instances.clear())),
        ("terminals", Box::new(|p| p.lookup_terminals.clear())),
        (
            "terminal presence",
            Box::new(|p| p.lookup_terminals[0] = None),
        ),
        (
            "main cap",
            Box::new(|p| p.commitments.main = p3_symmetric::MerkleCap::new(vec![[Val::ZERO; 4]])),
        ),
        ("random cap", Box::new(|p| p.commitments.random = None)),
        (
            "permutation cap",
            Box::new(|p| p.commitments.permutation = None),
        ),
        (
            "trace width",
            Box::new(|p| {
                p.opened_values.instances[0]
                    .base_opened_values
                    .trace_local
                    .pop();
            }),
        ),
        (
            "trace next",
            Box::new(|p| p.opened_values.instances[0].base_opened_values.trace_next = Some(vec![])),
        ),
        (
            "preprocessed presence",
            Box::new(|p| {
                p.opened_values.instances[0]
                    .base_opened_values
                    .preprocessed_local = None
            }),
        ),
        (
            "preprocessed next",
            Box::new(|p| {
                p.opened_values.instances[0]
                    .base_opened_values
                    .preprocessed_next = Some(vec![])
            }),
        ),
        (
            "random openings",
            Box::new(|p| p.opened_values.instances[0].base_opened_values.random = None),
        ),
        (
            "quotient count",
            Box::new(|p| {
                p.opened_values.instances[0]
                    .base_opened_values
                    .quotient_chunks
                    .pop();
            }),
        ),
        (
            "quotient width",
            Box::new(|p| {
                p.opened_values.instances[0]
                    .base_opened_values
                    .quotient_chunks[0]
                    .pop();
            }),
        ),
        (
            "permutation width",
            Box::new(|p| {
                p.opened_values.instances[0].permutation_next.pop();
            }),
        ),
        (
            "random rounds",
            Box::new(|p| {
                p.opening_proof.0.pop();
            }),
        ),
        (
            "random matrices",
            Box::new(|p| {
                p.opening_proof.0[0].pop();
            }),
        ),
        (
            "random points",
            Box::new(|p| {
                p.opening_proof.0[4][0].pop();
            }),
        ),
        (
            "random width",
            Box::new(|p| {
                p.opening_proof.0[0][0][0].pop();
            }),
        ),
        (
            "preprocessed randomness",
            Box::new(|p| p.opening_proof.0[3][0][0].push(profile::Challenge::ZERO)),
        ),
        (
            "FRI commit count",
            Box::new(|p| {
                p.opening_proof.1.commit_phase_commits.pop();
            }),
        ),
        (
            "FRI cap",
            Box::new(|p| {
                p.opening_proof.1.commit_phase_commits[0] =
                    p3_symmetric::MerkleCap::new(vec![[Val::ZERO; 4]])
            }),
        ),
        (
            "FRI commit PoW count",
            Box::new(|p| {
                p.opening_proof.1.commit_pow_witnesses.pop();
            }),
        ),
        (
            "final polynomial",
            Box::new(|p| p.opening_proof.1.final_poly.clear()),
        ),
        (
            "query count",
            Box::new(|p| {
                p.opening_proof.1.query_proofs.pop();
            }),
        ),
        (
            "query rounds",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].input_proof.pop();
            }),
        ),
        (
            "query matrices",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opened_values
                    .pop();
            }),
        ),
        (
            "query width",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0].pop();
            }),
        ),
        (
            "query salts",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .0
                    .pop();
            }),
        ),
        (
            "query salt width",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .0[0]
                    .pop();
            }),
        ),
        (
            "query siblings",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .1
                    .pop();
            }),
        ),
        (
            "FRI steps",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0]
                    .commit_phase_openings
                    .pop();
            }),
        ),
        (
            "FRI arity",
            Box::new(|p| p.opening_proof.1.query_proofs[0].commit_phase_openings[0].log_arity = 2),
        ),
        (
            "FRI sibling width",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                    .sibling_values
                    .clear()
            }),
        ),
        (
            "FRI salts",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                    .opening_proof
                    .0
                    .clear()
            }),
        ),
        (
            "FRI siblings",
            Box::new(|p| {
                p.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                    .opening_proof
                    .1
                    .pop();
            }),
        ),
    ];
    for (name, change) in &changes {
        let mut changed: BatchProof<Config> =
            serde_json::from_value(serde_json::to_value(&proof).unwrap()).unwrap();
        change(&mut changed);
        assert!(
            bind(&shape, &caps, &[(&public[0], &changed)], count, bytes).is_err(),
            "accepted {name}"
        );
    }
    eprintln!(
        "recursive_input_rejections shape_cases={} independent_admission_cases=9",
        changes.len()
    );
}

#[test]
#[ignore = "bounded serial CPU timing experiment; no proving or cache activation"]
fn measure_full_size_compilation_against_fresh_input_binding() {
    let height = 1 << 18;
    let shape = Shape::new(height).unwrap();
    let template = verifier::template::batch(&super::shape(height).unwrap()).unwrap();
    let caps = caps::<12>(19);
    let public = statements(23);
    let proofs = [colored(&template, 17), colored(&template, 53)];
    for finalize in [false, true] {
        let reference = compile(height, &caps, &public, &proofs, finalize);
        let count = reference.program.witness_values();
        let children = [(&public[0], &proofs[0]), (&public[1], &proofs[1])];
        let children = &children[..if finalize { 1 } else { 2 }];
        for pair in 0..6 {
            for candidate in if pair % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let started = Instant::now();
                let elapsed;
                if candidate {
                    let values = bind(&shape, &caps, children, count, count * 8).unwrap();
                    elapsed = started.elapsed().as_nanos();
                    assert_eq!(values, reference.witness);
                } else {
                    let full = compile(height, &caps, &public, &proofs, finalize);
                    elapsed = started.elapsed().as_nanos();
                    assert_eq!(full.program, reference.program);
                    assert_eq!(full.witness, reference.witness);
                }
                eprintln!("recursive_input_timing finalize={finalize} pair={pair} candidate={candidate} elapsed_ns={elapsed} values={count} byte_budget={}", count * 8);
            }
        }
    }
}
