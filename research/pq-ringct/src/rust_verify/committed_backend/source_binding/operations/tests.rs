//! Operation-coverage integration tests are kept separate from source proofs.
#![cfg(feature = "native-matrict")]
use super::*;
use lattica_prover_p3::block_v2::machine::{MachineAir, ProgramBuilder};

fn fixture() -> (RegisteredGraphShape, UnprovedRelationGraph, Vec<Val>) {
    let (statement, proof, _) = crate::rust_verify::committed_backend::tests::fixture();
    let graph = lower_unproved([29; 32], &[71; 32], &statement, &proof).unwrap();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let mut public = native_words(&[71; 32]).to_vec();
    // These tests prove individual graph operations. No statement verifier is
    // emitted here, and the session must remain incomplete.
    public.extend([Val::ZERO; 4]);
    public.extend(registered.node_manifest_hint(&graph).unwrap());
    (registered, graph, public)
}
fn compile(
    registered: &RegisteredGraphShape,
    graph: &UnprovedRelationGraph,
    action: impl FnOnce(&mut SourceBinding<'_, '_, '_>),
) -> (MachineAir, ProofInputs, Remaining) {
    let mut builder = ProgramBuilder::new(16).unwrap();
    let context = core::array::from_fn(|i| builder.public(i).unwrap());
    let statement = core::array::from_fn(|i| builder.public(8 + i).unwrap());
    let manifest = core::array::from_fn(|i| builder.public(12 + i).unwrap());
    let mut inputs = ProofInputs::default();
    let mut binding = SourceBinding::new(
        registered,
        graph,
        &mut builder,
        &mut inputs,
        context,
        statement,
        manifest,
    )
    .unwrap();
    action(&mut binding);
    let remaining = binding.remaining();
    assert!(binding.require_complete().is_err());
    let program = builder.finish(None).unwrap();
    eprintln!(
        "operation_binding_rows={} padded={} wires={}",
        program.active_rows(),
        program.height(),
        program.wire_count()
    );
    (MachineAir::new(program), inputs, remaining)
}

#[test]
fn exact_operation_batches_and_equalities_preserve_pending_producers() {
    let (registered, mut graph, mut public) = fixture();
    let add: Vec<_> = graph
        .operations
        .iter()
        .enumerate()
        .filter_map(|(i, op)| matches!(op, Operation::Add { modulus: Q, .. }).then_some(i))
        .take(2)
        .collect();
    let ntt = graph
        .operations
        .iter()
        .position(|op| matches!(op, Operation::Ntt { .. }))
        .unwrap();
    let mul = graph
        .operations
        .iter()
        .position(|op| matches!(op, Operation::Mul { .. }))
        .unwrap();
    let equality: Vec<_> = graph
        .operations
        .iter()
        .enumerate()
        .filter_map(|(i, op)| {
            matches!(
                op,
                Operation::EqualBytes { .. } | Operation::EqualSigned { .. }
            )
            .then_some(i)
        })
        .collect();
    let (machine, mut inputs, remaining) = compile(&registered, &graph, |binding| {
        assert!(binding.affine_requests(&add).is_ok());
        assert!(binding.affine_requests(&[]).is_err());
        assert!(binding.affine_requests(&[add[0], add[0]]).is_err());
        assert!(binding.affine_requests(&[add[1], add[0]]).is_err());
        assert!(binding.affine_requests(&[ntt]).is_err());
        assert!(binding.ntt_requests(&[ntt]).is_ok());
        assert!(binding.ntt_requests(&[mul]).is_err());
        assert!(binding.mul_requests(&[mul]).is_ok());
        assert!(binding.mul_requests(&[ntt]).is_err());
        for &index in &equality {
            binding.constrain_equality(index).unwrap();
            assert!(binding.constrain_equality(index).is_err());
        }
    });
    assert_eq!(
        remaining,
        Remaining {
            polynomial_nodes: 1770,
            byte_nodes: 6,
            operations: 1308
        }
    );
    machine.trace(&public, &inputs.values).unwrap();
    // A matching public manifest cannot hide a false equality relation.
    let index = equality
        .iter()
        .find_map(|&i| match graph.operations[i] {
            Operation::EqualBytes { left, .. } => Some(left.index()),
            _ => None,
        })
        .unwrap();
    graph.bytes[index].commitment[0] += Val::ONE;
    inputs.values[4 * (graph.polynomials.len() + index)] += Val::ONE;
    public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
    assert!(machine.trace(&public, &inputs.values).is_err());
}

fn canonical(graph: &UnprovedRelationGraph, id: PolyId) -> [u64; D] {
    let PolynomialValues::Canonical(values) = graph.polynomial(id).values else {
        panic!("canonical fixture input")
    };
    values
}
fn signed(graph: &UnprovedRelationGraph, id: PolyId) -> [i64; D] {
    let PolynomialValues::Signed(values) = graph.polynomial(id).values else {
        panic!("signed fixture input")
    };
    values
}
enum Artifact {
    Affine(AffineBatchProof),
    Ntt(NttBatchProof),
    Mul(MulBatchProof),
    GBound(GBoundArtifact),
    Permutation(PermutationProof),
    LinearMap(LinearMapProof),
}
impl Artifact {
    fn verify(&self, binding: &mut SourceBinding<'_, '_, '_>, index: usize) -> Result<()> {
        match self {
            Self::Affine(proof) => binding.verify_affine_batch(&[index], proof),
            Self::Ntt(proof) => binding.verify_ntt_batch(&[index], proof),
            Self::Mul(proof) => binding.verify_mul_batch(&[index], proof),
            Self::GBound(proof) => binding.verify_g_bound(index, proof),
            Self::Permutation(proof) => binding.verify_permutation(index, proof),
            Self::LinearMap(proof) => binding.verify_linear_map(index, proof),
        }
    }
}

#[test]
fn all_map_requests_are_exact_and_leave_coverage_pending() {
    let (registered, graph, public) = fixture();
    let (machine, inputs, remaining) = compile(&registered, &graph, |binding| {
        let mut linear = 0;
        let mut permutations = 0;
        for index in 0..graph.operations.len() {
            let permutation = binding.permutation_request(index);
            let affine = binding.linear_map_request(index);
            assert!(!(permutation.is_ok() && affine.is_ok()));
            permutations += usize::from(permutation.is_ok());
            linear += usize::from(affine.is_ok());
        }
        assert_eq!((permutations, linear), (3, 7));
        assert!(binding.permutation_request(graph.operations.len()).is_err());
        assert!(binding.linear_map_request(graph.operations.len()).is_err());
    });
    assert_eq!(
        remaining,
        Remaining {
            polynomial_nodes: 1770,
            byte_nodes: 6,
            operations: 1311
        }
    );
    machine.trace(&public, &inputs.values).unwrap();
}

#[test]
fn fixed_source_roots_are_constrained_to_trusted_registration() {
    let (registered, mut graph, mut public) = fixture();
    let fixed: Vec<_> = graph
        .polynomials
        .iter()
        .enumerate()
        .filter(|(_, node)| node.source == Source::Fixed)
        .map(|(index, _)| index)
        .collect();
    assert!(!fixed.is_empty());
    let (machine, mut inputs, remaining) = compile(&registered, &graph, |binding| {
        binding.constrain_fixed_sources().unwrap();
        assert!(binding.constrain_fixed_sources().is_err());
    });
    assert_eq!(remaining.polynomial_nodes, 1770 - fixed.len());
    assert_eq!(remaining.operations, 1311);
    machine.trace(&public, &inputs.values).unwrap();
    let index = fixed[0];
    graph.polynomials[index].commitment[0] += Val::ONE;
    inputs.values[4 * index] += Val::ONE;
    assert!(registered.node_manifest_hint(&graph).is_err());
    // Keep the original registered label while constructing a hostile public
    // node manifest. The helper correctly refuses this changed fixed source.
    let mut fields = registered.header(&graph);
    for (index, node) in graph.polynomials.iter().enumerate() {
        fields.extend([1, index as u64]);
        fields.extend(node.commitment.map(|value| value.as_canonical_u64()));
    }
    for (index, node) in graph.bytes.iter().enumerate() {
        fields.extend([2, index as u64]);
        fields.extend(node.commitment.map(|value| value.as_canonical_u64()));
    }
    public[12..].copy_from_slice(
        &commitment::hash_fields(NODE_MANIFEST_DOMAIN, &fields)
            .unwrap()
            .map(Val::from_u64),
    );
    assert!(machine.trace(&public, &inputs.values).is_err());
    assert!(!registered.matches(&graph));
}

#[test]
fn exact_leaf_coverage_consumes_all_flags_without_issuing_a_token() {
    let (registered, graph, public) = fixture();
    let mut constructor_bytes = vec![registered.plan.context, registered.plan.seed];
    constructor_bytes.sort_unstable();
    let check = |polynomials: &[usize], bytes: &[usize], operations: &[usize]| {
        let mut builder = ProgramBuilder::new(16).unwrap();
        let context = core::array::from_fn(|i| builder.public(i).unwrap());
        let statement = core::array::from_fn(|i| builder.public(8 + i).unwrap());
        let manifest = core::array::from_fn(|i| builder.public(12 + i).unwrap());
        let mut inputs = ProofInputs::default();
        let binding = SourceBinding::new(
            &registered,
            &graph,
            &mut builder,
            &mut inputs,
            context,
            statement,
            manifest,
        )
        .unwrap();
        let result = binding.require_exact_coverage(polynomials, bytes, operations);
        if result.is_ok() {
            MachineAir::new(builder.finish(None).unwrap())
                .trace(&public, &inputs.values)
                .unwrap();
        }
        result
    };
    check(&[], &constructor_bytes, &[]).unwrap();
    assert!(check(&[], &constructor_bytes[..1], &[]).is_err());
    assert!(check(&[0], &constructor_bytes, &[]).is_err());
    assert!(check(&[], &constructor_bytes, &[0]).is_err());
    assert!(check(
        &[],
        &[
            constructor_bytes[0],
            constructor_bytes[0],
            constructor_bytes[1]
        ],
        &[]
    )
    .is_err());
    assert!(check(&[], &[constructor_bytes[1], constructor_bytes[0]], &[]).is_err());
    assert!(check(&[], &[graph.bytes.len()], &[]).is_err());
    assert!(check(&[graph.polynomials.len()], &constructor_bytes, &[]).is_err());
    assert!(check(&[], &constructor_bytes, &[graph.operations.len()]).is_err());
}

#[test]
#[ignore = "actual pp SHAKE child and exact graph producer join; reserve8GiB"]
fn actual_parameter_producer_binds_graph_context_and_output() {
    use crate::{
        shake_air::{
            lane::{batch::ShakeBatchPartition, LaneShakeProof},
            Descriptor,
        },
        transcript_bridge::{pp_input_bytes, ShakeArtifacts},
    };
    let (registered, mut graph, mut public) = fixture();
    let (index, setup_seed, context, output) = graph
        .operations
        .iter()
        .enumerate()
        .find_map(|(index, op)| {
            if let Operation::ParametersPp {
                setup_seed,
                context,
                output,
            } = *op
            {
                Some((index, setup_seed, context, output))
            } else {
                None
            }
        })
        .unwrap();
    let data = pp_input_bytes(&setup_seed, &graph.byte_string(context).values);
    let partition = ShakeBatchPartition::new(
        Descriptor {
            input_len: data.len(),
            output_len: 32,
        },
        8,
    )
    .unwrap();
    let config = lattica_prover_p3::block_v2::profile::make_config();
    let proofs: Vec<_> = partition
        .segments()
        .iter()
        .map(|air| {
            let witness = air.generate(&data).unwrap();
            let proof = p3_uni_stark::prove(&config, air, witness.trace, &witness.public_values);
            p3_uni_stark::verify(&config, air, &proof, &witness.public_values).unwrap();
            LaneShakeProof {
                public_values: witness.public_values,
                proof,
            }
        })
        .collect();
    let (machine, mut inputs, remaining) = compile(&registered, &graph, |binding| {
        binding
            .verify_parameters_pp(
                index,
                ShakeArtifacts {
                    partition: &partition,
                    proofs: &proofs,
                },
            )
            .unwrap();
        assert!(binding
            .verify_parameters_pp(
                index,
                ShakeArtifacts {
                    partition: &partition,
                    proofs: &proofs
                }
            )
            .is_err());
    });
    assert_eq!(
        remaining,
        Remaining {
            polynomial_nodes: 1770,
            byte_nodes: 5,
            operations: 1310
        }
    );
    machine.trace(&public, &inputs.values).unwrap();
    graph.bytes[output.index()].commitment[0] += Val::ONE;
    inputs.values[4 * (graph.polynomials.len() + output.index())] += Val::ONE;
    public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
    assert!(machine.trace(&public, &inputs.values).is_err());
}

#[test]
#[ignore = "actual four map child STARKs and graph joins; reserve8GiB"]
fn actual_map_operation_proofs_bind_exact_graph_edges() {
    use crate::{linear_map_air::LinearMapInput, permutation_air::PermutationInput};
    let (registered, mut graph, mut public) = fixture();
    let mut selected = [None; 4];
    for index in 0..graph.operations.len() {
        if let Ok((kind, _, _)) = crate::permutation_air::graph::graph_operation(&graph, index) {
            let slot = match kind {
                PermutationKind::AutomorphismQ => 0,
                PermutationKind::InverseChallenge => 1,
            };
            selected[slot].get_or_insert(index);
        }
        if let Ok(relation) = crate::linear_map_air::graph_operation(&graph, index) {
            let slot = match relation.descriptor.output() {
                PolynomialKind::Canonical { .. } => 2,
                PolynomialKind::Signed { .. } => 3,
            };
            selected[slot].get_or_insert(index);
        }
    }
    for (slot, index) in selected.map(Option::unwrap).into_iter().enumerate() {
        let (artifact, output) = if slot < 2 {
            let (kind, input, output) =
                crate::permutation_air::graph::graph_operation(&graph, index).unwrap();
            let values = match kind {
                PermutationKind::AutomorphismQ => {
                    PermutationInput::Canonical(canonical(&graph, input))
                }
                PermutationKind::InverseChallenge => {
                    PermutationInput::Signed(signed(&graph, input))
                }
            };
            (
                Artifact::Permutation(RegisteredPermutationAir::new(kind).prove(&values).unwrap()),
                output.index(),
            )
        } else {
            let relation = crate::linear_map_air::graph_operation(&graph, index).unwrap();
            let values = relation
                .inputs
                .iter()
                .map(|&id| match graph.polynomial(id).kind {
                    PolynomialKind::Canonical { .. } => {
                        LinearMapInput::Canonical(canonical(&graph, id))
                    }
                    PolynomialKind::Signed { .. } => LinearMapInput::Signed(signed(&graph, id)),
                })
                .collect::<Vec<_>>();
            (
                Artifact::LinearMap(
                    RegisteredLinearMapAir::new(relation.descriptor)
                        .prove(&values)
                        .unwrap(),
                ),
                relation.output.index(),
            )
        };
        let (machine, mut inputs, remaining) = compile(&registered, &graph, |binding| {
            artifact.verify(binding, index).unwrap();
            assert!(artifact.verify(binding, index).is_err());
        });
        assert_eq!(
            remaining,
            Remaining {
                polynomial_nodes: 1769,
                byte_nodes: 6,
                operations: 1310
            }
        );
        machine.trace(&public, &inputs.values).unwrap();
        graph.polynomials[output].commitment[0] += Val::ONE;
        inputs.values[4 * output] += Val::ONE;
        public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
        assert!(
            machine.trace(&public, &inputs.values).is_err(),
            "unbound map {index}"
        );
        graph.polynomials[output].commitment[0] -= Val::ONE;
        public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
    }
}

#[test]
#[ignore = "actual six operation child STARKs and typed graph joins; reserve8GiB"]
fn actual_algebraic_operation_proofs_discharge_only_exact_edges() {
    use crate::affine_air::AffineInput;
    let (registered, mut graph, mut public) = fixture();
    let mut selected = [None; 6];
    for (index, operation) in graph.operations.iter().enumerate() {
        let kind = match operation {
            Operation::Add { .. } => 0,
            Operation::Sub { .. } => 1,
            Operation::SignedToCanonical { .. } => 2,
            Operation::Ntt { .. } => 3,
            Operation::Mul { .. } => 4,
            Operation::GBound { .. } => 5,
            _ => continue,
        };
        selected[kind].get_or_insert(index);
    }
    for index in selected.map(Option::unwrap) {
        let (artifact, changed, has_output) = match graph.operations[index].clone() {
            Operation::Add {
                modulus,
                left,
                right,
                output,
            }
            | Operation::Sub {
                modulus,
                left,
                right,
                output,
            } => {
                let kind = if matches!(graph.operations[index], Operation::Add { .. }) {
                    AffineKind::Add
                } else {
                    AffineKind::Sub
                };
                let key = RegisteredAffineAir::new(kind, modulus, 1).unwrap();
                let proof = key
                    .prove(&[AffineInput::Binary {
                        left: canonical(&graph, left),
                        right: canonical(&graph, right),
                    }])
                    .unwrap();
                (Artifact::Affine(proof), output.index(), true)
            }
            Operation::SignedToCanonical {
                bound,
                modulus,
                input,
                output,
            } => {
                let key =
                    RegisteredAffineAir::new(AffineKind::SignedToCanonical { bound }, modulus, 1)
                        .unwrap();
                (
                    Artifact::Affine(
                        key.prove(&[AffineInput::Signed(signed(&graph, input))])
                            .unwrap(),
                    ),
                    output.index(),
                    true,
                )
            }
            Operation::Ntt {
                modulus,
                input,
                output,
            } => {
                let key = RegisteredNttAir::new(modulus, 1).unwrap();
                (
                    Artifact::Ntt(key.prove(&[canonical(&graph, input)]).unwrap()),
                    output.index(),
                    true,
                )
            }
            Operation::Mul {
                modulus,
                left,
                right,
                output,
            } => {
                let key = RegisteredMulAir::new(modulus, 1).unwrap();
                (
                    Artifact::Mul(
                        key.prove(&[canonical(&graph, left)], &[canonical(&graph, right)])
                            .unwrap(),
                    ),
                    output.index(),
                    true,
                )
            }
            Operation::GBound { f, x, bound } => {
                let key = RegisteredGBoundAir::new(bound).unwrap();
                (
                    Artifact::GBound(key.prove(&signed(&graph, f), &signed(&graph, x)).unwrap()),
                    f.index(),
                    false,
                )
            }
            _ => unreachable!(),
        };
        let (machine, mut inputs, remaining) = compile(&registered, &graph, |binding| {
            artifact.verify(binding, index).unwrap();
            assert!(artifact.verify(binding, index).is_err());
        });
        assert_eq!(
            remaining,
            Remaining {
                polynomial_nodes: 1770 - usize::from(has_output),
                byte_nodes: 6,
                operations: 1310
            }
        );
        machine.trace(&public, &inputs.values).unwrap();
        graph.polynomials[changed].commitment[0] += Val::ONE;
        inputs.values[4 * changed] += Val::ONE;
        public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
        assert!(
            machine.trace(&public, &inputs.values).is_err(),
            "unbound operation{index}"
        );
        graph.polynomials[changed].commitment[0] -= Val::ONE;
        public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
    }
}
