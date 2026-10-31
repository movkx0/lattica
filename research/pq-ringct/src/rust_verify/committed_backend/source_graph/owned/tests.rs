use super::*;
use crate::execution::retained_resources::WorkerAllowance;

fn encoded_inputs() -> (Vec<u8>, Vec<u8>) {
    let mut statement = vec![0; STATEMENT_BYTES];
    statement[STATEMENT_BYTES - 32] = 1; // Distinct serial byte strings.
    (statement, vec![0; PROOF_BYTES])
}

fn total(requirements: Requirements) -> u64 {
    Category::ALL
        .into_iter()
        .map(|category| requirements.get(category).host)
        .sum()
}

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host,
        device: RawAdapterPlan::fixed().unwrap().device_bytes as u64,
    })
}

#[test]
fn decoded_inputs_use_actual_capacities_including_every_nested_vector() {
    let (s, p) = encoded_inputs();
    let mut statement = Statement::decode(&s).unwrap();
    let mut proof = Proof::decode(&p).unwrap();
    let before = FixedInputs::inspect(&statement, &proof)
        .unwrap()
        .retained_bytes()
        .unwrap();
    assert_eq!(before, inputs::decoded_retained_bytes().unwrap());
    let mut delta = 0;
    macro_rules! spare {
        ($vec:expr, $ty:ty) => {{
            let values = &mut $vec;
            let old = values.capacity();
            values.reserve_exact(old + 3);
            delta += (values.capacity() - old) * size_of::<$ty>();
        }};
    }
    spare!(statement.ring, [Account; 2]);
    for account in statement.ring.iter_mut().flatten() {
        spare!(account.pk, [u64; D]);
        spare!(account.cn, [u64; D]);
    }
    for rows in [&mut statement.recipients, &mut statement.coins] {
        spare!(*rows, Vec<[u64; D]>);
        for row in rows {
            spare!(*row, [u64; D]);
        }
    }
    spare!(proof.v, [u64; D]);
    spare!(proof.b, [u64; D]);
    spare!(proof.z_out, Vec<[i64; D]>);
    for row in proof.z_out.iter_mut().chain([
        &mut proof.z0,
        &mut proof.z1,
        &mut proof.z2,
        &mut proof.f1,
        &mut proof.zb,
        &mut proof.z,
    ]) {
        spare!(*row, [i64; D]);
    }
    let after = FixedInputs::inspect(&statement, &proof)
        .unwrap()
        .retained_bytes()
        .unwrap();
    assert_eq!(after, before + delta);
    assert!(delta > 0);
}

#[test]
fn complete_payload_reservation_precedes_decoding_and_failure_is_atomic() {
    let plan = PayloadPlan::fixed().unwrap();
    let requested = total(plan.combined);
    let (statement, proof) = encoded_inputs();
    let too_small = ledger(requested - 1);
    // Malformed coefficient distinguishes budget refusal from entering decode.
    let mut bad = statement.clone();
    bad[32..36].copy_from_slice(&(Q as u32).to_le_bytes());
    assert!(matches!(
        Construction::new([0; 32], [0; 32], &bad, &proof, &too_small),
        Err(BUDGET)
    ));
    assert_eq!(too_small.snapshot().current, Bytes::ZERO);
    assert_eq!(too_small.snapshot().peak, Bytes::ZERO);

    let quota = ledger(requested);
    let source = Construction::new([0; 32], [0; 32], &statement, &proof, &quota).unwrap();
    assert_eq!(quota.snapshot().current.host, requested);
    assert!(source.inputs.reservation.belongs_to(&quota));
    assert!(source.graph_reservation.belongs_to(&quota));
    assert!(source.growth_reservation.belongs_to(&quota));
    assert!(source.belongs_to(&quota));
    assert!(!source.belongs_to(&ledger(requested)));
    assert_eq!(
        source.operation_host_allowance(),
        plan.raw_adapters.operation_host_allowance
    );
    assert!(
        source
            .growth_reservation
            .requirements()
            .get(Category::PhaseScratch)
            .host
            >= (SymbolicScratch::fixed().unwrap().requested_bytes + plan.raw_adapters.host_bytes)
                as u64
    );
    drop(source);
    assert_eq!(quota.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "opencl")]
#[test]
fn raw_device_capacity_is_reserved_before_decode_and_not_just_checked_later() {
    let plan = PayloadPlan::fixed().unwrap();
    let (mut statement, proof) = encoded_inputs();
    statement[32..36].copy_from_slice(&(Q as u32).to_le_bytes());
    let quota = Ledger::new(WorkerAllowance {
        host: total(plan.combined),
        device: plan.raw_adapters.device_bytes as u64 - 1,
    });
    assert!(matches!(
        Construction::new([0; 32], [0; 32], &statement, &proof, &quota),
        Err(BUDGET)
    ));
    assert_eq!(quota.snapshot().current, Bytes::ZERO);
    assert_eq!(quota.snapshot().peak, Bytes::ZERO);
}

#[test]
fn all_decoder_failure_paths_release_the_original_reservations() {
    let plan = PayloadPlan::fixed().unwrap();
    let (statement, proof) = encoded_inputs();
    let quota = ledger(total(plan.combined));
    let mut cases = Vec::new();
    let mut malformed = statement.clone();
    malformed[32..36].copy_from_slice(&(Q as u32).to_le_bytes());
    cases.push((malformed, proof.clone()));
    let mut duplicate = statement.clone();
    duplicate[STATEMENT_BYTES - 64..].fill(0);
    cases.push((duplicate, proof.clone()));
    let mut bad_proof = proof.clone();
    bad_proof[..4].copy_from_slice(&(Q as u32).to_le_bytes());
    cases.push((statement.clone(), bad_proof));
    cases.push((statement[..statement.len() - 1].to_vec(), proof.clone()));
    cases.push((statement, proof[..proof.len() - 1].to_vec()));
    for (s, p) in cases {
        assert!(Construction::new([0; 32], [0; 32], &s, &p, &quota).is_err());
        assert_eq!(quota.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn reservation_survives_moves_and_original_ledger_retirement() {
    let plan = PayloadPlan::fixed().unwrap();
    let (statement, proof) = encoded_inputs();
    let quota = ledger(total(plan.combined));
    let monitor = quota.clone();
    let source = Construction::new([0; 32], [0; 32], &statement, &proof, &quota).unwrap();
    let moved = Some(source);
    drop(quota);
    assert_eq!(monitor.snapshot().current.host, total(plan.combined));
    drop(moved);
    assert_eq!(monitor.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "opencl")]
#[test]
fn native_failure_cannot_release_a_graph_or_lose_its_payload_charges() {
    use crate::rust_verify::committed_backend::gpu::GraphDevice;
    use lattica_prover_p3::block_v2::native_gpu::operations_arithmetic::{
        CanonicalOperation, SignedOperation,
    };
    use std::cell::Cell;
    struct Failed<'a> {
        quota: &'a Ledger,
        expected: u64,
        calls: Cell<usize>,
    }
    macro_rules! unreachable {
        ($name:ident($($arg:ident: $type:ty),*) -> $output:ty) => {
            fn $name(&self, $($arg: $type),*) -> core::result::Result<$output, String> {
                $(let _ = $arg;)*
                panic!("native callback reached after poisoned graph: {}", stringify!($name))
            }
        };
    }
    impl GraphDevice for Failed<'_> {
        fn commit_bytes(&self, _: &[u8; 32]) -> core::result::Result<[Val; 4], String> {
            assert_eq!(self.quota.snapshot().current.host, self.expected);
            self.calls.set(self.calls.get() + 1);
            Err("injected native failure before first graph node".into())
        }
        unreachable!(canonical(kind: CanonicalOperation, left: &[u64], right: &[u64], q: u64) -> Vec<u64>);
        unreachable!(signed(kind: SignedOperation, input: &[u64], count: usize) -> Vec<u64>);
        unreachable!(convert(input: &[i64], q: u64) -> Vec<u64>);
        unreachable!(ntt_poly(input: &[i64; D], q: u64) -> [u64; D]);
        unreachable!(mul_poly(left: &[u64; D], right: &[u64; D], q: u64) -> [u64; D]);
        unreachable!(aut_poly(input: &[u64; D]) -> [u64; D]);
        unreachable!(commit_canonical(input: &[u64; D], q: u64) -> [Val; 4]);
        unreachable!(commit_signed(input: &[i64; D]) -> [Val; 4]);
        unreachable!(parameters(seed: &[u8; 32], context: &[u8; 32]) -> primitives::Parameters);
        unreachable!(sample_g(seed: &[u8; 32]) -> Vec<[u64; D]>);
        unreachable!(expand_alpha(seed: &[u8; 32]) -> (Vec<[u64; D]>, [i64; D]));
        unreachable!(hash_alpha(input: &[u8]) -> [u8; 32]);
        unreachable!(hash_x(input: &[u8]) -> [i64; D]);
    }
    let plan = PayloadPlan::fixed().unwrap();
    let (s, p) = encoded_inputs();
    let quota = ledger(total(plan.combined));
    let source = Construction::new([0; 32], [0; 32], &s, &p, &quota).unwrap();
    let device = Failed {
        quota: &quota,
        expected: total(plan.combined),
        calls: Cell::new(0),
    };
    let result = source.lower(CommittedBackend::with_device([0; 32], &device));
    assert!(matches!(result, Err("source graph native lowering failed")));
    assert_eq!(device.calls.get(), 1);
    assert_eq!(quota.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "native-verification-allocation-audit")]
#[test]
#[ignore = "process-wide allocation observer; coordinator must serialize"]
fn payload_refusal_and_raw_shape_checks_allocate_nothing() {
    use crate::component_tree::shake_verification_memory::observe_planner_allocations;
    let plan = PayloadPlan::fixed().unwrap();
    let (s, p) = encoded_inputs();
    let mut statement = Statement::decode(&s).unwrap();
    let proof = Proof::decode(&p).unwrap();
    let quota = ledger(total(plan.combined) - 1);
    observe_planner_allocations(0, || {
        assert!(FixedInputs::inspect(&statement, &proof).is_ok());
        assert!(Construction::new([0; 32], [0; 32], &s, &p, &quota).is_err());
    });
    statement.ring[9][1].pk.pop();
    observe_planner_allocations(0, || {
        assert!(FixedInputs::inspect(&statement, &proof).is_err());
    });
    assert_eq!(quota.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "actual native fixture and full CPU source graph; coordinator memory window"]
fn genuine_graph_keeps_original_inputs_and_tokens_after_callback_and_moves() {
    use crate::native::{self, FixtureAmounts};
    use crate::rust_verify::committed_backend::source_binding::RegisteredGraphShape;
    let context = [71; 32];
    let setup_seed = [29; 32];
    let fixture = native::generate_fixture_with_setup_seed(
        context,
        setup_seed,
        3,
        FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
    )
    .unwrap();
    let plan = PayloadPlan::fixed().unwrap();
    let quota = ledger(total(plan.combined));
    let monitor = quota.clone();
    let source = Construction::new(
        setup_seed,
        context,
        &fixture.statement,
        &fixture.proof,
        &quota,
    )
    .unwrap();
    let pending = source.lower(CommittedBackend::new(setup_seed)).unwrap();
    // This is the actual graph produced under the preexisting reservation.
    // Even after lowering, callback growth remains charged until completion.
    assert_eq!(monitor.snapshot().current.host, total(plan.combined));
    let graph_pointer = pending.owned.graph.polynomials.as_ptr();
    let statement_pointer = pending.owned.inputs.statement.ring.as_ptr();
    let graph = pending.after_callback();
    assert_eq!(
        monitor.snapshot().current.host,
        total(plan.inputs) + total(plan.graph)
    );
    assert_eq!(
        monitor.snapshot().categories[Category::PhaseScratch as usize].current,
        Bytes::ZERO
    );
    assert!(graph.belongs_to(&quota));
    assert_eq!(graph.context(), &context);
    assert_eq!(graph.graph().setup_seed(), setup_seed);
    let expected = lower_unproved(
        setup_seed,
        &context,
        graph.inputs().statement(),
        graph.inputs().proof(),
    )
    .unwrap();
    let shape = RegisteredGraphShape::from_trusted_graph(&expected).unwrap();
    assert!(shape.matches(graph.graph()));
    for (actual, reference) in graph
        .graph()
        .polynomials()
        .iter()
        .zip(expected.polynomials())
    {
        assert_eq!(actual.commitment, reference.commitment);
        assert_eq!(actual.source, reference.source);
    }
    assert_eq!(
        shape.node_manifest_hint(graph.graph()).unwrap(),
        shape.node_manifest_hint(&expected).unwrap()
    );
    drop(expected);
    drop(quota);
    let moved = Some(graph);
    assert_eq!(
        moved.as_ref().unwrap().graph.polynomials.as_ptr(),
        graph_pointer
    );
    assert_eq!(
        moved.as_ref().unwrap().inputs.statement.ring.as_ptr(),
        statement_pointer
    );
    assert_eq!(
        monitor.snapshot().current.host,
        total(plan.inputs) + total(plan.graph)
    );
    drop(moved);
    assert_eq!(monitor.snapshot().current, Bytes::ZERO);
}
