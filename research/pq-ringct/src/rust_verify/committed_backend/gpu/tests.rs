use super::*;
use std::cell::Cell;

#[test]
fn malformed_raw_inputs_are_refused_before_the_native_callback() {
    use crate::execution::ProvingContext;
    use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};
    let mut encoded_statement = vec![0; STATEMENT_BYTES];
    encoded_statement[STATEMENT_BYTES - 32] = 1;
    let mut statement = Statement::decode(&encoded_statement).unwrap();
    let proof = Proof::decode(&vec![0; PROOF_BYTES]).unwrap();
    statement.ring[9][1].pk.pop();
    let worker = ProvingContext::cpu(1 << 30).unwrap();
    // A CPU context would produce a different error if execution reached it.
    let result = lower_unproved_on_gpu([0; 32], &[0; 32], &statement, &proof, &worker, 1 << 30);
    assert!(matches!(result, Err(ref e) if e == "graph requires the fixed n10 native dimensions"));
    let report = worker.report();
    assert_eq!(report["operations"]["witness_preparation_calls"], 0);
    assert_eq!(report["operations"]["native_gpu_calls"], 0);
    assert_eq!(report["operations"]["native_cpu_calls"], 0);
}

struct FailedDevice(Cell<usize>);

struct SignedDevice { calls: Cell<usize>, fail: bool }
// Only the first operation is expected to reach this fixture. Every later
// method must be skipped by the backend's poisoned state.
macro_rules! unexpected {
    ($name:ident($($arg:ident: $type:ty),*) -> $output:ty) => {
        fn $name(&self, $($arg: $type),*) -> Result<$output, String> {
            $(let _ = $arg;)*
            panic!("unexpected GPU callback after failure: {}", stringify!($name))
        }
    };
}
impl GraphDevice for FailedDevice {
    fn canonical(
        &self,
        _: CanonicalOperation,
        _: &[u64],
        _: &[u64],
        _: u64,
    ) -> Result<Vec<u64>, String> {
        self.0.set(self.0.get() + 1);
        Err("injected GPU operation failure".into())
    }
    unexpected!(signed(kind: SignedOperation, input: &[u64], count: usize) -> Vec<u64>);
    unexpected!(convert(input: &[i64], q: u64) -> Vec<u64>);
    unexpected!(ntt_poly(input: &RawSigned, q: u64) -> RawPoly);
    unexpected!(mul_poly(left: &RawPoly, right: &RawPoly, q: u64) -> RawPoly);
    unexpected!(aut_poly(input: &RawPoly) -> RawPoly);
    unexpected!(commit_canonical(input: &RawPoly, q: u64) -> [Val; 4]);
    unexpected!(commit_signed(input: &RawSigned) -> [Val; 4]);
    unexpected!(commit_bytes(input: &[u8; 32]) -> [Val; 4]);
    unexpected!(parameters(seed: &[u8; 32], context: &[u8; 32]) -> primitives::Parameters);
    unexpected!(sample_g(seed: &[u8; 32]) -> Vec<RawPoly>);
    unexpected!(expand_alpha(seed: &[u8; 32]) -> (Vec<RawPoly>, RawSigned));
    unexpected!(hash_alpha(input: &[u8]) -> [u8; 32]);
    unexpected!(hash_x(input: &[u8]) -> RawSigned);
}

impl GraphDevice for SignedDevice {
    fn signed(&self, kind: SignedOperation, input: &[u64], count: usize) -> Result<Vec<u64>, String> {
        assert!(matches!(kind, SignedOperation::Subtract));
        assert_eq!(count, D);
        assert_eq!(input.len(), 2 * D);
        self.calls.set(self.calls.get() + 1);
        if self.fail { return Err("injected signed batch failure".into()); }
        Ok((0..count).map(|i| ((input[i] as i64) - (input[count + i] as i64)) as u64).collect())
    }
    unexpected!(canonical(kind: CanonicalOperation, left: &[u64], right: &[u64], q: u64) -> Vec<u64>);
    unexpected!(convert(input: &[i64], q: u64) -> Vec<u64>);
    unexpected!(ntt_poly(input: &RawSigned, q: u64) -> RawPoly);
    unexpected!(mul_poly(left: &RawPoly, right: &RawPoly, q: u64) -> RawPoly);
    unexpected!(aut_poly(input: &RawPoly) -> RawPoly);
    unexpected!(commit_canonical(input: &RawPoly, q: u64) -> [Val; 4]);
    unexpected!(commit_signed(input: &RawSigned) -> [Val; 4]);
    unexpected!(commit_bytes(input: &[u8; 32]) -> [Val; 4]);
    unexpected!(parameters(seed: &[u8; 32], context: &[u8; 32]) -> primitives::Parameters);
    unexpected!(sample_g(seed: &[u8; 32]) -> Vec<RawPoly>);
    unexpected!(expand_alpha(seed: &[u8; 32]) -> (Vec<RawPoly>, RawSigned));
    unexpected!(hash_alpha(input: &[u8]) -> [u8; 32]);
    unexpected!(hash_x(input: &[u8]) -> RawSigned);
}

#[test]
fn signed_batch_preserves_scalar_expressions_values_bounds_and_failure() {
    let device = SignedDevice { calls: Cell::new(0), fail: false };
    let mut backend = CommittedBackend::new([1; 32]);
    let left = backend.signed_node(core::array::from_fn(|i| [-1073741823, 0, 1073741823][i % 3]),
        1073741823, Source::ProofPolynomial { position: 0 });
    let right = backend.signed_node(core::array::from_fn(|i| [1073741823, -1, -1073741823][i % 3]),
        1073741823, Source::ProofPolynomial { position: 1 });
    let left = backend.signed_refs(left);
    let right = backend.signed_refs(right);
    let begin = backend.graph.expressions.len();
    let scalar: [_; D] = core::array::from_fn(|i| backend.signed_sub(left[i], right[i]));
    let expected = backend.graph.expressions[begin..].to_vec();
    backend.graph.expressions.truncate(begin);
    backend.device = Some(&device);
    let batch = backend.signed_sub_poly(&left, &right);
    assert_eq!(device.calls.get(), 1);
    assert_eq!(&backend.graph.expressions[begin..], expected);
    assert_eq!(batch.map(|v| (v.value, v.expr, v.bound)), scalar.map(|v| (v.value, v.expr, v.bound)));
    assert!(backend.graph.operations.is_empty());

    let failed = SignedDevice { calls: Cell::new(0), fail: true };
    backend.device = Some(&failed);
    assert_eq!(backend.signed_sub_poly(&left, &right).map(|v| v.value), [0; D]);
    assert_eq!(backend.signed_sub_poly(&left, &right).map(|v| v.value), [0; D]);
    assert_eq!(failed.calls.get(), 1);
    assert_eq!(backend.failure.as_deref(), Some("injected signed batch failure"));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.into_unproved_graph())).is_err());
}

#[test]
fn signed_batch_rejects_foreign_operands_before_gpu_dispatch() {
    let device = SignedDevice { calls: Cell::new(0), fail: false };
    let mut first = CommittedBackend::new([1; 32]);
    let mut second = CommittedBackend::new([1; 32]);
    let a = first.signed_node([1; D], 1, Source::ProofPolynomial { position: 0 });
    let b = second.signed_node([1; D], 1, Source::ProofPolynomial { position: 0 });
    let a = first.signed_refs(a);
    let b = second.signed_refs(b);
    first.device = Some(&device);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| first.signed_sub_poly(&a, &b))).is_err());
    assert_eq!(device.calls.get(), 0);
}

#[test]
#[ignore = "requires exclusive admitted OpenCL; cached layouts and signed batch parity, no proofs"]
fn prepared_layouts_and_signed_batches_match_cpu_and_keep_scope_poisoning() {
    let worker = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30, device_bytes: 8 << 30, max_rows: 4096,
    }).unwrap();
    for reuse in [false, true] {
    let (_, report) = worker.with_witness_preparation(2 << 20, |operation| {
        if reuse { operation.enable_reusable_storage()?; }
        let device = PreparedDevice::new(operation);
        let a: RawSigned = core::array::from_fn(|i| [-1073741823, -1, 0, 1, 1073741823][i % 5]);
        let b = a.map(|v| -v);
        assert_eq!(device.signed_sub_poly(&a, &b)?, core::array::from_fn(|i| a[i] - b[i]));
        for q in [Q, QHAT] {
            let left: RawPoly = core::array::from_fn(|i| (i as u64 * 7919) % q);
            let right = left.map(|v| q - 1 - v);
            // Second pass exercises retained layouts with different values.
            for offset in [0, 1] {
                let input = a.map(|v| v + offset);
                assert_eq!(device.ntt_poly(&input, q)?, arithmetic::ntt(&input, q));
                assert_eq!(device.mul_poly(&left, &right, q)?, arithmetic::mul(&left, &right, q));
            }
        }
        Ok(())
    }).unwrap();
    assert_eq!(report.observations[0].completed_calls, 9);
    let failed = worker.with_witness_preparation(2 << 20, |operation| {
        if reuse { operation.enable_reusable_storage()?; }
        let device = PreparedDevice::new(operation);
        // Fill a layout, then poison the scope through a checked operation.
        device.ntt_poly(&[0; D], Q)?;
        assert!(operation.commit_signed_node(&[i64::MIN; D]).is_err());
        assert!(device.ntt_poly(&[0; D], Q).is_err());
        assert!(device.signed_sub_poly(&[0; D], &[0; D]).is_err());
        Ok(())
    });
    assert!(failed.is_err());
    }
    assert_eq!(worker.report()["operations"]["prove_calls"], 0);
}

#[test]
#[ignore = "exclusive admitted OpenCL; reusable scratch parity, fallbacks and unwinding, no proofs"]
fn reusable_storage_preserves_hashes_arithmetic_and_failure_cleanup() {
    use lattica_prover_p3::block_v2::native_gpu::{RawPreparationWorkspaceStorage,
        operations_arithmetic::{ArithmeticOperationSpec, CanonicalOperation}};
    let worker = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30, device_bytes: 8 << 30, max_rows: 4096 }).unwrap();
    let run = |reuse| worker.with_witness_preparation(4 << 20, |operation| {
        if reuse { operation.enable_reusable_storage()?; operation.enable_reusable_storage()?; }
        let mut output = Vec::new();
        for q in [Q, QHAT] {
            for offset in [0, 1] {
                let values = core::array::from_fn(|i| (i as u64 * 7919 + offset) % q);
                output.extend(operation.commit_canonical_node(&values, q)?);
            }
        }
        for offset in [0, 1] {
            output.extend(operation.commit_signed_node(&core::array::from_fn(|i| i as i64 - 128 + offset))?);
            output.extend(operation.commit_bytes32_node(&[offset as u8; 32])?);
        }
        for count in [0, 1, 3, 4, 5, 4095, 4096, 4097, 131073, 3] {
            operation.admit_field_chunks(count)?;
            let fields: Vec<_> = (0..count).map(|i| i as u64).collect();
            output.extend(operation.commit_field_chunks([7, count as u64, 0, 0], &fields)?);
        }
        for count in [1, 3, 256, 300, 1] {
            let spec = ArithmeticOperationSpec::canonical(CanonicalOperation::Add, count, Q)?;
            operation.admit_arithmetic_operation(&spec)?;
            let input: Vec<_> = (0..count).map(|i| i as u64).chain((0..count).map(|i| Q - 1 - i as u64)).collect();
            let actual = operation.arithmetic_output(&spec, &input)?;
            assert_eq!(actual, vec![Q - 1; count]);
            output.extend(actual);
        }
        Ok(output)
    }).map(|(output, _)| output);
    let reference = run(false).unwrap();
    assert_eq!(run(true).unwrap(), reference);
    assert!(worker.with_witness_preparation(RawPreparationWorkspaceStorage::fixed().host_bytes - 1,
        |operation| operation.enable_reusable_storage()).is_err());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = worker.with_witness_preparation(4 << 20, |operation| -> Result<(), String> {
            operation.enable_reusable_storage()?;
            operation.commit_bytes32_node(&[255; 32])?;
            panic!("injected reusable-scope unwind");
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(run(true).unwrap(), reference);
    assert_eq!(worker.report()["operations"]["prove_calls"], 0);
}

#[test]
fn native_failure_retains_the_original_diagnostic_allocation() {
    let device = FailedDevice(Cell::new(0));
    let mut backend = CommittedBackend::with_device([0; 32], &device);
    let mut diagnostic = String::with_capacity(4096);
    diagnostic.push_str("original GPU diagnostic");
    let pointer = diagnostic.as_ptr();
    let capacity = diagnostic.capacity();
    assert_eq!(backend.on_device::<()>(|_| Err(diagnostic)), Some(Err(())));
    for _ in 0..1024 {
        assert_eq!(
            backend.on_device::<()>(|_| panic!("callback after first failure")),
            Some(Err(()))
        );
    }
    let retained = backend.failure.as_ref().unwrap();
    assert_eq!(retained.as_str(), "original GPU diagnostic");
    assert_eq!(retained.as_ptr(), pointer);
    assert_eq!(retained.capacity(), capacity);
    assert_eq!(device.0.get(), 0);
}

#[test]
fn native_success_and_absent_device_keep_their_existing_paths() {
    let device = FailedDevice(Cell::new(0));
    let mut backend = CommittedBackend::with_device([0; 32], &device);
    assert_eq!(backend.on_device::<u64>(|_| Ok(37)), Some(Ok(37)));
    assert!(backend.failure.is_none());
    let mut cpu = CommittedBackend::new([0; 32]);
    assert_eq!(
        cpu.on_device::<()>(|_| panic!("CPU backend invoked a GPU callback")),
        None
    );
    assert!(cpu.failure.is_none());
}

#[cfg(feature = "native-verification-allocation-audit")]
#[test]
#[ignore = "process-wide allocation observer; coordinator must serialize"]
fn retaining_and_revisiting_native_failure_allocate_nothing() {
    use crate::component_tree::shake_verification_memory::observe_planner_allocations;
    let device = FailedDevice(Cell::new(0));
    let mut backend = CommittedBackend::with_device([0; 32], &device);
    // Upstream diagnostic creation is deliberately outside this ownership
    // boundary. This test does not claim to bound that original allocation.
    let mut diagnostic = String::with_capacity(4096);
    diagnostic.push_str("preallocated GPU diagnostic");
    let pointer = diagnostic.as_ptr();
    let capacity = diagnostic.capacity();
    observe_planner_allocations(0, || {
        assert_eq!(backend.on_device::<()>(|_| Err(diagnostic)), Some(Err(())));
        for _ in 0..1024 {
            assert_eq!(
                backend.on_device::<()>(|_| panic!("callback after first failure")),
                Some(Err(()))
            );
        }
    });
    let retained = backend.failure.as_ref().unwrap();
    assert_eq!(retained.as_ptr(), pointer);
    assert_eq!(retained.capacity(), capacity);
    assert_eq!(retained.as_str(), "preallocated GPU diagnostic");
}

#[test]
fn failed_infallible_operation_cannot_fall_back_or_release_graph() {
    let device = FailedDevice(Cell::new(0));
    let mut backend = CommittedBackend::with_device([0; 32], &device);
    let a = backend.constant(7, Q);
    let b = backend.constant(9, Q);
    let placeholder = backend.add(a, b, Q);
    assert_eq!(placeholder.value, 0);
    assert_eq!(device.0.get(), 1);
    assert_eq!(
        backend.failure.as_deref(),
        Some("injected GPU operation failure")
    );
    let value = witness_value!(&mut backend,
        next => next.canonical_add(7, 9, Q), panic!("CPU fallback after GPU failure"), 0);
    assert_eq!(value, 0);
    assert_eq!(device.0.get(), 1);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        backend.into_unproved_graph()
    }))
    .is_err());
}

#[test]
fn transcript_encoding_preserves_order_and_little_endian_coefficients() {
    let mut backend = CommittedBackend::new([0; 32]);
    let bytes = backend.byte_node([0xa5; 32], Source::Context);
    let values = core::array::from_fn(|i| 0x0102_0304 + i as u64);
    let poly = backend.canonical_node(values, Q, Source::ProofPolynomial { position: 0 });
    let graph = backend.into_unproved_graph();
    let encoded = transcript_bytes(
        &graph,
        &[
            TranscriptPart::Bytes(bytes),
            TranscriptPart::Polynomial(poly),
            TranscriptPart::Bytes(bytes),
        ],
    )
    .unwrap();
    assert_eq!(&encoded[..32], &[0xa5; 32]);
    assert_eq!(&encoded[32..36], &[4, 3, 2, 1]);
    assert_eq!(&encoded[36..40], &[5, 3, 2, 1]);
    assert_eq!(&encoded[32 + 4 * D..], &[0xa5; 32]);
}

#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "requires exclusive admitted OpenCL resources; full raw graph CPU/GPU parity"]
fn complete_gpu_graph_matches_cpu_values_commitments_shape_and_manifest() {
    use crate::execution::ProvingContext;
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
    let statement = Statement::decode(&fixture.statement).unwrap();
    let proof = Proof::decode(&fixture.proof).unwrap();
    let expected = lower_unproved(setup_seed, &context, &statement, &proof).unwrap();
    let worker = ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30,
        device_bytes: 8 << 30,
        max_rows: 2048,
    })
    .unwrap();
    let actual = lower_unproved_on_gpu(
        setup_seed,
        &context,
        &statement,
        &proof,
        &worker,
        8usize << 30,
    )
    .unwrap();
    assert_eq!(actual.polynomials.len(), expected.polynomials.len());
    assert_eq!(actual.bytes.len(), expected.bytes.len());
    for (index, (a, b)) in actual
        .polynomials
        .iter()
        .zip(&expected.polynomials)
        .enumerate()
    {
        assert_eq!(a.kind, b.kind, "polynomial {index} kind");
        assert_eq!(a.source, b.source, "polynomial {index} source");
        assert_eq!(a.commitment, b.commitment, "polynomial {index} commitment");
        match (&a.values, &b.values) {
            (PolynomialValues::Canonical(a), PolynomialValues::Canonical(b)) => {
                assert_eq!(a, b, "polynomial {index} canonical values")
            }
            (PolynomialValues::Signed(a), PolynomialValues::Signed(b)) => {
                assert_eq!(a, b, "polynomial {index} signed values")
            }
            _ => panic!("polynomial {index} value kind"),
        }
    }
    for (index, (a, b)) in actual.bytes.iter().zip(&expected.bytes).enumerate() {
        assert_eq!(a.source, b.source, "byte node {index} source");
        assert_eq!(a.values, b.values, "byte node {index} values");
        assert_eq!(a.commitment, b.commitment, "byte node {index} commitment");
    }
    let shape = RegisteredGraphShape::from_trusted_graph(&expected).unwrap();
    assert!(shape.matches(&actual));
    let expected_manifest = shape.node_manifest_hint(&expected).unwrap();
    let (actual_manifest, _) = worker
        .with_witness_preparation(8usize << 30, |operations| {
            shape
                .node_manifest_hint_on_gpu(&actual, operations)
                .map_err(|e| e.to_string())
        })
        .unwrap();
    assert_eq!(actual_manifest, expected_manifest);
    let diagnostics = worker.report();
    assert_eq!(diagnostics["operations"]["witness_preparation_calls"], 2);
    assert_eq!(
        diagnostics["operations"]["witness_preparation_complete_reports"],
        2
    );
    assert_eq!(diagnostics["operations"]["native_gpu_calls"], 0);
    assert_eq!(diagnostics["operations"]["native_cpu_calls"], 0);
    // Raw preparation creates no PCS commitments; dropping the worker closes
    // its engine without invoking proof-only finish acceptance.
    drop(worker);
}
mod batches;

struct RecipeDevice(Cell<usize>);
impl GraphDevice for RecipeDevice {
    fn canonical(&self, kind: CanonicalOperation, a: &[u64], b: &[u64], q: u64) -> Result<Vec<u64>, String> {
        self.0.set(self.0.get() + 1);
        Ok(a.iter().zip(b).map(|(&a, &b)| match kind {
            CanonicalOperation::Add => arithmetic::add(a, b, q),
            CanonicalOperation::Subtract => arithmetic::sub(a, b, q),
            CanonicalOperation::Montgomery => panic!("unexpected recipe multiplication"),
        }).collect())
    }
    fn inverse_challenge_poly(&self, x: &RawSigned) -> Result<RawSigned, String> {
        self.0.set(self.0.get() + 1);
        Ok(core::array::from_fn(|i| if (86..171).contains(&i) { -x[(3*i)%D] } else { x[(3*i)%D] }))
    }
    unexpected!(signed(kind: SignedOperation, input: &[u64], count: usize) -> Vec<u64>);
    unexpected!(convert(input: &[i64], q: u64) -> Vec<u64>);
    unexpected!(ntt_poly(input: &RawSigned, q: u64) -> RawPoly);
    unexpected!(mul_poly(left: &RawPoly, right: &RawPoly, q: u64) -> RawPoly);
    unexpected!(aut_poly(input: &RawPoly) -> RawPoly);
    unexpected!(commit_canonical(input: &RawPoly, q: u64) -> [Val; 4]);
    unexpected!(commit_signed(input: &RawSigned) -> [Val; 4]);
    unexpected!(commit_bytes(input: &[u8; 32]) -> [Val; 4]);
    unexpected!(parameters(seed: &[u8; 32], context: &[u8; 32]) -> primitives::Parameters);
    unexpected!(sample_g(seed: &[u8; 32]) -> Vec<RawPoly>);
    unexpected!(expand_alpha(seed: &[u8; 32]) -> (Vec<RawPoly>, RawSigned));
    unexpected!(hash_alpha(input: &[u8]) -> [u8; 32]);
    unexpected!(hash_x(input: &[u8]) -> RawSigned);
}
#[test]
fn vector_recipes_preserve_scalar_order_values_bounds_and_constant_folding() {
    let device = RecipeDevice(Cell::new(0));
    let mut backend = CommittedBackend::new([1; 32]);
    let id = backend.canonical_node(core::array::from_fn(|i| (i as u64 * 7654321) % Q), Q, Source::ProofPolynomial { position: 0 });
    let mut a = backend.canonical_refs(id);
    for i in (0..D).step_by(3) { a[i] = backend.constant(i as u64, Q); }
    let c = a.map(|v| backend.constant(v.value, Q));
    let id = backend.signed_node(core::array::from_fn(|i| [-2147483647, -1, 0, 2147483647][i%4]), 2147483647, Source::ProofPolynomial { position: 1 });
    let signed = backend.signed_refs(id);
    let start = backend.graph.expressions.len();
    let constants = backend.constants.clone();
    let mut w = relation_balance_scalar(&mut backend, &a, &c, &a, &c, &a);
    let t = relation_coin_term_scalar(&mut backend, &a, &c, &a, &c);
    relation_adjust_scalar(&mut backend, &mut w, &a, &c);
    let x = inverse_challenge_scalar(&mut backend, &signed);
    let expressions = backend.graph.expressions[start..].to_vec();
    backend.graph.expressions.truncate(start); backend.constants = constants;
    backend.device = Some(&device);
    let mut actual_w = backend.vector_relation_balance(&a, &c, &a, &c, &a);
    let actual_t = backend.vector_relation_coin_term(&a, &c, &a, &c);
    backend.vector_relation_adjust(&mut actual_w, &a, &c);
    let actual_x = backend.vector_inverse_challenge(&signed);
    assert_eq!(device.0.get(), 15);
    assert_eq!(&backend.graph.expressions[start..], expressions);
    assert_eq!(actual_w.map(|v| (v.expr, v.value, v.modulus)), w.map(|v| (v.expr, v.value, v.modulus)));
    assert_eq!(actual_t.map(|v| (v.expr, v.value)), t.map(|v| (v.expr, v.value)));
    assert_eq!(actual_x.map(|v| (v.expr, v.value, v.bound)), x.map(|v| (v.expr, v.value, v.bound)));
    assert!(backend.graph.operations.is_empty());
}
#[test]
fn vector_recipes_reject_foreign_operands_and_never_fallback_after_failure() {
    let failed = FailedDevice(Cell::new(0));
    let mut backend = CommittedBackend::new([1; 32]);
    let mut foreign = CommittedBackend::new([1; 32]);
    let a = [backend.constant(1, Q); D];
    let b = [foreign.constant(1, Q); D];
    backend.device = Some(&failed);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.vector_relation_coin_term(&a, &b, &a, &a))).is_err());
    assert_eq!(failed.0.get(), 0);
    let mut w = backend.vector_relation_balance(&a, &a, &a, &a, &a);
    backend.vector_relation_coin_term(&a, &a, &a, &a);
    backend.vector_relation_adjust(&mut w, &a, &a);
    assert_eq!(failed.0.get(), 1);
    assert_eq!(backend.failure.as_deref(), Some("injected GPU operation failure"));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.into_unproved_graph())).is_err());
}
