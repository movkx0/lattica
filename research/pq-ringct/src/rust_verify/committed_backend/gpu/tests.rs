use super::*;
use std::cell::Cell;

struct FailedDevice(Cell<usize>);
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
