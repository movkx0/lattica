//! Independent CPU arithmetic versus the actual reserved GPU graph. This is
//! test-only and compares witness hints; it confers no proof acceptance.
use super::*;
use p3_field::PrimeCharacteristicRing;

struct Graphs<'a> {
    left: &'a UnprovedRelationGraph,
    right: &'a UnprovedRelationGraph,
}
impl Graphs<'_> {
    fn polynomial(&self, left: PolyId, right: PolyId) -> bool {
        left.owner == self.left.owner
            && right.owner == self.right.owner
            && left.index == right.index
            && left.index < self.left.polynomials.len()
            && right.index < self.right.polynomials.len()
    }
    fn bytes(&self, left: BytesId, right: BytesId) -> bool {
        left.owner == self.left.owner
            && right.owner == self.right.owner
            && left.index == right.index
            && left.index < self.left.bytes.len()
            && right.index < self.right.bytes.len()
    }
    fn polynomials(&self, left: &[PolyId], right: &[PolyId]) -> bool {
        left.len() == right.len() && left.iter().zip(right).all(|(&a, &b)| self.polynomial(a, b))
    }
    fn transcript(&self, left: &[TranscriptPart], right: &[TranscriptPart]) -> bool {
        left.len() == right.len()
            && left.iter().zip(right).all(|(a, b)| match (a, b) {
                (TranscriptPart::Bytes(a), TranscriptPart::Bytes(b)) => self.bytes(*a, *b),
                (TranscriptPart::Polynomial(a), TranscriptPart::Polynomial(b)) => {
                    self.polynomial(*a, *b)
                }
                _ => false,
            })
    }
    fn expression(&self, left: &Expression, right: &Expression) -> bool {
        match (left, right) {
            (
                Expression::CanonicalInput {
                    polynomial: a,
                    index: i,
                },
                Expression::CanonicalInput {
                    polynomial: b,
                    index: j,
                },
            )
            | (
                Expression::SignedInput {
                    polynomial: a,
                    index: i,
                },
                Expression::SignedInput {
                    polynomial: b,
                    index: j,
                },
            ) => i == j && *i < D && self.polynomial(*a, *b),
            // All other variants contain scalar indices/parameters, no graph
            // owner IDs. Derived PartialEq compares their exact typed fields.
            _ => left == right,
        }
    }
    fn operation(&self, left: &Operation, right: &Operation) -> bool {
        use Operation::*;
        match (left, right) {
            (
                CanonicalMap {
                    modulus: a,
                    inputs: ai,
                    expressions: ae,
                    output: ao,
                },
                CanonicalMap {
                    modulus: b,
                    inputs: bi,
                    expressions: be,
                    output: bo,
                },
            ) => a == b && ae == be && self.polynomials(ai, bi) && self.polynomial(*ao, *bo),
            (
                SignedMap {
                    bound: a,
                    inputs: ai,
                    expressions: ae,
                    output: ao,
                },
                SignedMap {
                    bound: b,
                    inputs: bi,
                    expressions: be,
                    output: bo,
                },
            ) => a == b && ae == be && self.polynomials(ai, bi) && self.polynomial(*ao, *bo),
            (
                Add {
                    modulus: a,
                    left: al,
                    right: ar,
                    output: ao,
                },
                Add {
                    modulus: b,
                    left: bl,
                    right: br,
                    output: bo,
                },
            )
            | (
                Sub {
                    modulus: a,
                    left: al,
                    right: ar,
                    output: ao,
                },
                Sub {
                    modulus: b,
                    left: bl,
                    right: br,
                    output: bo,
                },
            )
            | (
                Mul {
                    modulus: a,
                    left: al,
                    right: ar,
                    output: ao,
                },
                Mul {
                    modulus: b,
                    left: bl,
                    right: br,
                    output: bo,
                },
            ) => {
                a == b
                    && self.polynomial(*al, *bl)
                    && self.polynomial(*ar, *br)
                    && self.polynomial(*ao, *bo)
            }
            (
                AutomorphismQ {
                    input: a,
                    output: ao,
                },
                AutomorphismQ {
                    input: b,
                    output: bo,
                },
            ) => self.polynomial(*a, *b) && self.polynomial(*ao, *bo),
            (
                SignedToCanonical {
                    bound: a,
                    modulus: aq,
                    input: ai,
                    output: ao,
                },
                SignedToCanonical {
                    bound: b,
                    modulus: bq,
                    input: bi,
                    output: bo,
                },
            ) => a == b && aq == bq && self.polynomial(*ai, *bi) && self.polynomial(*ao, *bo),
            (
                Ntt {
                    modulus: a,
                    input: ai,
                    output: ao,
                },
                Ntt {
                    modulus: b,
                    input: bi,
                    output: bo,
                },
            ) => a == b && self.polynomial(*ai, *bi) && self.polynomial(*ao, *bo),
            (
                Norm {
                    inputs: a,
                    maximum: am,
                },
                Norm {
                    inputs: b,
                    maximum: bm,
                },
            ) => am == bm && self.polynomials(a, b),
            (
                GBound {
                    f: a,
                    x: ax,
                    bound: ab,
                },
                GBound {
                    f: b,
                    x: bx,
                    bound: bb,
                },
            ) => ab == bb && self.polynomial(*a, *b) && self.polynomial(*ax, *bx),
            (EqualBytes { left: a, right: ar }, EqualBytes { left: b, right: br }) => {
                self.bytes(*a, *b) && self.bytes(*ar, *br)
            }
            (EqualSigned { left: a, right: ar }, EqualSigned { left: b, right: br }) => {
                self.polynomial(*a, *b) && self.polynomial(*ar, *br)
            }
            (
                ByteMap {
                    inputs: a,
                    output: ao,
                },
                ByteMap {
                    inputs: b,
                    output: bo,
                },
            ) => {
                self.bytes(*ao, *bo)
                    && a.iter()
                        .zip(b)
                        .all(|(&(a, ai), &(b, bi))| ai == bi && ai < 32 && self.bytes(a, b))
            }
            (
                ParametersPp {
                    setup_seed: a,
                    context: ac,
                    output: ao,
                },
                ParametersPp {
                    setup_seed: b,
                    context: bc,
                    output: bo,
                },
            ) => a == b && self.bytes(*ac, *bc) && self.bytes(*ao, *bo),
            (
                SampleG {
                    seed: a,
                    output: ao,
                },
                SampleG {
                    seed: b,
                    output: bo,
                },
            ) => self.bytes(*a, *b) && self.polynomials(ao, bo),
            (
                ExpandAlpha {
                    seed: a,
                    canonical: ac,
                    signed: as_,
                },
                ExpandAlpha {
                    seed: b,
                    canonical: bc,
                    signed: bs,
                },
            ) => self.bytes(*a, *b) && self.polynomials(ac, bc) && self.polynomial(*as_, *bs),
            (
                HashAlpha {
                    parts: a,
                    output: ao,
                },
                HashAlpha {
                    parts: b,
                    output: bo,
                },
            ) => self.transcript(a, b) && self.bytes(*ao, *bo),
            (
                HashX {
                    parts: a,
                    output: ao,
                },
                HashX {
                    parts: b,
                    output: bo,
                },
            ) => self.transcript(a, b) && self.polynomial(*ao, *bo),
            _ => false,
        }
    }
}

/// No serialization, hashes, allocations, graph clones or shape-only shortcuts.
/// Every field is compared; only the independently issued owner IDs normalize,
/// and each reference must still belong to its own actual graph.
fn compare(left: &UnprovedRelationGraph, right: &UnprovedRelationGraph) -> Result<()> {
    if left.setup_seed != right.setup_seed
        || left.polynomials.len() != right.polynomials.len()
        || left.bytes.len() != right.bytes.len()
        || left.expressions.len() != right.expressions.len()
        || left.operations.len() != right.operations.len()
    {
        return Err("reference graph profile or cardinality mismatch");
    }
    for (a, b) in left.polynomials.iter().zip(&right.polynomials) {
        let values = match (&a.values, &b.values) {
            (PolynomialValues::Canonical(a), PolynomialValues::Canonical(b)) => a == b,
            (PolynomialValues::Signed(a), PolynomialValues::Signed(b)) => a == b,
            _ => false,
        };
        if a.kind != b.kind
            || a.source != b.source
            || a.commitment != b.commitment
            || a.expressions != b.expressions
            || !values
        {
            return Err("reference polynomial value, root, source or expression mismatch");
        }
    }
    for (a, b) in left.bytes.iter().zip(&right.bytes) {
        if a.source != b.source || a.values != b.values || a.commitment != b.commitment {
            return Err("reference byte value, root or source mismatch");
        }
    }
    let pair = Graphs { left, right };
    if !left
        .expressions
        .iter()
        .zip(&right.expressions)
        .all(|(a, b)| pair.expression(a, b))
    {
        return Err("reference expression topology or parameter mismatch");
    }
    if !left
        .operations
        .iter()
        .zip(&right.operations)
        .all(|(a, b)| pair.operation(a, b))
    {
        return Err("reference operation order, parameter or edge mismatch");
    }
    Ok(())
}

// Changes remain inside the original graph owner and never change capacity.
// These checks run on the real CPU/GPU pair as well as a small CPU-only fixture.
fn reject_mutations(actual: &mut UnprovedRelationGraph, expected: &UnprovedRelationGraph) -> usize {
    compare(actual, expected).unwrap();
    actual.setup_seed[0] ^= 1;
    assert!(compare(actual, expected).is_err());
    actual.setup_seed[0] ^= 1;
    let PolynomialValues::Canonical(values) = &mut actual.polynomials[0].values else {
        panic!("fixed first polynomial must be canonical");
    };
    values[0] ^= 1;
    assert!(compare(actual, expected).is_err());
    let PolynomialValues::Canonical(values) = &mut actual.polynomials[0].values else {
        unreachable!()
    };
    values[0] ^= 1;
    actual.polynomials[0].commitment[0] += Val::ONE;
    assert!(compare(actual, expected).is_err());
    actual.polynomials[0].commitment[0] -= Val::ONE;
    let previous = std::mem::replace(&mut actual.polynomials[0].source, Source::Fixed);
    assert_ne!(previous, Source::Fixed);
    assert!(compare(actual, expected).is_err());
    actual.polynomials[0].source = previous;
    actual.polynomials[0].expressions[0] ^= 1;
    assert!(compare(actual, expected).is_err());
    actual.polynomials[0].expressions[0] ^= 1;
    actual.bytes[0].values[0] ^= 1;
    assert!(compare(actual, expected).is_err());
    actual.bytes[0].values[0] ^= 1;
    actual.bytes[0].commitment[0] += Val::ONE;
    assert!(compare(actual, expected).is_err());
    actual.bytes[0].commitment[0] -= Val::ONE;
    let first = actual.polynomials[0].expressions[0];
    let Expression::CanonicalInput { polynomial, .. } = &mut actual.expressions[first] else {
        panic!("fixed canonical input expression");
    };
    polynomial.owner ^= 1;
    assert!(compare(actual, expected).is_err());
    let Expression::CanonicalInput { polynomial, .. } = &mut actual.expressions[first] else {
        unreachable!()
    };
    polynomial.owner ^= 1;
    let add_index = actual
        .operations
        .iter()
        .position(|op| matches!(op, Operation::Add { .. }))
        .unwrap();
    let Operation::Add { modulus, .. } = &mut actual.operations[add_index] else {
        unreachable!()
    };
    *modulus ^= 1;
    assert!(compare(actual, expected).is_err());
    let Operation::Add {
        modulus, output, ..
    } = &mut actual.operations[add_index]
    else {
        unreachable!()
    };
    *modulus ^= 1;
    output.owner ^= 1;
    assert!(compare(actual, expected).is_err());
    let Operation::Add { output, .. } = &mut actual.operations[add_index] else {
        unreachable!()
    };
    output.owner ^= 1;
    let different = actual
        .operations
        .iter()
        .position(|op| op != &actual.operations[0])
        .unwrap();
    actual.operations.swap(0, different);
    assert!(compare(actual, expected).is_err());
    actual.operations.swap(0, different);
    let removed = actual.operations.pop().unwrap();
    assert!(compare(actual, expected).is_err());
    actual.operations.push(removed);
    compare(actual, expected).unwrap();
    12
}

#[test]
fn graph_differential_normalizes_only_owner_identity_and_rejects_mutations() {
    fn fixture() -> UnprovedRelationGraph {
        let mut backend = CommittedBackend::new([29; 32]);
        let a = backend.canonical_node([7; D], Q, Source::StatementPolynomial { position: 0 });
        let b = backend.canonical_node([14; D], Q, Source::Derived { operation: 0 });
        let c = backend.byte_node([71; 32], Source::Context);
        backend.graph.operations.push(Operation::Add {
            modulus: Q,
            left: a,
            right: a,
            output: b,
        });
        backend
            .graph
            .operations
            .push(Operation::EqualBytes { left: c, right: c });
        backend.into_unproved_graph()
    }
    let mut actual = fixture();
    let expected = fixture();
    assert_ne!(actual.owner, expected.owner);
    compare(&actual, &expected).unwrap();
    assert_eq!(reject_mutations(&mut actual, &expected), 12);
}

#[cfg(all(
    feature = "owned-gpu-runtime",
    feature = "native-matrict",
    target_os = "linux"
))]
mod qualification {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;
    use crate::native::{self, FixtureAmounts, NativeFixture};
    use crate::opencl::{Limits, PendingRuntime};
    use std::time::Instant;

    /// Additional CPU-only scratch. The actual CPU graph has its own complete
    /// Construction owner; none of its native arithmetic is charged as GPU work.
    /// Conservatively sum every fixed primitive return plus unpacked transcript
    /// input, ignoring disjoint lifetimes. No compiled-stack/RSS claim is made.
    struct CpuReferenceScratch {
        _reservation: Reservation,
    }
    impl CpuReferenceScratch {
        fn bytes() -> Result<usize> {
            use super::super::super::bounds::{backing, mul};
            let c = Ceilings::fixed();
            // hash_alpha reconstructs one native Statement; the complete fixed
            // statement+proof decoder ceiling is a deliberate overcharge.
            let decoded = mul(3, inputs::decoded_retained_bytes()?)?;
            // Parameters, samplers and transcript-unpack arrays are ordinary
            // CPU Vecs. Triple fixed lengths cover allocation growth overlap.
            let polys = add(185 + 4 + 4 + 2, add(c.alpha_parts, c.x_parts)?)?;
            let mut host = add(decoded, backing::<[u64; D]>(mul(3, polys)?)?)?;
            host = add(host, backing::<Vec<[u64; D]>>(3 * (7 + 4 + 29 + 2))?)?;
            let alpha_bytes = add(
                mul(mul(c.alpha_parts.checked_sub(3).ok_or(BUDGET)?, D)?, 4)?,
                3 * 32,
            )?;
            let x_bytes = add(
                mul(mul(c.x_parts.checked_sub(1).ok_or(BUDGET)?, D)?, 4)?,
                32,
            )?;
            host = add(host, mul(3, add(alpha_bytes, x_bytes)?)?)?;
            for bytes in [
                32,
                32,
                7648 * 4,
                3366 * 4,
                37232 * 5,
                1197 * 4,
                1197 * 4,
                643 * 4,
                127,
                32,
                137,
                32 + 6 + 2 + 4 + 4 + 1,
                b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".len() + 64,
            ] {
                host = add(host, mul(3, add(bytes, 15)?)?)?;
            }
            // Sequential scalar Poseidon construction: two four-by-eight
            // external constant Vecs and one 22-element internal Vec. Three
            // copies conservatively cover constructor overlap, not parallelism.
            host = add(host, 3 * (32 + 22 + 32) * size_of::<Val>())?;
            for bytes in [
                size_of::<Self>(),
                size_of::<primitives::AesStream>(),
                size_of::<sha3::Shake256>(),
                size_of::<sha3::Shake256Reader>(),
                size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>(),
                32 * size_of::<Vec<u64>>(),
                4 * size_of::<[u64; D]>(),
            ] {
                host = add(host, bytes)?;
            }
            Ok(host)
        }
        fn reserve(ledger: &Ledger) -> Result<Self> {
            let host = Self::bytes()?;
            let _reservation = ledger
                .reserve(
                    Category::PhaseScratch,
                    Bytes {
                        host: u64::try_from(host).map_err(|_| BUDGET)?,
                        device: 0,
                    },
                )
                .map_err(|_| "CPU reference scratch reservation refused")?;
            Ok(Self { _reservation })
        }
    }

    #[test]
    fn cpu_reference_scratch_is_additive_and_refuses_before_lowering() {
        let bytes = CpuReferenceScratch::bytes().unwrap() as u64;
        let small = Ledger::new(WorkerAllowance {
            host: bytes - 1,
            device: 0,
        });
        assert!(CpuReferenceScratch::reserve(&small).is_err());
        assert_eq!(small.snapshot().current, Bytes::ZERO);
        assert_eq!(small.snapshot().peak, Bytes::ZERO);
        let original = Ledger::new(WorkerAllowance {
            host: bytes + 1,
            device: 0,
        });
        let preceding = original
            .reserve(Category::CompilerInputs, Bytes { host: 1, device: 0 })
            .unwrap();
        let baseline = original.snapshot().current;
        let scratch = CpuReferenceScratch::reserve(&original).unwrap();
        assert!(scratch._reservation.belongs_to(&original));
        assert_eq!(original.snapshot().current.host, bytes + 1);
        assert_eq!(original.snapshot().current.device, 0);
        let moved = Some(scratch);
        assert!(CpuReferenceScratch::reserve(&original).is_err());
        drop(moved);
        assert_eq!(original.snapshot().current, baseline);
        drop(preceding);
        assert_eq!(original.snapshot().current, Bytes::ZERO);
    }

    #[test]
    #[ignore = "fixed guarded RTX 5080 worker; genuine CPU/GPU raw graph differential; coordinator only"]
    fn gpu_reserved_source_graph_matches_independent_cpu_and_rejects_mutations() {
        let context = [71; 32];
        let setup_seed = [29; 32];
        // Native C fixture generation/verification remains outside all three
        // reported intervals. Its real retained backing reduces worker quota.
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
        assert_eq!(fixture.statement.len(), STATEMENT_BYTES);
        assert_eq!(fixture.proof.len(), PROOF_BYTES);
        let fixture_bytes = fixture
            .statement
            .capacity()
            .checked_add(fixture.proof.capacity())
            .unwrap()
            .checked_add(size_of::<NativeFixture>())
            .unwrap() as u64;
        let ledger = Ledger::new(WorkerAllowance {
            host: (32u64 << 30).checked_sub(fixture_bytes).unwrap(),
            device: 8 << 30,
        });
        let pending = PendingRuntime::reserve(
            &ledger,
            Limits {
                host_bytes: 32 << 30,
                device_bytes: 8 << 30,
                max_rows: 2048,
            },
        )
        .unwrap();
        let startup = pending.reserved_bytes();
        let cpu_scratch = CpuReferenceScratch::reserve(&ledger).unwrap();
        let cpu_source = Construction::new(
            setup_seed,
            context,
            &fixture.statement,
            &fixture.proof,
            &ledger,
        )
        .unwrap();
        let gpu_source = Construction::new(
            setup_seed,
            context,
            &fixture.statement,
            &fixture.proof,
            &ledger,
        )
        .unwrap();
        assert!(cpu_source.belongs_to(&ledger) && gpu_source.belongs_to(&ledger));
        // Both full source owners and extra CPU scratch precede any lowering.
        // CPU uses the legacy scalar arithmetic/AES/SHAKE/Poseidon code paths,
        // with no DeviceSession, operation report or GPU receipt.
        let cpu_started = Instant::now();
        let reference = cpu_source
            .lower(CommittedBackend::new(setup_seed))
            .unwrap()
            .after_callback();
        let cpu_ns = cpu_started.elapsed().as_nanos();
        drop(cpu_scratch);
        assert!(reference.belongs_to(&ledger));
        let before_start = ledger.snapshot().current;
        let startup_started = Instant::now();
        // SAFETY: exact isolated ignored test under root's sealed env-clear
        // process/VRAM guard, no environment mutations or unrelated GPU work.
        let session = unsafe { pending.start().unwrap() };
        let startup_ns = startup_started.elapsed().as_nanos();
        assert_eq!(ledger.snapshot().current, before_start);
        let gpu_started = Instant::now();
        let mut actual =
            crate::execution::prepare_owned_graph(&session, gpu_source, &ledger).unwrap();
        let gpu_ns = gpu_started.elapsed().as_nanos();
        assert!(actual.belongs_to(&ledger));
        assert_eq!(actual.context(), reference.context());
        assert_eq!(actual.context(), &context);
        assert_ne!(actual.graph.owner, reference.graph.owner);
        assert_eq!(ledger.snapshot().current.device, startup.device);
        let comparison_started = Instant::now();
        compare(&actual.graph, &reference.graph).unwrap();
        let comparison_ns = comparison_started.elapsed().as_nanos();
        let before_mutations = ledger.snapshot();
        let mutations = reject_mutations(&mut actual.graph, &reference.graph);
        assert_eq!(ledger.snapshot(), before_mutations);
        let counts = [
            actual.graph.polynomials.len(),
            actual.graph.bytes.len(),
            actual.graph.expressions.len(),
            actual.graph.operations.len(),
        ];
        drop(actual);
        drop(reference);
        assert_eq!(ledger.snapshot().current, startup);
        let retired = session.finish_reserved().unwrap();
        assert_eq!(retired.managed_live_bytes, 0);
        assert_eq!(retired.host_tree_live_bytes, 0);
        assert!(retired.lease_released);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        drop(fixture);
        eprintln!("reserved_raw_graph_differential polynomials={} byte_nodes={} expressions={} operations={} cpu_reference_ns={cpu_ns} runtime_startup_ns={startup_ns} raw_gpu_preparation_ns={gpu_ns} exact_comparison_ns={comparison_ns} mutation_cases={mutations} independent_cpu_arithmetic=true original_ledger_retired=true proof_completion=false complete_workflow_measurement=false", counts[0], counts[1], counts[2], counts[3]);
    }
}
