use super::*;
use crate::{config::Val, gpu_matrix::GOLDILOCKS_MODULUS as P};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};

#[test]
fn field_spans_reject_overflow_and_partial_aliases() {
    assert_eq!(extent(3, 17, 3, 55).unwrap(), 54);
    for (first, count, degree, words) in [
        (0, 0, 1, 4),
        (0, 1, 0, 4),
        (0, 1, 4, 4),
        (0, usize::MAX, 3, usize::MAX),
        (usize::MAX, 1, 1, usize::MAX),
        (3, 17, 3, 53),
    ] {
        assert!(extent(first, count, degree, words).is_err());
    }
    assert!(!partial_overlap(3, 3, 51));
    assert!(!partial_overlap(3, 54, 51));
    assert!(partial_overlap(3, 53, 51));
    assert!(partial_overlap(53, 3, 51));
}

fn oracle<F: ExtensionField<Val>>(a: &[u64], b: &[u64], operation: FieldOperation) -> Vec<u64> {
    a.chunks_exact(F::DIMENSION)
        .zip(b.chunks_exact(F::DIMENSION))
        .flat_map(|(a, b)| {
            let a = F::from_basis_coefficients_iter(a.iter().map(|x| Val::from_u64(*x))).unwrap();
            let b = F::from_basis_coefficients_iter(b.iter().map(|x| Val::from_u64(*x))).unwrap();
            let value = match operation {
                FieldOperation::Canonicalize => a,
                FieldOperation::Negate => -a,
                FieldOperation::InverseOrZero => a.try_inverse().unwrap_or(F::ZERO),
                FieldOperation::Power(exponent) => a.exp_u64(exponent),
                FieldOperation::Add => a + b,
                FieldOperation::Subtract => a - b,
                FieldOperation::Multiply => a * b,
            };
            value
                .as_basis_coefficients_slice()
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
#[ignore = "requires CUDA and pinned NVRTC; run serially after proof benchmarks"]
fn cuda_field_arithmetic_matches_independent_cpu_fields_with_guards() {
    let uuid = std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap();
    let runtime = Runtime::new(
        &uuid,
        super::super::Limits {
            managed_bytes: 16 << 20,
            max_allocation_bytes: 8 << 20,
            ..super::super::Limits::default()
        },
    )
    .unwrap();
    let program = FieldProgram::new(&runtime).unwrap();
    let mut boundaries = vec![0, 1, 2, 7, P - 2, P - 1, P, P + 1, u64::MAX - 1, u64::MAX];
    for bit in 1..64 {
        boundaries.extend([(1u64 << bit) - 1, 1u64 << bit, (1u64 << bit) + 1]);
    }
    // All boundary pairs exercise carry/borrow/high-half reduction; append a
    // deterministic corpus solely for testing (never a production RNG).
    let mut pairs: Vec<_> = boundaries
        .iter()
        .flat_map(|a| boundaries.iter().map(move |b| (*a, *b)))
        .collect();
    let mut state = 0xd1b5_4a32_d192_ed03u64;
    for _ in 0..1027 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        pairs.push((
            state,
            state.rotate_left(29).wrapping_add(0x9e37_79b9_7f4a_7c15),
        ));
    }
    const GUARD: u64 = 0xa5a5_936c_d18e_72b4;
    for extension in [Extension::Base, Extension::Quadratic, Extension::Cubic] {
        let degree = extension.degree();
        let count = pairs.len() + 2;
        let mut a = vec![GUARD; count * degree + 8];
        let mut b = a.clone();
        a[3..3 + degree].fill(0);
        b[3..3 + degree].fill(0);
        a[3 + degree..3 + 2 * degree].fill(P);
        b[3 + degree..3 + 2 * degree].fill(P);
        for (i, &(x, y)) in pairs.iter().enumerate() {
            for coefficient in 0..degree {
                let at = 3 + (i + 2) * degree + coefficient;
                a[at] = if coefficient == 0 {
                    x
                } else {
                    pairs[(i + coefficient * 97) % pairs.len()].0
                };
                b[at] = if coefficient == 0 {
                    y
                } else {
                    pairs[(i + coefficient * 71) % pairs.len()].1
                };
            }
        }
        let left = runtime.allocate(a.len()).unwrap();
        let right = runtime.allocate(b.len()).unwrap();
        let output = runtime.allocate(a.len()).unwrap();
        left.write(0, &a).unwrap();
        right.write(0, &b).unwrap();
        let operations = [
            FieldOperation::Canonicalize,
            FieldOperation::Negate,
            FieldOperation::InverseOrZero,
            FieldOperation::Power(0),
            FieldOperation::Power(1),
            FieldOperation::Power(7),
            FieldOperation::Power(u64::MAX),
            FieldOperation::Add,
            FieldOperation::Subtract,
            FieldOperation::Multiply,
        ];
        for operation in operations {
            let rhs = operation.code().2.then_some(FieldSpan {
                buffer: &right,
                first: 3,
            });
            output.write(0, &vec![GUARD; a.len()]).unwrap();
            let a_values = &a[3..3 + count * degree];
            let b_values = &b[3..3 + count * degree];
            let expected =
                match extension {
                    Extension::Base => oracle::<Val>(a_values, b_values, operation),
                    Extension::Quadratic => {
                        oracle::<crate::config::Challenge>(a_values, b_values, operation)
                    }
                    Extension::Cubic => oracle::<
                        p3_field::extension::CubicTrinomialExtensionField<Val>,
                    >(a_values, b_values, operation),
                };
            program
                .apply(
                    operation,
                    extension,
                    count,
                    FieldSpan {
                        buffer: &left,
                        first: 3,
                    },
                    rhs,
                    FieldSpan {
                        buffer: &output,
                        first: 3,
                    },
                )
                .unwrap()
                .finish()
                .unwrap();
            let mut actual = vec![0; a.len()];
            output.read(0, &mut actual).unwrap();
            assert_eq!(&actual[..3], &[GUARD; 3]);
            assert_eq!(&actual[3 + count * degree..], &[GUARD; 5]);
            assert_eq!(
                &actual[3..3 + count * degree],
                expected,
                "{extension:?} {operation:?}"
            );
        }
        let before = runtime.snapshot();
        for first in [2, 4, usize::MAX] {
            assert!(program
                .apply(
                    FieldOperation::Negate,
                    extension,
                    count,
                    FieldSpan {
                        buffer: &left,
                        first: 3
                    },
                    None,
                    FieldSpan {
                        buffer: &left,
                        first
                    }
                )
                .is_err());
        }
        assert_eq!(runtime.snapshot(), before);
        let mut retained = vec![0; a.len()];
        left.read(0, &mut retained).unwrap();
        assert_eq!(retained, a);
        right.read(0, &mut retained).unwrap();
        assert_eq!(retained, b);
        program
            .apply(
                FieldOperation::Negate,
                extension,
                count,
                FieldSpan {
                    buffer: &left,
                    first: 3,
                },
                None,
                FieldSpan {
                    buffer: &left,
                    first: 3,
                },
            )
            .unwrap()
            .finish()
            .unwrap();
        left.read(0, &mut retained).unwrap();
        assert_eq!(&retained[..3], &[GUARD; 3]);
        assert_eq!(&retained[3 + count * degree..], &[GUARD; 5]);
        assert_eq!(
            &retained[3..3 + count * degree],
            a[3..3 + count * degree]
                .iter()
                .map(|w| (-Val::from_u64(*w)).as_canonical_u64())
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(runtime.snapshot().live_bytes, 0);
    runtime.finish().unwrap();
}

#[test]
#[ignore = "requires pinned NVRTC but no GPU context"]
fn cuda_field_source_compiles_for_volta_and_blackwell() {
    for capability in [70, 120] {
        let ptx = super::super::compiler::compile(SOURCE, capability).unwrap();
        assert!(!ptx.is_empty());
    }
}
