//! Dispatch and arithmetic conformance against p3-field 0.6.1 before the patch.
//! The original registry archive is pinned by the qualification evidence.

use super::Val;
use p3_field::{
    batch_multiplicative_inverse as selected, batch_multiplicative_inverse_general, ExtensionField,
    Field, FieldArray, PackedValue, PrimeCharacteristicRing,
};
use rayon::prelude::*;

// Original arithmetic and parallel dispatch, without its tracing attribute.
fn original<F: Field>(x: &[F]) -> Vec<F> {
    const CHUNK_SIZE: usize = 1024;
    const WIDTH: usize = 4;
    let mut result = F::zero_vec(x.len());
    x.par_chunks(CHUNK_SIZE)
        .zip(result.par_chunks_mut(CHUNK_SIZE))
        .for_each(|(x_chunk, result_chunk)| {
            let (x_packed, x_tail) = FieldArray::<F, WIDTH>::pack_slice_with_suffix(x_chunk);
            let (result_packed, result_tail) =
                FieldArray::<F, WIDTH>::pack_slice_with_suffix_mut(result_chunk);
            batch_multiplicative_inverse_general(x_packed, result_packed, |y| {
                // Frozen FieldArray::inverse body; that method is crate-private.
                let mut inverse = FieldArray::<F, WIDTH>::default();
                batch_multiplicative_inverse_general(&y.0, &mut inverse.0, |x| x.inverse());
                inverse
            });
            if !x_tail.is_empty() {
                batch_multiplicative_inverse_general(x_tail, result_tail, |y| y.inverse());
            }
        });
    result
}

const LENGTHS: [usize; 25] = [
    0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1023, 1024, 1025, 2047, 2048,
    2049, 4097,
];

fn values<F: ExtensionField<Val>>(count: usize) -> Vec<F> {
    (0..count)
        .map(|i| {
            F::from_basis_coefficients_fn(|j| {
                Val::from_u64(((i + 1) * (j + 1) * 17 + j * j) as u64)
            })
        })
        .collect()
}

fn conformance<F: ExtensionField<Val> + serde::Serialize>() {
    for length in LENGTHS {
        let input = values::<F>(length);
        let expected = original(&input);
        let actual = selected(&input);
        assert_eq!(actual, expected, "length={length}");
        assert_eq!(actual.capacity(), expected.capacity());
        assert_eq!(
            postcard::to_allocvec(&actual).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
        for (&x, &inverse) in input.iter().zip(&actual) {
            assert_eq!(inverse, x.inverse());
            assert_eq!(x * inverse, F::ONE);
        }
    }
}

#[test]
fn packed_tail_and_chunk_boundaries_match_original_and_elementwise_inverses() {
    conformance::<Val>();
    conformance::<crate::config::Challenge>();
    conformance::<crate::block_v2::profile::Challenge>();
    eprintln!("verifier_inverse_conformance fields=3 lengths=25 original=true elementwise=true encoding=true capacity=true");
}

fn zero_conformance<F: ExtensionField<Val>>() {
    for length in [1, 2, 3, 4, 17, 1024, 1025, 2049] {
        for index in [0, length / 2, length - 1] {
            let mut input = values::<F>(length);
            input[index] = F::ZERO;
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| original(&input)))
                    .is_err()
            );
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| selected(&input)))
                    .is_err()
            );
        }
    }
}

#[test]
fn zero_inputs_keep_the_original_failure_contract() {
    zero_conformance::<Val>();
    zero_conformance::<crate::config::Challenge>();
    zero_conformance::<crate::block_v2::profile::Challenge>();
    eprintln!("verifier_inverse_zero_parity fields=3 lengths=8 positions=3");
}

#[cfg(target_os = "linux")]
fn local<F: ExtensionField<Val>>() {
    for length in LENGTHS.into_iter().filter(|&n| n <= 1024) {
        let input = values::<F>(length);
        let inverse = selected(&input);
        assert_eq!(inverse.len(), length);
        assert!(input.iter().zip(inverse).all(|(&x, y)| x * y == F::ONE));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn cold_process_single_chunk_needs_no_rayon_pool() {
    const CHILD: &str = "LATTICA_VERIFIER_INVERSE_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        // Limit only this fresh test process. No user limit or parent process is
        // changed. Existing harness threads keep running; new Rayon threads
        // cannot be created. Root would bypass RLIMIT_NPROC, so require nonroot.
        unsafe {
            assert_ne!(libc::geteuid(), 0);
            let mut limit: libc::rlimit = core::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut limit), 0);
            limit.rlim_cur = 0;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NPROC, &limit), 0);
        }
        match mode.as_str() {
            "small" => {
                local::<Val>();
                local::<crate::config::Challenge>();
                local::<crate::block_v2::profile::Challenge>();
                // The frozen original cannot run even the two-element case.
                assert!(std::panic::catch_unwind(|| original(&[Val::ONE; 2])).is_err());
                eprintln!("verifier_inverse_cold fields=3 max_elements=1024 selected=caller original=pool_required");
            }
            "large" => {
                // More than one chunk retains the original parallel dispatch.
                assert!(std::panic::catch_unwind(|| selected(&[Val::ONE; 1025])).is_err());
                eprintln!("verifier_inverse_large elements=1025 selected=pool_required");
            }
            _ => panic!("unknown inversion probe mode"),
        }
        return;
    }
    for mode in ["small", "large"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "block_v2::machine::backend::inverse_tests::cold_process_single_chunk_needs_no_rayon_pool",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{mode}: {stderr}");
        assert!(stderr.contains(if mode == "small" {
            "selected=caller original=pool_required"
        } else {
            "elements=1025 selected=pool_required"
        }));
        eprint!("{stderr}");
    }
}
