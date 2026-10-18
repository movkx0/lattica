use super::*;
use crate::block_v2::gpu_hash::{
    self,
    device::{DeviceSession, Extension, MatrixSpec, RowOrder},
    FriExtension, Limits, TestShutdownGuard,
};
use crate::config::{Dft, MyCompress, MyHash};
use p3_air::symbolic::SymbolicExpressionExt;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::Algebra;
use p3_field::{Field, PrimeField64, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use std::sync::Arc;

use crate::block_v2::quotient_program::test_support::{constant, program, words};

#[test]
fn extension_compiler_uses_compact_rows_parameters_and_constants() {
    let quadratic = program::<crate::config::Challenge>();
    let cubic = program::<profile::Challenge>();
    assert_eq!(quadratic.extension, Extension::Quadratic);
    assert_eq!((quadratic.row_words, quadratic.parameter_words), (18, 8));
    assert_eq!((cubic.row_words, cubic.parameter_words), (22, 11));
    assert_eq!(quadratic.constraints, 7);
    assert_eq!(cubic.constraints, 7);
    assert!(quadratic
        .instructions
        .chunks_exact(5)
        .filter(|op| op[0] == 0)
        .all(|op| op[4] == 0));
    assert!(cubic
        .instructions
        .chunks_exact(5)
        .any(|op| op[0] == 0 && op[4] != 0));
    assert!(Program::input_shape_extension(quadratic.layout, Extension::Base).is_err());
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn quadratic_quotients_match_cpu_with_owned_partitioned_inputs_and_commitments() {
    conformance::<crate::config::Challenge>(false);
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn cubic_quotients_match_cpu_with_owned_partitioned_inputs_and_commitments() {
    conformance::<profile::Challenge>(false);
}

#[test]
#[ignore = "requires selected OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn quadratic_quotients_match_cpu_across_large_device_tiles() {
    conformance::<crate::config::Challenge>(true);
}

#[test]
#[ignore = "requires selected OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn cubic_quotients_match_cpu_across_large_device_tiles() {
    conformance::<profile::Challenge>(true);
}

fn conformance<F: FriExtension>(large_tiles: bool)
where
    SymbolicExpressionExt<Val, F>: Algebra<F>,
{
    let _shutdown = TestShutdownGuard;
    gpu_hash::initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: if large_tiles { 16 << 20 } else { 128 << 10 },
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let p = Arc::new(program::<F>());
    let init = DeviceSession::new().unwrap();
    let prepared = init.prepare_quotient(p.clone()).unwrap();
    drop(init);
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(permutation.clone());
    let compress = MyCompress::new(permutation);
    let mut cases = 0;
    let domains = if large_tiles {
        &[(10u32, 15u32, 7u64), (14, 16, 11)][..]
    } else {
        &[(0u32, 3u32, 7u64), (3, 6, 11), (5, 9, 7), (10, 13, 11)][..]
    };
    for &(log_trace, log_quotient, shift) in domains {
        let session = DeviceSession::new().unwrap();
        let height = 1usize << log_quotient;
        let matrix = |width, salt: u64| {
            RowMajorMatrix::new(
                (0..(1 << log_trace) * width)
                    .map(|i| {
                        Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xffff_ffff_0000_0000)
                                .wrapping_add(salt),
                        )
                    })
                    .collect(),
                width,
            )
        };
        let main = matrix(3, 17);
        let pre = matrix(2, 19);
        let perm = matrix(2 * F::DIMENSION, 23);
        let cpu_lde = |m| {
            Dft::default()
                .coset_lde_batch(m, (log_quotient - log_trace) as usize, Val::new(shift))
                .to_row_major_matrix()
        };
        let cpu_main = cpu_lde(main.clone());
        let cpu_pre = cpu_lde(pre.clone());
        let cpu_perm = cpu_lde(perm.clone());
        let upload = |m: &RowMajorMatrix<Val>, extension: Extension| {
            session
                .upload(
                    MatrixSpec::new(
                        log_trace,
                        m.width / extension.degree(),
                        extension,
                        RowOrder::Natural,
                        1,
                    )
                    .unwrap(),
                    &m.values
                        .iter()
                        .map(PrimeField64::as_canonical_u64)
                        .collect::<Vec<_>>(),
                )
                .unwrap()
        };
        let original_main = upload(&main, Extension::Base);
        let original_pre = upload(&pre, Extension::Base);
        let original_perm = upload(&perm, F::DEVICE_EXTENSION);
        let salts: Vec<_> = (0..height * 4).map(|i| (i * 39 + 17) as u64).collect();
        let device_salts = session
            .upload(
                MatrixSpec::new(log_quotient, 4, Extension::Base, RowOrder::Natural, shift)
                    .unwrap(),
                &salts,
            )
            .unwrap();
        for partitioned in [false, true] {
            let input_log = if partitioned { log_trace } else { log_quotient };
            let device_main = session
                .lde(&original_main, input_log, shift, RowOrder::BitReversed)
                .unwrap();
            let device_pre = session
                .lde(&original_pre, input_log, shift, RowOrder::Natural)
                .unwrap();
            let device_perm = session
                .lde(&original_perm, input_log, shift, RowOrder::BitReversed)
                .unwrap();
            let public = [Val::new(31), Val::new(0xffff_ffff_0000_0000)];
            let challenges = [
                constant::<F>(),
                F::from_basis_coefficients_fn(|i| Val::new(17 + i as u64)),
            ];
            let terminal = F::from_basis_coefficients_fn(|i| Val::new(29 + i as u64));
            let parameters: Vec<_> = public
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .chain(challenges.into_iter().chain([terminal]).flat_map(words))
                .collect();
            let evaluate = |alpha: &[u64], parameters: &[u64], pre| {
                if partitioned {
                    session.quotient_extension_partitioned(
                        &prepared,
                        log_trace,
                        log_quotient,
                        shift,
                        &device_main,
                        pre,
                        Some(&device_perm),
                        alpha,
                        parameters,
                    )
                } else {
                    session.quotient_extension(
                        &prepared,
                        log_trace,
                        &device_main,
                        pre,
                        Some(&device_perm),
                        alpha,
                        parameters,
                    )
                }
            };
            let before_invalid = session.stats();
            assert!(evaluate(&[0], &parameters, Some(&device_pre)).is_err());
            assert!(evaluate(&vec![0; F::DIMENSION + 1], &parameters, Some(&device_pre)).is_err());
            assert!(evaluate(
                &vec![u64::MAX; F::DIMENSION],
                &parameters,
                Some(&device_pre)
            )
            .is_err());
            assert!(evaluate(&vec![0; F::DIMENSION], &parameters[1..], Some(&device_pre)).is_err());
            assert!(evaluate(&vec![0; F::DIMENSION], &parameters, None).is_err());
            assert_eq!(
                session.stats().uploaded_bytes,
                before_invalid.uploaded_bytes
            );
            assert_eq!(
                session.stats().downloaded_bytes,
                before_invalid.downloaded_bytes
            );
            for alpha in [F::ZERO, constant::<F>()] {
                let before = session.stats();
                let quotient = evaluate(&words(alpha), &parameters, Some(&device_pre)).unwrap();
                let after = session.stats();
                let calls = if partitioned {
                    1u64 << (log_quotient - log_trace)
                } else {
                    1
                };
                let scalar_output = if partitioned { 8 * calls } else { 0 };
                assert_eq!(
                    after.downloaded_bytes - before.downloaded_bytes,
                    8 * calls + scalar_output
                );
                assert_eq!(
                    after.quotient_evaluations - before.quotient_evaluations,
                    calls
                );
                assert!(after.quotient_device_ns > before.quotient_device_ns);
                assert_eq!(quotient.spec().extension(), F::DEVICE_EXTENSION);
                assert_eq!(quotient.spec().bytes(), height * F::DIMENSION * 8);
                let root = Val::two_adic_generator(log_quotient as usize);
                let last = Val::two_adic_generator(log_trace as usize).inverse();
                let next_step = 1usize << (log_quotient - log_trace);
                let expected: Vec<F> = (0..height)
                    .map(|row| {
                        let next = (row + next_step) % height;
                        let m = &cpu_main.values[row * 3..row * 3 + 3];
                        let n = &cpu_main.values[next * 3..next * 3 + 3];
                        let pr = &cpu_pre.values[row * 2..row * 2 + 2];
                        let pn = &cpu_pre.values[next * 2..next * 2 + 2];
                        let q = |r, col| {
                            F::from_basis_coefficients_fn(|i| {
                                cpu_perm.values[(r * 2 + col) * F::DIMENSION + i]
                            })
                        };
                        let x = Val::new(shift) * root.exp_u64(row as u64);
                        let z = x.exp_power_of_2(log_trace as usize) - Val::ONE;
                        let first = z / (x - Val::ONE);
                        let last_selector = z / (x - last);
                        [
                            F::from(-(m[0] + public[0]) * (n[1] - pn[0])),
                            -(q(next, 0) + challenges[0])
                                * (q(row, 1) - terminal + constant::<F>()),
                            F::from(first * (pr[0] - m[2])),
                            (challenges[1] * q(row, 0) + constant::<F>()) * last_selector,
                            F::from((x - last) * (n[0] - m[1])),
                            (q(next, 1) + terminal) * (challenges[0] + F::from(m[0])),
                            F::from(public[1] - n[2]),
                        ]
                        .into_iter()
                        .fold(F::ZERO, |acc, constraint| acc * alpha + constraint)
                            / F::from(z)
                    })
                    .collect();
                // Consume the quotient in a GPU commitment before any value readback.
                let before_commit = session.stats();
                let committed = session.commit(&quotient, &device_salts, 2).unwrap();
                assert_eq!(session.stats().uploaded_bytes, before_commit.uploaded_bytes);
                assert_eq!(
                    session.stats().downloaded_bytes - before_commit.downloaded_bytes,
                    (committed.cap().len() * 32) as u64
                );
                let mut layers = vec![(0..height)
                    .map(|row| {
                        hash.hash_iter(
                            expected[row]
                                .as_basis_coefficients_slice()
                                .iter()
                                .copied()
                                .chain(salts[row * 4..row * 4 + 4].iter().map(|v| Val::new(*v))),
                        )
                    })
                    .collect::<Vec<_>>()];
                while layers.last().unwrap().len() > 4 {
                    layers.push(
                        layers
                            .last()
                            .unwrap()
                            .chunks_exact(2)
                            .map(|v| compress.compress([v[0], v[1]]))
                            .collect(),
                    );
                }
                assert_eq!(committed.cap(), layers.last().unwrap());
                for row in [0, 1, height / 2, height - 1] {
                    let expected_path: Vec<_> = layers[..layers.len() - 1]
                        .iter()
                        .enumerate()
                        .map(|(level, layer)| layer[(row >> level) ^ 1])
                        .collect();
                    assert_eq!(committed.open(row).unwrap(), expected_path);
                }
                let expected_words = expected.into_iter().flat_map(words).collect::<Vec<_>>();
                assert_eq!(
                    session.read(&quotient, quotient.spec().bytes()).unwrap(),
                    expected_words
                );
                if partitioned && log_trace == 3 {
                    use crate::block_v2::gpu_hash::device::DomainSpec;
                    let before = session.stats();
                    let owned = evaluate::owned_quotient(
                        &session,
                        &p,
                        &public,
                        DomainSpec::new(1, log_trace as usize).unwrap(),
                        DomainSpec::new(shift, log_quotient as usize).unwrap(),
                        &device_main,
                        Some(&device_perm),
                        &[terminal],
                        &challenges,
                        Some(&device_pre),
                        alpha,
                    )
                    .unwrap();
                    assert_eq!(
                        session.stats().downloaded_bytes - before.downloaded_bytes,
                        16 * calls
                    );
                    assert_eq!(
                        session.read(&owned, owned.spec().bytes()).unwrap(),
                        expected_words
                    );
                }
                cases += 1;
            }
        }
    }
    drop(prepared);
    gpu_hash::shutdown().unwrap();
    assert_eq!(cases, 4 * domains.len());
    println!(
        "device_quotient_tile_conformance extension={} large_tiles={large_tiles} cases={cases}",
        F::DIMENSION
    );
    eprintln!("extension_quotient_cpu_matched degree={} cases={cases} quotient_readback_before_commit_bytes=0", F::DIMENSION);
}
