//! Raw witness-arithmetic oracles; no dense trace or proof is constructed.
use super::{Payload, Policy as CryptoPolicy, Request as CryptoRequest, RequestDescriptor, Val};
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};
use lattica_prover_p3::{
    block_v2::native_gpu::{with_operations, SparseProfile, UniformProfile},
    proving::{Backend, Policy, Request, Stage},
};
use p3_field::PrimeCharacteristicRing;

fn aes_bytes(key: &[u8; 32], domain: u64, counter: u32, count: usize) -> Vec<u8> {
    let cipher = Aes256::new(key.into());
    let mut out = Vec::with_capacity(count);
    for block in 0..count.div_ceil(16) {
        let mut input = [0u8; 16];
        input[..4].copy_from_slice(&counter.wrapping_add(block as u32).to_le_bytes());
        input[8..].copy_from_slice(&domain.to_le_bytes());
        let mut encrypted = input.into();
        cipher.encrypt_block(&mut encrypted);
        out.extend_from_slice(&encrypted[..(count - out.len()).min(16)]);
    }
    out
}

#[test]
#[ignore = "requires exclusive bounded OpenCL; raw witness outputs only"]
fn raw_gpu_crypto_outputs_match_rustcrypto_and_exact_sampler_profiles() {
    let session = crate::opencl::Session::start(crate::opencl::Limits {
        host_bytes: 32 << 30,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    })
    .unwrap();
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    };
    let key = core::array::from_fn(|i| (13 * i + 7) as u8);
    let (_, report) = with_operations(8 << 20, request, |ctx| {
        let graph_context = crate::graph_tree::GraphContext {
            context: [17; 32],
            statement: [Val::ONE; 4],
            node_manifest: [Val::ZERO; 4],
        };
        for count in [1, 17, 33] {
            let item = CryptoRequest::new(
                [19; 32],
                0,
                0,
                RequestDescriptor::Aes(crate::aes_air::Descriptor {
                    domain: 0x4368,
                    start_counter: u32::MAX,
                    output_len: count,
                }),
                Payload::Aes(key),
                CryptoPolicy::default(),
            )
            .unwrap();
            let expected = item.endpoint_context_hint(&graph_context);
            let actual = item
                .endpoint_context_hint_on_gpu(&graph_context, ctx)
                .map_err(|e| e.to_string())?;
            assert_eq!(actual.input, expected.input);
            assert_eq!(actual.output, expected.output);
            assert_eq!(actual.context, expected.context);
            assert_eq!(actual.statement, expected.statement);
        }
        for length in [0, 1, 7, 8, 9, 135, 136, 137] {
            let input = (0..length).map(|i| (i * 29 + 3) as u8).collect::<Vec<_>>();
            let item = CryptoRequest::new(
                [19; 32],
                0,
                0,
                RequestDescriptor::Shake(crate::shake_air::Descriptor {
                    input_len: length,
                    output_len: 137,
                }),
                Payload::Shake(input),
                CryptoPolicy::default(),
            )
            .unwrap();
            let expected = item.endpoint_context_hint(&graph_context);
            let actual = item
                .endpoint_context_hint_on_gpu(&graph_context, ctx)
                .map_err(|e| e.to_string())?;
            assert_eq!(actual.input, expected.input);
            assert_eq!(actual.output, expected.output);
        }
        for domain in [0, 0x4368, 0x1020304050607080] {
            for count in [0, 1, 15, 16, 17, 127, 137] {
                assert_eq!(
                    ctx.aes256_ctr(&key, domain, u32::MAX, count)?,
                    aes_bytes(&key, domain, u32::MAX, count)
                );
            }
        }
        for length in [0, 1, 135, 136, 137, 273] {
            let input = (0..length).map(|i| (i * 17 + 23) as u8).collect::<Vec<_>>();
            for count in [0, 1, 135, 136, 137, 273] {
                assert_eq!(
                    ctx.shake256(&input, count)?,
                    crate::rust_verify::primitives::shake(&input, count)
                );
            }
        }
        // Inject values immediately below/at/above each rejection threshold.
        for (profile, width, modulus, bound) in [
            (
                UniformProfile::Q32,
                4,
                crate::rust_verify::Q,
                4_194_256_025u64,
            ),
            (
                UniformProfile::Qhat40,
                5,
                crate::rust_verify::QHAT,
                1_099_243_232_955u64,
            ),
        ] {
            let input = [bound, bound + 1, 0, bound - 1, modulus - 1, modulus, 7]
                .iter()
                .flat_map(|value| value.to_le_bytes()[..width].to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                ctx.uniform_coefficients(&input, profile, 5)?,
                vec![0, (bound - 1) % modulus, modulus - 1, 0, 7]
            );
        }
        // Independent relation primitives establish the two exact sparse schedules.
        for seed in [[0u8; 32], key, [255u8; 32]] {
            let gbytes = ctx.aes256_ctr(&seed, 0, 0, 1197 * 4)?;
            let expected = crate::rust_verify::primitives::sample_g(&seed).unwrap();
            assert_eq!(
                ctx.uniform_coefficients(&gbytes, UniformProfile::Q32, 4 * 256)?,
                expected.concat()
            );
            let (expected_uniform, expected_sparse) =
                crate::rust_verify::primitives::expand_alpha(&seed).unwrap();
            let uniform = ctx.aes256_ctr(&seed, 0x4368, 0, 643 * 4)?;
            assert_eq!(
                ctx.uniform_coefficients(&uniform, UniformProfile::Q32, 2 * 256)?,
                expected_uniform.concat()
            );
            let sparse = ctx.aes256_ctr(&seed, 0x4368, 161, 127)?;
            assert_eq!(
                ctx.sparse_polynomial(&sparse, SparseProfile::AlphaPrime39)?,
                expected_sparse
            );
            let zero = [0u64; 256];
            let expected =
                crate::rust_verify::primitives::hash_x(&seed, &zero, &zero, &[], &[], &[]).unwrap();
            let mut input = seed.to_vec();
            input.resize(32 + 2 * 256 * 4, 0);
            // Transcript serialization uses four bytes per coefficient.
            let sparse = ctx.shake256(&input, 137)?;
            assert_eq!(
                ctx.sparse_polynomial(&sparse, SparseProfile::ChallengeX44)?,
                expected
            );
        }
        let parameters = crate::rust_verify::primitives::parameters(&key, &[9; 32]).unwrap();
        for (domain, draws, width, profile, expected) in [
            (
                0x4d617431,
                7648,
                4,
                UniformProfile::Q32,
                parameters.mat1.concat().concat(),
            ),
            (
                0x4d617433,
                37232,
                5,
                UniformProfile::Qhat40,
                parameters.mat3.concat().concat(),
            ),
        ] {
            let stream = ctx.aes256_ctr(&key, domain, 0, draws * width)?;
            assert_eq!(
                ctx.uniform_coefficients(&stream, profile, expected.len())?,
                expected
            );
        }
        let mut expected = Vec::new();
        for row in &parameters.mat2 {
            for poly in &row[..2] {
                expected.extend_from_slice(poly);
            }
        }
        for row in &parameters.mat2 {
            for k in 4..128 {
                expected.extend_from_slice(&[row[2][k], row[2][128 + k]]);
            }
        }
        let stream = ctx.aes256_ctr(&key, 0x4d617432, 0, 3366 * 4)?;
        assert_eq!(
            ctx.uniform_coefficients(&stream, UniformProfile::Q32, expected.len())?,
            expected
        );
        Ok(())
    })
    .unwrap();
    assert!(report.succeeded && report.stage_coverage_complete);
    assert!(report
        .observations
        .iter()
        .any(|o| o.stage == Stage::WitnessTrace
            && o.backend == Backend::OpenCl
            && o.device_calls > 0
            && o.calls == o.completed_calls));
    assert!(!report
        .observations
        .iter()
        .any(|o| o.backend == Backend::Cpu && o.stage == Stage::WitnessTrace));
    // A caught raw-operation error must still poison the whole operation scope.
    for kind in 0..3 {
        let result = with_operations(8 << 20, request, |ctx| {
            let failed = match kind {
                0 => ctx
                    .uniform_coefficients(&[255; 40], UniformProfile::Q32, 1)
                    .map(|_| ()),
                1 => ctx
                    .sparse_polynomial(&[0; 127], SparseProfile::AlphaPrime39)
                    .map(|_| ()),
                _ => ctx
                    .sparse_polynomial(&[0; 137], SparseProfile::ChallengeX44)
                    .map(|_| ()),
            };
            assert!(failed.is_err());
            assert!(ctx.shake256(&[], 1).is_err());
            Ok(())
        });
        assert!(result.is_err());
    }
    drop(session);
}
