//! Qualification only: compares the disconnected launcher with the unchanged
//! operation path. No caller or routing hook outside this test is introduced.
use super::super::super::{env_bytes, DRIVER_RESERVE_BYTES};
use super::*;
use crate::block_v2::{
    gpu_hash::{
        self,
        device::{DeviceSession, Extension, MatrixSpec, RowOrder},
    },
    native_gpu::{self, OperationContext, SparseProfile, UniformProfile},
};
use crate::proving::{Backend, Policy, Request, Stage};

fn record(context: &OperationContext<'_>, completion: Completion) -> Result<(), String> {
    for timing in completion.kernels.into_iter().flatten() {
        context
            .run
            .observe_device(
                Stage::WitnessTrace,
                Backend::OpenCl,
                1,
                u128::from(timing.nanoseconds),
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn plan(engine: &Engine, words: &[usize]) -> Result<(), String> {
    // Test-only callers use the existing complete simultaneous MemoryPlan
    // before making any SecretAllocation. No launch-helper numeric quota exists.
    let mut specs = [MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1)?; 4];
    if words.is_empty() || words.len() > specs.len() {
        return Err("candidate test allocation plan shape".into());
    }
    for (slot, &words) in specs.iter_mut().zip(words) {
        *slot = MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1)?;
    }
    DeviceSession::plan(engine, &specs[..words.len()])?;
    Ok(())
}
fn read(buffer: &SecretAllocation) -> Result<Vec<u64>, String> {
    let mut words = vec![0u64; buffer.buffer().len()];
    // The existing readback wrapper is deliberately outside the candidate's
    // allocation claim. It is used only after the candidate drained both queues.
    buffer
        .buffer()
        .read(&mut words)
        .enq()
        .map_err(|e| e.to_string())?;
    Ok(words)
}

fn candidate_arithmetic(
    context: &OperationContext<'_>,
    spec: &ArithmeticOperationSpec,
    input: &[u64],
) -> Result<(Vec<u64>, Vec<u64>), String> {
    context.execute(|| {
        context.admit_host_bytes(spec.staging_bytes()?)?;
        let shape = ArithmeticShape::check(spec).map_err(|e| e.to_string())?;
        let (value, completion) = context.session.with_engine(|engine| {
            let before = engine.snapshot().managed_live_bytes;
            plan(engine, &shape.words)?;
            let result = {
                let input_buffer = SecretAllocation::new(engine, shape.words[0])?;
                let metadata = SecretAllocation::new(engine, shape.words[1])?;
                let output = SecretAllocation::new(engine, shape.words[2])?;
                let status = SecretAllocation::new(engine, shape.words[3])?;
                let complete = arithmetic(
                    engine,
                    spec,
                    input,
                    ArithmeticBuffers {
                        input: &input_buffer,
                        metadata: &metadata,
                        output: &output,
                        status: &status,
                    },
                )
                .map_err(|e| e.to_string())?;
                ((read(&output)?, read(&status)?), complete)
            };
            assert_eq!(engine.snapshot().managed_live_bytes, before);
            Ok(result)
        })?;
        record(context, completion)?;
        Ok(value)
    })
}

fn candidate_crypto(
    context: &OperationContext<'_>,
    kind: CryptoKind,
    input: &[u8],
    output_count: usize,
) -> Result<Vec<u64>, String> {
    context.execute(|| {
        let shape = CryptoShape::new(kind, input.len(), output_count).map_err(|e| e.to_string())?;
        // Conservative test-only admission includes the input, all word shapes
        // and the launcher's fixed stack staging before readback is allocated.
        let host_bytes = shape
            .words
            .iter()
            .try_fold(input.len() + 16_384, |bytes, words| {
                words
                    .checked_mul(8)
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or("candidate test crypto host bound overflow")?;
        context.admit_host_bytes(host_bytes)?;
        let (mut words, complete) = context.session.with_engine(|engine| {
            let before = engine.snapshot().managed_live_bytes;
            plan(engine, &shape.words)?;
            let result = {
                let input_buffer = SecretAllocation::new(engine, shape.words[0])?;
                let geometry = SecretAllocation::new(engine, shape.words[1])?;
                let scratch = SecretAllocation::new(engine, shape.words[2])?;
                let output = SecretAllocation::new(engine, shape.words[3])?;
                let complete = crypto(
                    engine,
                    kind,
                    input,
                    output_count,
                    CryptoBuffers {
                        input: &input_buffer,
                        geometry: &geometry,
                        scratch: &scratch,
                        output: &output,
                    },
                )
                .map_err(|e| e.to_string())?;
                (read(&output)?, complete)
            };
            assert_eq!(engine.snapshot().managed_live_bytes, before);
            Ok(result)
        })?;
        record(context, complete)?;
        if words.pop() != Some(0) {
            return Err("candidate crypto status rejection".into());
        }
        Ok(words)
    })
}

fn candidate_node(
    context: &OperationContext<'_>,
    kind: NodeKind,
    input: &[u64],
) -> Result<[u64; 5], String> {
    context.execute(|| {
        context.admit_host_bytes((input.len() + 5) * 8)?;
        let (words, complete) = context.session.with_engine(|engine| {
            let before = engine.snapshot().managed_live_bytes;
            plan(engine, &[input.len(), 5])?;
            let result = {
                let input_buffer = SecretAllocation::new(engine, input.len())?;
                let output = SecretAllocation::new(engine, 5)?;
                let complete = node(
                    engine,
                    kind,
                    input,
                    NodeBuffers {
                        input: &input_buffer,
                        output: &output,
                    },
                )
                .map_err(|e| e.to_string())?;
                (read(&output)?, complete)
            };
            assert_eq!(engine.snapshot().managed_live_bytes, before);
            Ok(result)
        })?;
        record(context, complete)?;
        words.try_into().map_err(|_| "candidate node shape".into())
    })
}

#[test]
#[ignore = "exclusive RTX5080 qualification; use existing 8GiB managed/4GiB context, 47GiB/zero-swap guard"]
fn gpu_all_seven_kernels_match_existing_operations_and_release_allocations() {
    use crate::block_v2::native_gpu::operations_arithmetic::{CanonicalOperation, SignedOperation};
    let _shutdown = gpu_hash::TestShutdownGuard;
    assert_eq!(
        env_bytes("LATTICA_V2_GPU_CONTEXT_BYTES", DRIVER_RESERVE_BYTES).unwrap(),
        4 << 30
    );
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    session
        .with_engine(|engine| {
            assert_eq!(engine.limits.managed_bytes, 8 << 30);
            Ok(())
        })
        .unwrap();
    drop(session);
    let (_, report) = native_gpu::with_operations(
        64 << 20,
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        |context| {
            let input: Vec<u64> = (0..512).map(|i| (i * 7 + 3) as u64).collect();
            for operation in [
                CanonicalOperation::Add,
                CanonicalOperation::Subtract,
                CanonicalOperation::Montgomery,
            ] {
                for q in [167770241, 3489661057] {
                    let spec = ArithmeticOperationSpec::canonical(operation, 256, q)?;
                    let expected = context.arithmetic_output(&spec, &input)?;
                    let (actual, status) = candidate_arithmetic(context, &spec, &input)?;
                    assert_eq!(expected, actual);
                    assert!(status.iter().all(|&v| v == 0));
                }
            }
            let signed: Vec<_> = (0..512).map(|i| (i as i64 - 256) as u64).collect();
            for operation in [SignedOperation::Negate, SignedOperation::Subtract] {
                let spec = ArithmeticOperationSpec::signed(operation, 256)?;
                let values = &signed[..spec.input_words];
                let expected = context.arithmetic_output(&spec, values)?;
                let (actual, status) = candidate_arithmetic(context, &spec, values)?;
                assert_eq!(actual, expected);
                assert!(status.iter().all(|&v| v == 0));
            }
            // Exercise every arithmetic opcode, including both signed reduction
            // endpoints and public schedule uploads. These valid synthetic schedules
            // test launch parity, not the semantic validity of a MatRiCT NTT table.
            let endpoints = [i64::MIN as u64, i64::MAX as u64, (-1i64) as u64, 0];
            for q in [167770241, 3489661057] {
                let spec = ArithmeticOperationSpec::signed_to_canonical(endpoints.len(), q)?;
                let expected = context.arithmetic_output(&spec, &endpoints)?;
                let (actual, status) = candidate_arithmetic(context, &spec, &endpoints)?;
                assert_eq!(actual, expected);
                assert!(status.iter().all(|&v| v == 0));
                let steps = core::array::from_fn::<_, 768, _>(|i| {
                    [(i % 128) as u64, (i % 128 + 128) as u64, 1, 3]
                });
                let permutation = core::array::from_fn::<_, 64, _>(|i| (63 - i) as u64);
                let spec = ArithmeticOperationSpec::ntt(q, 2, &steps, &permutation)?;
                let expected = context.arithmetic_output(&spec, &signed)?;
                let (actual, status) = candidate_arithmetic(context, &spec, &signed)?;
                assert_eq!(actual, expected);
                assert!(status.iter().all(|&v| v == 0));
                let terms =
                    core::array::from_fn::<_, 1024, _>(|i| [(i % 7) as u64, (i % 2) as u64]);
                let spec = ArithmeticOperationSpec::mul(q, 1, &terms)?;
                let expected = context.arithmetic_output(&spec, &input)?;
                let (actual, status) = candidate_arithmetic(context, &spec, &input)?;
                assert_eq!(actual, expected);
                assert!(status.iter().all(|&v| v == 0));
            }
            let sources = core::array::from_fn::<_, 256, _>(|i| (255 - i) as u64);
            let factors = core::array::from_fn::<_, 256, _>(|i| (i % 7) as u64);
            let spec = ArithmeticOperationSpec::automorphism(&sources, &factors)?;
            let expected = context.arithmetic_output(&spec, &input[..256])?;
            let (actual, status) = candidate_arithmetic(context, &spec, &input[..256])?;
            assert_eq!(actual, expected);
            assert!(status.iter().all(|&v| v == 0));
            let negative = core::array::from_fn::<_, 256, _>(|i| i % 2 != 0);
            let spec = ArithmeticOperationSpec::inverse_challenge(&sources, &negative)?;
            let expected = context.arithmetic_output(&spec, &signed[..256])?;
            let (actual, status) = candidate_arithmetic(context, &spec, &signed[..256])?;
            assert_eq!(actual, expected);
            assert!(status.iter().all(|&v| v == 0));
            let key = [7u8; 32];
            let expected = context.aes256_ctr(&key, 9, 3, 186160)?;
            let actual = candidate_crypto(
                context,
                CryptoKind::Aes {
                    domain: 9,
                    counter: 3,
                },
                &key,
                186160,
            )?;
            assert!(actual
                .iter()
                .copied()
                .eq(expected.into_iter().map(u64::from)));
            for length in [0, 1, 135, 136, 137, 271, 272] {
                let input = vec![19; length];
                for count in [0, 32, 136, 137, 272] {
                    let expected = context.shake256(&input, count)?;
                    let actual = candidate_crypto(context, CryptoKind::Shake, &input, count)?;
                    assert!(actual
                        .iter()
                        .copied()
                        .eq(expected.into_iter().map(u64::from)));
                }
            }
            for (profile, kind) in [
                (UniformProfile::Q32, CryptoKind::UniformQ),
                (UniformProfile::Qhat40, CryptoKind::UniformQhat),
            ] {
                let input = [0; 5 * 256];
                let expected = context.uniform_coefficients(&input, profile, 256)?;
                assert_eq!(candidate_crypto(context, kind, &input, 256)?, expected);
            }
            for (profile, kind, length) in [
                (SparseProfile::AlphaPrime39, CryptoKind::SparseAlpha, 127),
                (SparseProfile::ChallengeX44, CryptoKind::SparseX, 137),
            ] {
                let mut input = vec![0; length];
                if length == 127 {
                    for (index, byte) in input[5..44].iter_mut().enumerate() {
                        *byte = index as u8;
                    }
                } else {
                    for group in 0..4 {
                        for item in 1..11 {
                            input[10 + group * 10 + item - 1] = item as u8;
                        }
                    }
                }
                let expected = context.sparse_polynomial(&input, profile)?;
                let actual = candidate_crypto(context, kind, &input, 256)?;
                let decoded: Vec<_> = actual
                    .into_iter()
                    .map(|v| match v {
                        0 => 0,
                        1 => 1,
                        2 => -1,
                        _ => panic!("sparse encoding"),
                    })
                    .collect();
                assert_eq!(decoded.as_slice(), expected.as_slice());
            }
            let canonical = core::array::from_fn::<_, 256, _>(|i| i as u64);
            for (q, kind) in [
                (167770241, NodeKind::CanonicalQ),
                (3489661057, NodeKind::CanonicalQhat),
            ] {
                let expected = context.commit_canonical_node(&canonical, q)?;
                let actual = candidate_node(context, kind, &canonical)?;
                assert_eq!(actual[..4], expected);
                assert_eq!(actual[4], 0);
            }
            let signed = core::array::from_fn::<_, 256, _>(|i| i as i64 - 128);
            let expected = context.commit_signed_node(&signed)?;
            let actual = candidate_node(context, NodeKind::Signed, &signed.map(|v| v as u64))?;
            assert_eq!(actual[..4], expected);
            assert_eq!(actual[4], 0);
            let bytes = core::array::from_fn::<_, 32, _>(|i| i as u8);
            let expected = context.commit_bytes32_node(&bytes)?;
            let actual = candidate_node(context, NodeKind::Bytes32, &bytes.map(u64::from))?;
            assert_eq!(actual[..4], expected);
            assert_eq!(actual[4], 0);

            // Noncanonical witness data must still produce the kernel's rejection
            // status; a completed kernel alone is never accepted as a valid result.
            let spec = ArithmeticOperationSpec::canonical(CanonicalOperation::Add, 1, 167770241)?;
            let (_, status) = candidate_arithmetic(context, &spec, &[167770241, 0])?;
            assert!(status.iter().any(|&v| v != 0));
            let spec = ArithmeticOperationSpec::signed(SignedOperation::Negate, 1)?;
            let (_, status) = candidate_arithmetic(context, &spec, &[i64::MIN as u64])?;
            assert!(status.iter().any(|&v| v != 0));
            let mut bad = canonical;
            bad[0] = 167770241;
            assert_ne!(candidate_node(context, NodeKind::CanonicalQ, &bad)?[4], 0);
            Ok(())
        },
    )
    .unwrap();
    assert!(report.succeeded);
    assert!(report.stage_coverage_complete);
    assert!(!report.completion_rejected);
    assert_eq!(report.observation_errors, 0);
    gpu_hash::shutdown().unwrap();
    eprintln!("native_launcher_equivalence kernels=7 status_mutations=true terminal_cleanup=true workflow_authority=false");
}
