use super::*;
use crate::{
    config::Val,
    cuda_compute::{Limits, Transcript, Transcripts},
    gpu_matrix::GOLDILOCKS_MODULUS as P,
};
use p3_commit::PolynomialSpace;
use p3_field::{
    coset::TwoAdicMultiplicativeCoset, BasedVectorSpace, ExtensionField, Field,
    PrimeCharacteristicRing, PrimeField64, TwoAdicField,
};

fn runtime(managed: usize, allocation: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: allocation,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn read(buffer: &Buffer) -> Vec<u64> {
    let mut output = vec![0; buffer.len()];
    buffer.read(0, &mut output).unwrap();
    output
}
fn coefficients<F: ExtensionField<Val>>(value: F) -> Vec<u64> {
    value
        .as_basis_coefficients_slice()
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}

#[test]
fn scalar_and_domain_bounds_are_checked_without_device_work() {
    for extension in [Extension::Base, Extension::Quadratic, Extension::Cubic] {
        assert_eq!(
            words(limits::SCALAR_OUTPUTS, extension).unwrap(),
            4096 * extension.degree()
        );
        for count in [0, 4097, usize::MAX] {
            assert!(words(count, extension).is_err());
        }
    }
    assert_eq!(lookup_width(u32::MAX as usize).unwrap(), u32::MAX);
    assert!(lookup_width(0).is_err());
    assert!(lookup_width(usize::MAX).is_err());
    for (shift, log) in [(0, 0), (P, 0), (1, 33), (1, usize::MAX)] {
        assert!(DomainSpec::new(shift, log).is_err());
    }
}

fn conformance<F: ExtensionField<Val>>(extension: Extension) {
    let runtime = runtime(4 << 20, 2 << 20);
    let engine = Scalars::new(&runtime).unwrap();
    let degree = extension.degree();
    for data in [
        [0, 0, 0, 0, 0, 0],
        [P, P + 1, u64::MAX, P - 1, 1, 0],
        [17, 29, 37, 11, 19, 31],
    ] {
        let mut guarded = vec![0xdead_beef];
        guarded.extend_from_slice(&data[..2 * degree]);
        guarded.push(0xdead_beef);
        let input = runtime.allocate(guarded.len()).unwrap();
        input.write(0, &guarded).unwrap();
        let span = FieldSpan {
            buffer: &input,
            first: 1,
        };
        let alpha = F::from_basis_coefficients_fn(|i| Val::from_u64(data[i]));
        let beta = F::from_basis_coefficients_fn(|i| Val::from_u64(data[degree + i]));
        for (first, count) in [(0, 4096), (19, 129), (u64::MAX, 1)] {
            let before = runtime.snapshot();
            let actual = engine.powers(span, extension, first, count).unwrap();
            let after = runtime.snapshot();
            assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
            assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
            let expected: Vec<_> = (0..count)
                .flat_map(|i| coefficients(alpha.exp_u64(first + i as u64)))
                .collect();
            assert_eq!(read(&actual), expected);
        }
        for width in [1, 7, 33, u32::MAX as usize] {
            let count = if width == 33 { 4096 } else { 17 };
            let before = runtime.snapshot();
            let actual = engine
                .lookup_prefixes(span, extension, width, count)
                .unwrap();
            assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
            assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
            let gamma = beta.exp_u64(width as u64);
            let expected: Vec<_> = (0..count)
                .flat_map(|i| coefficients(alpha + gamma * Val::from_usize(i + 1)))
                .collect();
            assert_eq!(read(&actual), expected);
        }
        let logs: Vec<_> = (0..4096).map(|i| i % 33).collect();
        let before = runtime.snapshot();
        let actual = engine.next_points(span, extension, &logs).unwrap();
        assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
        assert_eq!(
            runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
            4096 * 8
        );
        let expected: Vec<_> = logs
            .iter()
            .flat_map(|&log| coefficients(alpha * Val::two_adic_generator(log as usize)))
            .collect();
        assert_eq!(read(&actual), expected);
        drop(actual);
        let sampled = runtime.allocate(2 * degree).unwrap();
        sampled.copy_from(0, &input, 1, 2 * degree).unwrap();
        let ids = [4, 0, 4, 2, 0, 4095];
        let prepared = engine.prepare_lookup(extension, 7, &ids).unwrap();
        let before = runtime.snapshot();
        let actual = prepared.finish(&sampled).unwrap();
        assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
        let gamma = beta.exp_u64(7);
        let expected: Vec<_> = ids
            .into_iter()
            .flat_map(|i| [alpha + gamma * Val::from_usize(i + 1), beta])
            .flat_map(coefficients)
            .collect();
        assert_eq!(read(&actual), expected);
        assert_eq!(
            read(&input),
            guarded,
            "scalar input and guards remain immutable"
        );
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_scalar_arithmetic_matches_base_quadratic_and_cubic_cpu_oracles() {
    conformance::<Val>(Extension::Base);
    conformance::<crate::config::Challenge>(Extension::Quadratic);
    conformance::<p3_field::extension::CubicTrinomialExtensionField<Val>>(Extension::Cubic);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_scalar_domains_match_upstream_without_readback() {
    let runtime = runtime(2 << 20, 1 << 20);
    let engine = Scalars::new(&runtime).unwrap();
    for shift in [1, 7, 11, P - 1] {
        for log in [0, 1, 5, 13, 25, 32] {
            let domain = DomainSpec::new(shift, log).unwrap();
            let reference = TwoAdicMultiplicativeCoset::new(Val::new(shift), log).unwrap();
            for parts in [0, 1, 4, 8].into_iter().filter(|&n| n <= log) {
                let before = runtime.snapshot();
                let actual = engine.split_domains(domain, 1 << parts).unwrap();
                let after = runtime.snapshot();
                assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
                let expected = reference.split_domains(1 << parts);
                assert_eq!(actual.log_size, log - parts);
                assert_eq!(
                    read(&actual.shifts),
                    expected
                        .into_iter()
                        .map(|d| d.shift().as_canonical_u64())
                        .collect::<Vec<_>>()
                );
            }
            for size in [log, 32] {
                let actual = engine.disjoint_domain(domain, size).unwrap();
                let expected = reference.create_disjoint_domain(1usize << size);
                assert_eq!(actual.log_size, expected.log_size());
                assert_eq!(
                    read(&actual.shifts),
                    vec![expected.shift().as_canonical_u64()]
                );
            }
        }
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_scalars_reject_shapes_and_exhausted_storage_before_commands() {
    let runtime = runtime(64 << 10, 32 << 10);
    let engine = Scalars::new(&runtime).unwrap();
    let input = runtime.allocate(8).unwrap();
    let span = FieldSpan {
        buffer: &input,
        first: 0,
    };
    let before = runtime.snapshot();
    for count in [0, 4097, usize::MAX] {
        assert!(engine.powers(span, Extension::Cubic, 0, count).is_err());
    }
    assert!(engine.powers(span, Extension::Cubic, u64::MAX, 2).is_err());
    assert!(engine
        .powers(
            FieldSpan {
                buffer: &input,
                first: usize::MAX
            },
            Extension::Cubic,
            0,
            1
        )
        .is_err());
    assert!(engine
        .lookup_prefixes(span, Extension::Cubic, 0, 1)
        .is_err());
    assert!(engine.prepare_lookup(Extension::Cubic, 1, &[4096]).is_err());
    assert!(engine.prepare_lookup(Extension::Cubic, 1, &[]).is_err());
    assert!(engine
        .prepare_lookup(Extension::Cubic, 1, &vec![0; 4096])
        .is_err());
    assert!(engine.next_points(span, Extension::Cubic, &[33]).is_err());
    assert!(engine.next_points(span, Extension::Cubic, &[]).is_err());
    assert!(engine
        .next_points(span, Extension::Cubic, &vec![0; 4096])
        .is_err());
    for chunks in [0, 3, 512, usize::MAX] {
        assert!(engine
            .split_domains(DomainSpec::new(7, 8).unwrap(), chunks)
            .is_err());
    }
    assert!(engine
        .disjoint_domain(DomainSpec::new(7, 8).unwrap(), 33)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let mut filler = Vec::new();
    while runtime.snapshot().live_bytes < 64 << 10 {
        let remaining = (64 * 1024 - runtime.snapshot().live_bytes) / 8;
        filler.push(runtime.allocate(remaining.min(4096)).unwrap());
    }
    let before = runtime.snapshot();
    assert!(engine.powers(span, Extension::Cubic, 0, 1).is_err());
    assert!(engine.prepare_lookup(Extension::Cubic, 1, &[0]).is_err());
    assert!(engine.next_points(span, Extension::Cubic, &[8]).is_err());
    assert!(engine
        .split_domains(DomainSpec::new(7, 8).unwrap(), 1)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(filler);
    runtime.state.fail();
    assert!(engine.powers(span, Extension::Base, 0, 1).is_err());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_scalar_failures_and_unwind_retire_the_transcript_family() {
    let runtime = runtime(2 << 20, 1 << 20);
    let scalars = Scalars::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    for unwind in [false, true] {
        let mut state = transcripts.start().unwrap();
        let fork = state.snapshot().unwrap();
        let sampled = state.sample_resident(3).unwrap();
        let before = runtime.snapshot();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.derive_scalars(&scalars, || {
                let _ = scalars.powers(
                    FieldSpan {
                        buffer: &sampled,
                        first: 0,
                    },
                    Extension::Cubic,
                    0,
                    17,
                )?;
                if unwind {
                    panic!("injected failure after scalar kernel completion");
                }
                Err::<(), String>("injected scalar failure".into())
            })
        }));
        assert!(failed.is_err() || failed.unwrap().is_err());
        assert!(runtime.snapshot().completed_commands > before.completed_commands);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert!(fork.check_live().is_err());
        assert!(state.check_live().is_err());
    }
    let fresh: Transcript = transcripts.start().unwrap();
    assert!(fresh.check_live().is_ok());
}

#[test]
#[ignore = "requires pinned NVRTC but no GPU context"]
fn cuda_scalar_kernels_compile_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
