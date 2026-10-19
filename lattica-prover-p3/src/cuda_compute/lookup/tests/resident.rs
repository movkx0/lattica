use super::*;
use crate::cuda_compute::{Scalars, Transcripts};
use p3_challenger::{CanObserve, CanSample};

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_lookup_challenges_and_terminal_round_trip_through_resident_transcript() {
    type F = crate::block_v2::profile::Challenge;
    let runtime = runtime(limits());
    let engine = Lookups::new(&runtime).unwrap();
    let (layout, lookups) = lookup_fixture();
    let prepared = engine.prepare(layout, &lookups, 256 << 20).unwrap();
    let scalars = Scalars::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    let mut transcript = transcripts.start().unwrap();
    let mut reference =
        crate::config::Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8());
    transcript.observe(&[7, 19, 23]).unwrap();
    for v in [7, 19, 23] {
        reference.observe(Val::from_u64(v));
    }
    let alpha = F::from_basis_coefficients_fn(|_| <_ as CanSample<Val>>::sample(&mut reference));
    let beta = F::from_basis_coefficients_fn(|_| <_ as CanSample<Val>>::sample(&mut reference));
    let ids = [0, 1, 2];
    let challenges: Vec<_> = ids
        .into_iter()
        .flat_map(|i| [alpha + beta.exp_u64(3) * Val::from_usize(i + 1), beta])
        .collect();
    let mapping = scalars.prepare_lookup(Extension::Cubic, 3, &ids).unwrap();
    let main = RowMajorMatrix::new(
        (0..256 * layout.main_width)
            .map(|i| Val::from_usize(i + 9))
            .collect(),
        layout.main_width,
    );
    let pre = Some(RowMajorMatrix::new(
        (0..256 * layout.preprocessed_width)
            .map(|i| Val::from_usize(i + 13))
            .collect(),
        layout.preprocessed_width,
    ));
    let public = [Val::NEG_ONE, Val::from_u64(79)];
    let (expected, terminal) = LogUpGadget::new()
        .generate_permutation::<crate::block_v2::profile::Config>(
            &main,
            &pre,
            &public,
            &lookups,
            &challenges,
        );
    let terminal_coefficients: &[Val] = terminal.as_ref().unwrap().0.as_basis_coefficients_slice();
    for &v in terminal_coefficients {
        reference.observe(v);
    }
    let expected_next =
        F::from_basis_coefficients_fn(|_| <_ as CanSample<Val>>::sample(&mut reference));
    let main_gpu = upload(&runtime, &main, RowOrder::BitReversed);
    let pre_gpu = upload(&runtime, pre.as_ref().unwrap(), RowOrder::Natural);
    let public_gpu = runtime.allocate(2).unwrap();
    public_gpu
        .write(0, &public.map(|v| v.as_canonical_u64()))
        .unwrap();
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, false, true).scoped(
        CoverageScope::Operation,
        &[Stage::Transcript, Stage::Scalar, Stage::Lookup],
    );
    for stage in [Stage::Transcript, Stage::Scalar, Stage::Lookup] {
        capabilities.set(stage, Backend::Cuda);
    }
    let run = Run::new(
        "cuda_lookup_transcript",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap();
    let before = runtime.snapshot();
    let (witness, next) = runtime
        .reported(&run, || {
            let sampled = transcript.sample_resident(6)?;
            let challenges = mapping.finish(&sampled)?;
            let witness = engine.generate(
                &prepared,
                &main_gpu,
                Some(&pre_gpu),
                Some(&public_gpu),
                &challenges,
                Extension::Cubic,
            )?;
            transcript.observe_resident(witness.terminal().buffer, 0, 3)?;
            let next = transcript.sample_resident(3)?;
            Ok((witness, next))
        })
        .unwrap();
    let after = runtime.snapshot();
    assert!(run.finish(true).unwrap().stage_coverage_complete);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
    assert_eq!(
        witness.trace.read(1 << 20).unwrap(),
        words(&expected.values)
    );
    let mut actual = [0; 3];
    next.read(0, &mut actual).unwrap();
    assert_eq!(actual.as_slice(), words(&[expected_next]));
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_lookup_empty_buses_produce_zero_witness_without_private_uploads() {
    let runtime = runtime(limits());
    let engine = Lookups::new(&runtime).unwrap();
    let (layout, mut lookups) = simple(Expr::ONE);
    lookups[0].elements.clear();
    lookups[0].multiplicities.clear();
    let prepared = engine.prepare(layout, &lookups, 256 << 20).unwrap();
    let main = runtime
        .upload_matrix(
            MatrixSpec::new(8, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &[1; 256],
        )
        .unwrap();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let challenges = runtime.allocate(extension.degree() * 2).unwrap();
        let before = runtime.snapshot();
        let attempt = run();
        let witness = runtime
            .reported(&attempt, || {
                engine.generate(&prepared, &main, None, None, &challenges, extension)
            })
            .unwrap();
        assert!(attempt.finish(true).unwrap().stage_coverage_complete);
        assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            8
        );
        assert!(witness.trace.read(1 << 20).unwrap().iter().all(|&v| v == 0));
        let mut terminal = vec![1; extension.degree()];
        witness.terminal().buffer.read(0, &mut terminal).unwrap();
        assert!(terminal.iter().all(|&v| v == 0));
        drop(witness);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
}
