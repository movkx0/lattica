use super::*;
use p3_field::PrimeCharacteristicRing;

#[test]
fn completed_prefix_bound_excludes_retired_memos_but_keeps_construction_allowance() {
    for streams in 1..=MAX_IDENTITY_STREAMS {
        let footprint = IdentityBatchFootprint::for_borrowed_program_bounds(streams, 123).unwrap();
        assert_eq!(footprint.retained_host_bytes, streams as u64 * IDENTITY_PREFIX_HOST_BYTES);
        assert_eq!(footprint.host_bytes, streams as u64 * ((32 << 20) + 4096)
            + crate::block_v2::machine::symbolic::HOST_BYTES
            + streams as u64 * WORKER_STACK_BYTES + (1 << 20));
        assert!(footprint.retained_host_bytes < streams as u64 * IDENTITY_PREFIX_CONSTRUCTION_BYTES);
    }
}

#[test]
fn streaming_and_resumed_prefix_preserve_every_rate_boundary() {
    for n in 0..=65 {
        let values: Vec<u64> = (0..n).map(|i| (i * 1234567) as u64).collect();
        let reference = commitment::hash_fields(DOMAIN, &values).unwrap();
        for split in 0..=n {
            let mut prefix = State::new(DOMAIN, n).unwrap();
            for &v in &values[..split] {
                prefix.push(v).unwrap();
            }
            for &v in &values[split..] {
                prefix.push(v).unwrap();
            }
            assert_eq!(prefix.finish().unwrap(), reference);
        }
    }
    assert!(State::new(commitment::MODULUS, 1).is_err());
    assert!(State::new(1, 2).unwrap().finish().is_err());
    let mut long = State::new(1, 1).unwrap();
    long.push(1).unwrap();
    assert!(long.push(2).is_err());
    assert!(State::new(1, 1).unwrap().push(commitment::MODULUS).is_err());
}

#[test]
fn real_program_identity_matches_slice_and_rejects_foreign_metadata() {
    let mut builder = crate::block_v2::machine::ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    builder.assert_equal(builder.public(0).unwrap(), input);
    let program = Arc::new(builder.finish(Some(64)).unwrap());
    let air = MachineAir::from_shared_program(Arc::clone(&program));
    let analysis = analysis::analyze(&air).unwrap();
    let constraints = crate::block_v2::machine::symbolic::prepare_machine(
        &air,
        crate::block_v2::machine::compiler_constants::Constants::cpu(),
    )
    .unwrap()
    .into_parts()
    .1;
    let fingerprint = fingerprint::bounded::encode(
        &constraints.base,
        &constraints.extension,
        &constraints.order,
        fingerprint::bounded::HOST_BYTES,
    )
    .unwrap();
    let roots = vec![[super::super::Val::from_u64(17); 4]; 1 << profile::CAP_HEIGHT];
    let common = super::super::common_from_cap(&air, p3_symmetric::MerkleCap::new(roots)).unwrap();
    let expected = super::super::program_identity(&air, &common, &analysis);
    assert_eq!(
        hash(&air, &analysis, &fingerprint, &common).unwrap(),
        expected
    );
    let context = IdentityCpuContext::new();
    let make = || {
        let cap_fields = common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment
            .roots()
            .len()
            * 4;
        let mut state = State::new(
            DOMAIN,
            prefix_len(&air, &analysis, &fingerprint).unwrap() + cap_fields,
        )
        .unwrap();
        for field in identity_stream::Cursor::new(&air, &analysis, &fingerprint) {
            state.push(field.unwrap()).unwrap();
        }
        CompletedIdentityPrefix {
            authority: Arc::clone(&context.authority),
            batch: 1,
            job: 7,
            program: Arc::clone(&program),
            header: identity_stream::header(&air),
            trailer: identity_stream::trailer(&analysis),
            fingerprint: fingerprint.clone(),
            cap_fields,
            state,
        }
    };
    assert!(make()
        .check_owner(&IdentityCpuContext::new(), 7, &air)
        .is_err());
    assert!(make().check_owner(&context, 8, &air).is_err());
    assert_eq!(
        make()
            .finish(&air, &analysis, &fingerprint, &common)
            .unwrap(),
        expected
    );
    let mut changed = fingerprint.clone();
    changed[0] ^= 1;
    assert!(make().finish(&air, &analysis, &changed, &common).is_err());
    let mut token = make();
    token.header[0] ^= 1;
    assert!(token
        .finish(&air, &analysis, &fingerprint, &common)
        .is_err());
    let mut token = make();
    token.trailer[0] ^= 1;
    assert!(token
        .finish(&air, &analysis, &fingerprint, &common)
        .is_err());
    let mut token = make();
    token.cap_fields += 4;
    assert!(token
        .finish(&air, &analysis, &fingerprint, &common)
        .is_err());
}

#[test]
fn cpu_worker_options_are_bounded_and_default_to_physical_topology() {
    for n in 1..=16 {
        assert!(IdentityCpuOptions::workers(n).unwrap().max_streams() <= n);
    }
    for s in ["0", "17", "serial", "batched-v1", "", "-1"] {
        assert!(IdentityCpuOptions::parse(s).is_err());
    }
    assert!(IdentityCpuOptions::parse("auto").unwrap().max_streams() <= 16);
}

#[test]
fn cpu_cohort_admission_selects_largest_ready_width_and_refuses_one_job_overflow() {
    let options = IdentityCpuOptions {
        requested_workers: Some(16),
        max_streams: 16,
    };
    for n in [1, 2, 4, 8, 16] {
        let allowance = IdentityBatchFootprint::for_borrowed_program_bounds(n, 0)
            .unwrap()
            .host_bytes;
        assert_eq!(options.fit_ready(16, allowance).unwrap().max_streams(), n);
        assert!(options
            .fit_ready(16, allowance - 1)
            .map(|o| o.max_streams() < n)
            .unwrap_or(n == 1));
    }
    assert!(options.fit_ready(0, u64::MAX).is_err());
    assert!(options.fit_ready(1, 0).is_err());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "exclusive guarded GPU preprocessing/proof and independent CPU verification"]
fn cpu_identity_and_prefixes_match_gpu_reference_without_gpu_identity_calls() {
    use super::super::{identity_receipt, RegisteredProgram};
    use crate::block_v2::{gpu_hash, quotient_pcs};
    fn initialize() {
        let fusion = quotient_pcs::initialize_research_from_env().unwrap();
        quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
        gpu_hash::initialize_from_env().unwrap();
        assert!(gpu_hash::initialize_resident_from_env().unwrap());
    }
    let _shutdown = gpu_hash::TestShutdownGuard;
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    };
    let mut builder = crate::block_v2::machine::ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    builder.assert_equal(builder.public(0).unwrap(), input);
    let program = Arc::new(builder.finish(Some(64)).unwrap());
    let air = || MachineAir::from_shared_program(Arc::clone(&program));
    initialize();
    let reference = RegisteredProgram::new_with_request(air(), 2 << 30, request).unwrap();
    let expected = reference.id();
    assert_eq!(
        expected,
        super::super::program_identity(
            reference.air(),
            &reference.prepared.data.common,
            reference.analysis()
        )
    );
    drop(reference);
    let before = identity_receipt::full_gpu_hashes();
    let (direct, reports) =
        RegisteredProgram::new_with_cpu_identity_and_report(air(), 2 << 30, request).unwrap();
    assert_eq!(direct.id(), expected);
    assert!(direct.identity_receipt().is_none());
    assert_eq!(reports.identity.policy, Policy::CpuRequired);
    assert_eq!(reports.preprocessing.policy, Policy::GpuRequired);
    let values = [super::super::Val::from_u64(9)];
    let proof = direct
        .prove_with_request(&values, &values, request)
        .unwrap();
    direct.verifier().verify(&proof, &values).unwrap();
    drop(direct);
    let context = IdentityCpuContext::new();
    let pending = context
        .plan_borrowed(
            IdentityCpuOptions::workers(2).unwrap(),
            vec![(0, &program), (1, &program)],
            2 << 30,
            0,
        )
        .unwrap()
        .execute(request)
        .unwrap();
    // An actual live GPU lease prevents CPU worker launch.
    assert!(pending.complete_after_retirement().is_err());
    let pending = context
        .plan_borrowed(
            IdentityCpuOptions::workers(2).unwrap(),
            vec![(0, &program), (1, &program)],
            2 << 30,
            0,
        )
        .unwrap()
        .execute(request)
        .unwrap();
    gpu_hash::shutdown().unwrap();
    let (tokens, reports) = pending.complete_after_retirement().unwrap();
    assert_eq!(reports.effective_workers, 2);
    initialize();
    for token in tokens {
        let (registered, reports) = RegisteredProgram::new_with_cpu_identity_prefix_and_report(
            air(),
            2 << 30,
            request,
            &context,
            token.job(),
            token,
        )
        .unwrap();
        assert_eq!(registered.id(), expected);
        assert!(registered.identity_receipt().is_none());
        assert_eq!(reports.identity.policy, Policy::CpuRequired);
        let proof = registered
            .prove_with_request(&values, &values, request)
            .unwrap();
        registered.verifier().verify(&proof, &values).unwrap();
    }
    assert_eq!(identity_receipt::full_gpu_hashes(), before);
    gpu_hash::shutdown().unwrap();
}
