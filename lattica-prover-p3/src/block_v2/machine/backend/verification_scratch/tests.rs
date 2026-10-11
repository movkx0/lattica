use super::*;
use crate::block_v2::machine::backend::RegisteredVerifier;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::block_v2::machine::ProgramBuilder;
use crate::spill_alloc::allocation_requests::{measure, Requests};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::MerkleCap;

fn verifier(publics: usize, height: usize) -> RegisteredVerifier {
    let log_lde = height.ilog2() as usize + 1 + profile::LOG_BLOWUP;
    RegisteredVerifier::from_trusted_cap(
        publics,
        height,
        MerkleCap::new(vec![[Val::ZERO; 4]; 1 << log_lde.min(profile::CAP_HEIGHT)]),
    )
    .unwrap()
}

fn plan(verifier: &RegisteredVerifier) -> Plan {
    Plan::new(&verifier.air, &verifier.common, verifier.quotient_chunks).unwrap()
}

fn bounded(requests: Requests, limit: usize) {
    assert!(!requests.overflow);
    assert!(
        requests.bytes <= limit,
        "{requests:?}, source bound={limit}"
    );
}

#[test]
fn allocation_ledger_covers_growth_boxing_sorting_and_single_height_map() {
    for n in [0, 1, 2, 3, 4, 7, 8, 9, 16, 17, 31, 32, 33, 1025] {
        let mut ledger = Ledger::default();
        ledger.growing::<Ext>(n).unwrap();
        ledger.exact::<Ext>(n).unwrap(); // Possible boxed-slice shrink.
        let (values, observed) = measure(|| {
            let mut values = Vec::new();
            for i in 0..n {
                values.push(Ext::from_u64(i as u64));
            }
            values.into_boxed_slice()
        });
        bounded(observed, ledger.0);
        assert_eq!(values.len(), n);

        let mut ledger = Ledger::default();
        ledger.growing::<SortedDimension>(n).unwrap();
        ledger.exact::<SortedDimension>(n).unwrap();
        let dims: Vec<_> = (0..n)
            .map(|i| Dimensions {
                width: 1,
                height: n - i,
            })
            .collect();
        let (values, observed) = measure(|| {
            let mut values: Vec<_> = dims.iter().enumerate().collect();
            values.sort_by_key(|(_, dim)| dim.height);
            values
        });
        bounded(observed, ledger.0);
        assert_eq!(values.len(), n);
    }
    let (values, observed) = measure(|| {
        let mut values = std::collections::BTreeMap::new();
        for _ in 0..32 {
            values.insert(29usize, (Ext::ONE, Ext::ZERO));
        }
        values
    });
    assert_eq!(values.len(), 1);
    bounded(
        observed,
        8 * size_of::<usize>() + 11 * (size_of::<usize>() + size_of::<(Ext, Ext)>()),
    );
    assert_eq!(observed.calls, 1);
    assert!(Ledger::default().exact::<Ext>(usize::MAX).is_err());
    assert!(Ledger::default().growing::<Val>(usize::MAX).is_err());
    assert!(Ledger(usize::MAX).bytes(1).is_err());
    assert!(Ledger::default().repeat(Ledger(2), usize::MAX).is_err());
    let (_, observed) = measure(|| std::hint::black_box(7usize));
    assert_eq!(observed.bytes, 0);
    eprintln!("native_verifier_scratch_primitives growth=true boxing=true sorting=true single_height_map=true overflow=true");
}

#[test]
fn trusted_geometry_bounds_all_templates_and_exact_limit_boundary() {
    let mut maximum = 0;
    let mut cases = 0;
    for publics in [0, 1, 23, 32, 33, 64] {
        let mut previous = 0;
        for height in [8, 64, 1 << 19, 1 << 24] {
            let verifier = verifier(publics, height);
            let (plan, observed) = measure(|| plan(&verifier));
            assert_eq!(observed.bytes, 0, "planning must not allocate");
            assert_eq!(
                plan.requested_bytes,
                plan.batch_bytes + plan.transcript_bytes + plan.lookup_bytes + plan.fri_bytes
            );
            assert!(plan.requested_bytes > previous);
            assert!(plan.admit(plan.requested_bytes).is_ok());
            assert!(plan.admit(plan.requested_bytes - 1).is_err());
            assert!(plan.admit(LIMIT_BYTES).is_ok());
            maximum = maximum.max(plan.requested_bytes);
            previous = plan.requested_bytes;
            cases += 1;
        }
    }
    eprintln!("native_verifier_scratch_templates cases={cases} max_requested_bytes={maximum} limit_bytes={LIMIT_BYTES} wide={}", cfg!(feature = "block-v2-wide-lanes"));
}

#[test]
fn unsupported_trusted_geometry_cannot_reuse_the_bound() {
    let mut v = verifier(1, 8);
    for chunks in [0, 3, profile::MAX_QUOTIENT_CHUNKS + 1, usize::MAX] {
        assert!(Plan::new(&v.air, &v.common, chunks).is_err());
    }
    v.common
        .preprocessed
        .as_mut()
        .unwrap()
        .matrix_to_instance
        .push(0);
    assert!(Plan::new(&v.air, &v.common, v.quotient_chunks).is_err());
    v.common
        .preprocessed
        .as_mut()
        .unwrap()
        .matrix_to_instance
        .pop();
    v.common.preprocessed.as_mut().unwrap().instances[0]
        .as_mut()
        .unwrap()
        .degree_bits += 1;
    assert!(Plan::new(&v.air, &v.common, v.quotient_chunks).is_err());
    v.common.preprocessed.as_mut().unwrap().instances[0]
        .as_mut()
        .unwrap()
        .degree_bits -= 1;
    let mut entries = v.common.lookups[0].to_vec();
    entries.last_mut().unwrap().kind = Kind::Global("unadmitted-global-bus".into());
    v.common.lookups[0] = p3_lookup::Lookups::try_from_ordered(entries).unwrap();
    assert!(Plan::new(&v.air, &v.common, v.quotient_chunks).is_err());
    v.common.lookups[0] = p3_lookup::Lookups::try_from_ordered(Vec::new()).unwrap();
    assert!(Plan::new(&v.air, &v.common, v.quotient_chunks).is_err());
    eprintln!("native_verifier_scratch_geometry unsupported_rejected=true");
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[test]
fn numerical_allocations_and_verification_decisions_fit_the_source_bound() {
    use super::super::{verify_batch, BatchProof, RegisteredProgram};
    fn check(
        registered: &RegisteredProgram,
        config: &Config,
        proof: &BatchProof<Config>,
        public: &[Vec<Val>],
        valid: bool,
    ) {
        super::super::verification_envelope::check(
            &registered.air,
            &registered.data.common,
            registered.analysis.quotient_chunks,
            proof,
        )
        .unwrap();
        let plan = Plan::new(
            &registered.air,
            &registered.data.common,
            registered.analysis.quotient_chunks,
        )
        .unwrap();
        let (result, observed) = measure(|| {
            verify_batch(
                config,
                core::slice::from_ref(&registered.air),
                proof,
                public,
                &registered.data.common,
            )
        });
        assert_eq!(result.is_ok(), valid, "{result:?}");
        bounded(observed, plan.requested_bytes);
        assert_eq!(registered.verify(proof, &public[0]).is_ok(), valid);
        eprintln!("native_verifier_scratch_observed height={} publics={} valid={valid} requested_bytes={} calls={} largest={} source_bound={} wide={}",
            registered.air.program().height(), public[0].len(), observed.bytes, observed.calls, observed.largest, plan.requested_bytes, cfg!(feature = "block-v2-wide-lanes"));
    }
    for publics in [1, 33] {
        for height in [8, 64] {
            let mut builder = ProgramBuilder::new(publics).unwrap();
            let public = builder.public(0).unwrap();
            let input = builder.input();
            builder.assert_equal(public, input);
            let registered =
                RegisteredProgram::new(MachineAir::new(builder.finish(Some(height)).unwrap()))
                    .unwrap();
            let mut public = vec![vec![Val::ZERO; publics]];
            public[0][0] = Val::from_u64(17);
            let mut proof = registered.prove(&public[0], &[public[0][0]]).unwrap();
            let config = profile::make_config();
            check(&registered, &config, &proof, &public, true);
            public[0][0] += Val::ONE;
            check(&registered, &config, &proof, &public, false);
            public[0][0] -= Val::ONE;
            proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] += Ext::ONE;
            check(&registered, &config, &proof, &public, false);
            proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] -= Ext::ONE;
            // The last query forces prior query work to finish before rejection.
            let last = profile::NUM_QUERIES - 1;
            proof.opening_proof.1.query_proofs[last].input_proof[0].opened_values[0][0] += Val::ONE;
            check(&registered, &config, &proof, &public, false);
            proof.opening_proof.1.query_proofs[last].input_proof[0].opened_values[0][0] -= Val::ONE;
            let layer = proof.opening_proof.1.query_proofs[last]
                .commit_phase_openings
                .len()
                - 1;
            proof.opening_proof.1.query_proofs[last].commit_phase_openings[layer].sibling_values
                [0] += Ext::ONE;
            check(&registered, &config, &proof, &public, false);
            proof.opening_proof.1.query_proofs[last].commit_phase_openings[layer].sibling_values
                [0] -= Ext::ONE;
            check(&registered, &config, &proof, &public, true);
        }
    }
    eprintln!("native_verifier_scratch_numerical proofs=4 attempts=24 malformed=16 valid=8 decisions_match=true");
}
