use super::*;
use crate::proving::{Capabilities, CoverageScope, Policy, Profile, Request};
use p3_field::PrimeCharacteristicRing;

#[test]
fn tree_staging_includes_statements_during_dummy_generation() {
    let layout = crate::batch_joinsplit_air::device_batch_geometry();
    let dummy = Plan::new(1 << 20).unwrap().staging_bytes().unwrap();
    for count in [1, 3, crate::MAX_TREE_TX] {
        let statements = count * js::N_PUBLIC;
        let host = (statements + 3 + 4 * layout.chunks.len()) * 8 + dummy;
        assert!(TreePlan::new(statements, host - 1).is_err());
        let plan = TreePlan::new(statements, host).unwrap();
        let words = plan.words().unwrap();
        assert_eq!(words.len(), plan.specs[1].words());
        assert_eq!(words.capacity(), words.len());
        assert!(TreePlan::new(statements, (statements + words.len() + 4) * 8).is_err());
    }
    for words in [
        0,
        js::N_PUBLIC - 1,
        (crate::MAX_TREE_TX + 1) * js::N_PUBLIC,
        usize::MAX,
    ] {
        assert!(TreePlan::new(words, usize::MAX).is_err());
    }
}

#[test]
#[ignore = "requires release native GPU startup in a 1 GiB managed bounded service"]
fn gpu_tree_roots_match_cpu_through_maximum_count_without_private_readback() {
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 0);
    let mut caps = Capabilities::cpu(Profile::LegacyQuadratic, false, false).scoped(
        CoverageScope::Operation,
        &[Stage::WitnessTrace, Stage::PublicValues],
    );
    caps.set(Stage::WitnessTrace, Backend::OpenCl);
    caps.set(Stage::PublicValues, Backend::OpenCl);
    let session = DeviceSession::new().unwrap();
    let run = Run::new(
        "legacy_tree_root_differential",
        Request {
            policy: Policy::GpuRequired,
            emit_report: true,
        },
        caps,
    )
    .unwrap();
    let before = session.stats();
    let allocations = crate::block_v2::gpu_hash::report("tree_rejection_before")
        .unwrap()
        .allocations;
    for (fields, count, allowance) in [
        (vec![], 0, 1 << 30),
        (vec![0; js::N_PUBLIC], crate::MAX_TREE_TX + 1, 1 << 30),
        (vec![0; js::N_PUBLIC - 1], 1, 1 << 30),
        (vec![GOLDILOCKS_MODULUS; js::N_PUBLIC], 1, 1 << 30),
        (vec![0; js::N_PUBLIC], 1, 0),
    ] {
        assert!(session
            .joinsplit_tree_root(&fields, count, allowance, &run)
            .is_err());
    }
    let after = session.stats();
    assert_eq!(before, after);
    assert_eq!(
        allocations,
        crate::block_v2::gpu_hash::report("tree_rejection_after")
            .unwrap()
            .allocations
    );
    let counts = [
        1, 2, 3, 4, 5, 7, 8, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1023, 1024,
    ];
    for count in counts {
        let fields: Vec<_> = (0..count * js::N_PUBLIC)
            .map(|i| {
                if i % 3 == 0 {
                    GOLDILOCKS_MODULUS - 1 - i as u64
                } else {
                    (i * 7919 + count) as u64
                }
            })
            .collect();
        let before = session.stats();
        let geometry_words = 3 + 4 * crate::batch_joinsplit_air::device_batch_geometry()
            .chunks
            .len();
        let host = (fields.len() + geometry_words) * 8
            + Plan::new(1 << 20).unwrap().staging_bytes().unwrap();
        let allocations = crate::block_v2::gpu_hash::report("tree_staging_before")
            .unwrap()
            .allocations;
        assert!(session
            .joinsplit_tree_root(&fields, count, host - 1, &run)
            .is_err());
        assert_eq!(session.stats(), before);
        assert_eq!(
            crate::block_v2::gpu_hash::report("tree_staging_after")
                .unwrap()
                .allocations,
            allocations
        );
        let actual = session
            .joinsplit_tree_root(&fields, count, host, &run)
            .unwrap();
        assert_eq!(
            session.stats().downloaded_bytes - before.downloaded_bytes,
            40
        );
        let mut expected = [Val::ZERO; 4];
        for public in fields.chunks_exact(js::N_PUBLIC) {
            let public: Vec<_> = public.iter().copied().map(Val::from_u64).collect();
            expected = js::merge(
                expected,
                crate::batch_joinsplit_air::tx_statement_digest(&public),
            );
        }
        expected = crate::finish_tree_root(expected, count);
        assert_eq!(
            actual,
            expected.map(|v| v.as_canonical_u64()),
            "count={count}"
        );
    }
    assert!(run.finish(true).unwrap().stage_coverage_complete);
    drop(session);
    assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 0);
    eprintln!("legacy_gpu_tree_roots_matched counts=18 maximum=1024 rejected_uploads=0 public_readback_bytes_per_root=32 control_readback_bytes_per_root=8");
}
