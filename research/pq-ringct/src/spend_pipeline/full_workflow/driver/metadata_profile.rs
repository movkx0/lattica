//! Process-isolated measurement of the real metadata path. No proof continuation
//! or successful-workflow retirement receipt is produced by this test-only stop.
use super::metadata_timing;
mod fixture;
mod replay;
pub(super) use fixture::capture;
use crate::component_tree::native_shape::cache;
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{
    HeightEnvelopeCacheStatistics, MetadataPlanningStatistics,
};
use std::{cell::Cell, marker::PhantomData, rc::Rc};

#[derive(Clone, Copy, Default)]
struct State {
    stopped: bool,
    reported: bool,
    fixture_load_ns: u128,
}
thread_local! { static ACTIVE: Cell<Option<State>> = const { Cell::new(None) }; }
struct Scope(PhantomData<Rc<()>>);
impl Scope {
    fn begin() -> Self {
        ACTIVE.with(|s| {
            assert!(s.get().is_none());
            s.set(Some(State::default()));
        });
        Self(PhantomData)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|s| s.set(None));
    }
}

pub(super) fn stop_before_execution() -> bool {
    ACTIVE.with(|s| match s.get() {
        Some(mut state) => {
            assert!(!state.stopped);
            state.stopped = true;
            s.set(Some(state));
            true
        }
        None => false,
    })
}
pub(super) fn assert_execution_allowed() {
    ACTIVE.with(|s| {
        assert!(
            s.get().is_none(),
            "metadata profiling cannot execute proofs"
        )
    });
}
pub(super) fn active() -> bool {
    ACTIVE.with(|s| s.get().is_some())
}

pub(super) fn phase_started(phase: metadata_timing::Phase) {
    ACTIVE.with(|s| {
        if s.get().is_some() {
            eprintln!("RINGCT_METADATA_PHASE {phase:?}");
        }
    });
}

#[derive(serde::Serialize)]
struct Report {
    schema: &'static str,
    hash_variant: &'static str,
    reuse_variant: &'static str,
    reuse_counters: [u64; 8],
    next_variant: &'static str,
    next_counters: [u64; 4],
    endpoint_adoptions: usize,
    transactions: usize,
    layout: &'static str,
    setup_seed: [u8; 32],
    context: [u8; 32],
    host_profile: &'static str,
    metadata_workers: usize,
    input_randomness: &'static str,
    complete_metadata: bool,
    complete_workflow: bool,
    recursive_proofs_generated: usize,
    retirement: &'static str,
    native_input_generation_ns: u128,
    fixture_load_verify_ns: u128,
    generation_and_startup_ns: u128,
    timing: metadata_timing::Statistics,
    registered_cache: HeightEnvelopeCacheStatistics,
    native_cache: cache::Statistics,
    native_families: [cache::FamilyStatistics; 13],
    expensive_misses: [Option<cache::Miss>; 32],
    planner: MetadataPlanningStatistics,
}
pub(super) const fn frame_bytes() -> usize {
    8 * core::mem::size_of::<Report>() + fixture::FRAME_BYTES + (8 << 10)
}

pub(super) fn record(
    complete_metadata: bool,
    transactions: usize,
    native_input_generation_ns: u128,
    generation_and_startup_ns: u128,
    timing: metadata_timing::Statistics,
    registered_cache: HeightEnvelopeCacheStatistics,
    native_cache: cache::Statistics,
    (native_families, expensive_misses): ([cache::FamilyStatistics; 13], [Option<cache::Miss>; 32]),
    planner: MetadataPlanningStatistics,
) -> std::io::Result<()> {
    ACTIVE.with(|s| {
        let state = s.get().expect("active metadata profile");
        assert_eq!(state.stopped, complete_metadata);
        assert!(!state.reported);
    });
    cache::emit_inventory()?;
    let report = Report {
        schema: "ringct-complete-metadata-profile-v1",
        hash_variant: crate::preparation_options::variant(),
        reuse_variant: crate::preparation_options::reuse_variant(),
        reuse_counters: crate::preparation_options::reuse_counts(),
        next_variant: crate::preparation_options::next_variant(),
        next_counters: crate::preparation_options::next_counts(),
        endpoint_adoptions: crate::preparation_options::endpoint_adoptions(),
        transactions,
        layout: "paired-v1",
        setup_seed: [0x11; 32],
        context: [0x22; 32],
        host_profile: "standard",
        metadata_workers: workers(),
        input_randomness: if native_input_generation_ns == 0 { "replayed-verified-public-fixture" } else { "fixed-public-parameters-fresh-private-entropy" },
        complete_metadata,
        complete_workflow: false,
        recursive_proofs_generated: 0,
        retirement: "process-teardown-incomplete-case-owners-retained",
        native_input_generation_ns,
        fixture_load_verify_ns: ACTIVE.with(|s| s.get().unwrap().fixture_load_ns),
        generation_and_startup_ns,
        timing,
        registered_cache,
        native_cache,
        native_families,
        expensive_misses,
        planner,
    };
    use std::io::Write;
    let mut out = std::io::stderr().lock();
    out.write_all(b"RINGCT_METADATA_STAGE_PROFILE ")?;
    serde_json::to_writer(&mut out, &report).map_err(std::io::Error::other)?;
    out.write_all(b"\n")?;
    ACTIVE.with(|s| {
        s.set(Some(State {
            stopped: complete_metadata,
            reported: true,
            fixture_load_ns: report.fixture_load_verify_ns,
        }))
    });
    Ok(())
}

fn set_fixture_load_ns(ns: u128) {
    ACTIVE.with(|s| { let mut state = s.get().expect("active fixture profile"); state.fixture_load_ns = ns; s.set(Some(state)); });
}
fn workers() -> usize {
    std::env::var("LATTICA_RINGCT_METADATA_WORKERS").ok().map(|v| v.parse().expect("metadata worker count")).unwrap_or(16)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiling_stops_once_and_refuses_execution() {
        assert!(!stop_before_execution());
        assert_execution_allowed();
        let scope = Scope::begin();
        assert!(std::panic::catch_unwind(assert_execution_allowed).is_err());
        assert!(stop_before_execution());
        assert!(std::panic::catch_unwind(stop_before_execution).is_err());
        drop(scope);
        assert_execution_allowed();
    }

    #[test]
    #[ignore = "guarded full profile, native N3 input generation; no recursive proofs"]
    fn complete_n3_metadata_stage() {
        assert_eq!(
            std::env::var("LATTICA_RINGCT_METADATA_STAGE_PROFILE").as_deref(),
            Ok("n3-paired-v1")
        );
        assert_eq!(
            std::env::var("LATTICA_RINGCT_HOST_PROFILE").as_deref(),
            Ok("standard")
        );
        assert_eq!(std::env::var("RUST_MIN_STACK").as_deref(), Ok("8388608"));
        let _scope = Scope::begin();
        if let Some(path) = std::env::var_os("LATTICA_RINGCT_METADATA_FIXTURE_IN") {
            replay::run(std::path::Path::new(&path)).unwrap_or_else(|error| panic!("complete fixture metadata boundary not reached: {error:?}"));
            ACTIVE.with(|s| assert!(s.get().is_some_and(|state| state.stopped && state.reported)));
            return;
        }
        eprintln!("RINGCT_METADATA_INPUT_GENERATION n=3 layout=paired-v1");
        let metadata_cpu = lattica_prover_p3::block_v2::machine::verifier::batch::shape::MetadataCpuOptions::workers(workers()).unwrap();
        assert_eq!(metadata_cpu.max_workers(), workers());
        let result = super::super::fresh_entry::run_n3(
            [0x11; 32],
            [0x22; 32],
            crate::graph_crypto::ShakeWrapperLayout::PairedV1,
            Default::default(),
            crate::host_memory_profile::HostMemoryProfile::Standard,
            true,
            metadata_cpu,
        );
        match result {
            Err(crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError::Workflow {
                cause: crate::execution::workflow_resources::WorkflowError::MetadataProfileComplete, ..
            }) => (),
            Err(error) => panic!("complete metadata boundary not reached: {error:?}"),
            Ok(_) => panic!("metadata profile entered complete workflow"),
        }
        ACTIVE.with(|s| {
            let state = s.get().unwrap();
            assert!(state.stopped && state.reported);
        });
        // Armed case owners intentionally remain retained by the existing error
        // path until this dedicated test process exits. Never forge completion.
    }
}
