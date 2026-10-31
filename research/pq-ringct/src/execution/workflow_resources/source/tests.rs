use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use std::cell::Cell;

fn bytes(host: u64) -> Bytes {
    Bytes { host, device: 0 }
}

fn requirements() -> Requirements {
    let mut requirements = Requirements::single(Category::PhaseScratch, bytes(128));
    requirements.add(Category::SymbolicCompiler, bytes(64)).unwrap();
    requirements.add(Category::Report, bytes(32)).unwrap();
    requirements.add(Category::RegisteredMetadata, bytes(SlotPool::bookkeeping_bytes(2).unwrap())).unwrap();
    requirements
}

fn specs() -> [SlotSpec; 2] {
    [
        SlotSpec { requirements: Requirements::single(Category::SymbolicCompiler, bytes(64)) },
        SlotSpec { requirements: Requirements::single(Category::Report, bytes(32)) },
    ]
}

struct Payload {
    ledger: Ledger,
    dropped: Rc<Cell<bool>>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        assert_eq!(self.ledger.snapshot().current, bytes(96 + SlotPool::bookkeeping_bytes(2).unwrap()));
        self.dropped.set(true);
    }
}

#[test]
fn borrowed_source_phase_returns_ready_while_original_output_survives() {
    let context = ProvingContext::cpu(8192).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let other = Ledger::new(WorkerAllowance { host: 1024, device: 0 });
    let mut phase = capability.admit(requirements()).unwrap();
    let pool = SlotPool::new_borrowed(&mut phase, &specs()).unwrap();
    pool.begin().unwrap();
    let dropped = Rc::new(Cell::new(false));
    let source = SourceRetained {
        payload: Payload { ledger: ledger.clone(), dropped: Rc::clone(&dropped) },
        source: [1; 32],
        compiled_source: [2; 32],
        claim: pool.claim(SlotId::new(0)).unwrap(),
    };
    let failure = pool.claim(SlotId::new(1)).unwrap();
    phase.complete_after_cleanup().unwrap();
    pool.after_cleanup().unwrap();
    pool.retire().unwrap();
    drop(failure);
    drop(pool);
    assert_eq!(capability.status(), Status::Ready);
    assert_eq!(ledger.snapshot().current, bytes(96 + SlotPool::bookkeeping_bytes(2).unwrap()));
    assert!(source.belongs_to(&ledger));
    assert!(!source.belongs_to(&other));
    let moved = source;
    assert_eq!(moved.source_fingerprint(), [1; 32]);
    assert!(!dropped.get());
    drop(moved);
    assert!(dropped.get());
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn failed_actual_source_cleanup_retains_payload_and_originals_until_terminal_cleanup() {
    let context = ProvingContext::cpu(8192).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit(requirements()).unwrap();
    let pool = SlotPool::new_borrowed(&mut phase, &specs()).unwrap();
    pool.begin().unwrap();
    let dropped = Rc::new(Cell::new(false));
    let pending = SourceRetained {
        payload: Payload { ledger: ledger.clone(), dropped: Rc::clone(&dropped) },
        source: [1; 32],
        compiled_source: [2; 32],
        claim: pool.claim(SlotId::new(0)).unwrap(),
    };
    let failure_claim = pool.claim(SlotId::new(1)).unwrap();
    let busy = context.registry.borrow_mut();
    let status = phase.complete_after_cleanup().unwrap_err();
    pool.poison();
    let failure = SourceFailure {
        pending: Some(pending),
        error: None,
        status: Some(status.into()),
        claim: failure_claim,
    };
    assert_eq!(capability.status(), Status::Poisoned);
    assert_eq!(ledger.snapshot().current, bytes(224 + SlotPool::bookkeeping_bytes(2).unwrap()));
    assert!(!dropped.get());
    assert!(pool.begin().is_err());
    drop(busy);
    capability.retire().unwrap();
    pool.retire_after_cleanup();
    drop(pool);
    assert_eq!(ledger.snapshot().current, bytes(96 + SlotPool::bookkeeping_bytes(2).unwrap()));
    assert!(!dropped.get());
    assert!(failure.status().is_some());
    drop(failure);
    assert!(dropped.get());
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

fn graph_specs(graph: &PreparedGraphSources) -> [SlotSpec; 2] {
    [SlotSpec { requirements: graph.initial_output_requirements().unwrap() },
        SlotSpec { requirements: Requirements::single(Category::Report, bytes(32)) }]
}

fn graph_requirements(graph: &PreparedGraphSources) -> Requirements {
    let specs = graph_specs(graph);
    let mut requirements = combine(specs[0].requirements, specs[1].requirements).unwrap();
    requirements = combine(requirements, SlotPool::bookkeeping_requirements(2).unwrap()).unwrap();
    requirements.add(Category::PhaseScratch, bytes(128)).unwrap();
    requirements
}

// Tests may construct refused tokens to exercise the private checks. Production
// issues one only inside execute_source's successful post-cleanup arm.
fn graph_cleanup_token<'pool>(pool: &'pool Rc<SlotPool>, source: &SourceRetained<PreparedGraphSources>)
    -> CompletedSourceCleanup<'pool>
{
    CompletedSourceCleanup { pool, claim: &source.claim, payload: &source.payload as *const _ as *const () }
}

#[test]
fn checked_graph_releases_only_surplus_after_cleanup_and_survives_moves() {
    let graph = PreparedGraphSources::retention_fixture();
    let full = graph.initial_output_requirements().unwrap();
    let actual = graph.retained_graph_host_bytes().unwrap();
    let release = full.get(Category::SymbolicCompiler).host - actual;
    assert!(release > 0);
    let context = ProvingContext::cpu(2 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit(graph_requirements(&graph)).unwrap();
    let pool = SlotPool::new_borrowed(&mut phase, &graph_specs(&graph)).unwrap();
    pool.begin().unwrap();
    let mut source = SourceRetained { payload: graph, source: [1; 32], compiled_source: [2; 32],
        claim: pool.claim(SlotId::new(0)).unwrap() };
    let failure = pool.claim(SlotId::new(1)).unwrap();
    let before_cleanup = ledger.snapshot();
    let premature = graph_cleanup_token(&pool, &source);
    assert!(source.claim.retain_completed_graph(&source.payload, &premature).is_err());
    assert_eq!(ledger.snapshot(), before_cleanup);
    phase.complete_after_cleanup().unwrap(); pool.after_cleanup().unwrap(); pool.retire().unwrap();
    let before = ledger.snapshot();
    let cleanup = graph_cleanup_token(&pool, &source);
    source.claim.retain_completed_graph(&source.payload, &cleanup).unwrap();
    let after = ledger.snapshot();
    assert_eq!(after.current, bytes(before.current.host - release));
    assert_eq!(after.peak, before.peak);
    for category in Category::ALL {
        if category == Category::SymbolicCompiler {
            assert_eq!(after.categories[category as usize].current, bytes(actual));
        } else {
            assert_eq!(after.categories[category as usize].current, before.categories[category as usize].current);
        }
    }
    assert!(source.claim.retain_completed_graph(&source.payload, &cleanup).is_err());
    assert_eq!(ledger.snapshot(), after);
    assert!(pool.begin().is_err());
    drop(failure); drop(pool);
    let moved = source;
    assert!(moved.belongs_to(&ledger));
    assert_eq!(moved.get().retained_graph_host_bytes().unwrap(), actual);
    assert_eq!(moved.source_fingerprint(), [1; 32]);
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn wrong_payload_or_cleanup_pool_never_releases_an_original() {
    let graph = PreparedGraphSources::retention_fixture();
    let other_graph = PreparedGraphSources::retention_fixture();
    assert_eq!(graph.initial_output_requirements().unwrap(), other_graph.initial_output_requirements().unwrap());
    let context = ProvingContext::cpu(2 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit(graph_requirements(&graph)).unwrap();
    let pool = SlotPool::new_borrowed(&mut phase, &graph_specs(&graph)).unwrap(); pool.begin().unwrap();
    let mut source = SourceRetained { payload: graph, source: [1; 32], compiled_source: [2; 32],
        claim: pool.claim(SlotId::new(0)).unwrap() };
    let failure = pool.claim(SlotId::new(1)).unwrap();
    phase.complete_after_cleanup().unwrap(); pool.after_cleanup().unwrap(); pool.retire().unwrap();
    let cleanup = graph_cleanup_token(&pool, &source);
    let before = ledger.snapshot();
    assert!(source.claim.retain_completed_graph(&other_graph, &cleanup).is_err());
    assert_eq!(ledger.snapshot(), before);

    let other_context = ProvingContext::cpu(2 << 30).unwrap();
    let mut other_capability = other_context.phase_capability(Bytes::ZERO).unwrap();
    let other_ledger = other_capability.ledger().clone();
    let mut other_phase = other_capability.admit(graph_requirements(&other_graph)).unwrap();
    let other_pool = SlotPool::new_borrowed(&mut other_phase, &graph_specs(&other_graph)).unwrap();
    other_pool.begin().unwrap();
    let other_source = SourceRetained { payload: other_graph, source: [1; 32], compiled_source: [2; 32],
        claim: other_pool.claim(SlotId::new(0)).unwrap() };
    let other_failure = other_pool.claim(SlotId::new(1)).unwrap();
    other_phase.complete_after_cleanup().unwrap(); other_pool.after_cleanup().unwrap(); other_pool.retire().unwrap();
    let wrong_cleanup = graph_cleanup_token(&other_pool, &other_source);
    let other_before = other_ledger.snapshot();
    assert!(source.claim.retain_completed_graph(&source.payload, &wrong_cleanup).is_err());
    assert_eq!(ledger.snapshot(), before); assert_eq!(other_ledger.snapshot(), other_before);
    drop(other_failure); drop(other_source); drop(other_pool);
    drop(failure); drop(source); drop(pool);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(other_ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn incomplete_output_original_refuses_without_releasing_split_storage() {
    let graph = PreparedGraphSources::retention_fixture();
    let context = ProvingContext::cpu(2 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit(graph_requirements(&graph)).unwrap();
    let pool = SlotPool::new_borrowed(&mut phase, &graph_specs(&graph)).unwrap(); pool.begin().unwrap();
    let mut source = SourceRetained { payload: graph, source: [1; 32], compiled_source: [2; 32],
        claim: pool.claim(SlotId::new(0)).unwrap() };
    let failure = pool.claim(SlotId::new(1)).unwrap();
    phase.complete_after_cleanup().unwrap(); pool.after_cleanup().unwrap(); pool.retire().unwrap();
    let split = source.claim.split(Requirements::single(Category::SymbolicCompiler, bytes(1))).unwrap();
    let before = ledger.snapshot(); let cleanup = graph_cleanup_token(&pool, &source);
    assert!(source.claim.retain_completed_graph(&source.payload, &cleanup).is_err());
    assert_eq!(ledger.snapshot(), before);
    assert!(source.claim.reunite(split).is_ok());
    source.claim.retain_completed_graph(&source.payload, &cleanup).unwrap();
    drop(failure); drop(source); drop(pool);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn failed_graph_cleanup_keeps_full_output_and_failure_claims() {
    let graph = PreparedGraphSources::retention_fixture();
    let full = graph.initial_output_requirements().unwrap();
    let context = ProvingContext::cpu(2 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit(graph_requirements(&graph)).unwrap();
    let pool = SlotPool::new_borrowed(&mut phase, &graph_specs(&graph)).unwrap(); pool.begin().unwrap();
    let mut source = SourceRetained { payload: graph, source: [1; 32], compiled_source: [2; 32],
        claim: pool.claim(SlotId::new(0)).unwrap() };
    let failure_claim = pool.claim(SlotId::new(1)).unwrap();
    let busy = context.registry.borrow_mut();
    let status = phase.complete_after_cleanup().unwrap_err(); pool.poison();
    let before = ledger.snapshot(); let invalid_cleanup = graph_cleanup_token(&pool, &source);
    assert!(source.claim.retain_completed_graph(&source.payload, &invalid_cleanup).is_err());
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(before.categories[Category::SymbolicCompiler as usize].current,
        full.get(Category::SymbolicCompiler));
    let failed = SourceFailure { pending: Some(source), error: None, status: Some(status.into()), claim: failure_claim };
    drop(busy); capability.retire().unwrap(); pool.retire_after_cleanup(); drop(pool);
    assert_eq!(ledger.snapshot().categories[Category::SymbolicCompiler as usize].current,
        full.get(Category::SymbolicCompiler));
    assert!(failed.status().is_some()); drop(failed);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
