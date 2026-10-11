use super::*;
use crate::block_v2::execution::job::test_support::pin;

#[test]
fn full_cost_history_eviction_and_worker_forgetting_preserve_storage_and_estimates() {
    let job = Job::empty(pin(), [9; 32], 0, 0).unwrap();
    let worker = |id| WorkerCapabilities {
        worker: WorkerId(id),
        profile: pin().profile(),
        resources: super::super::Resources {
            ram_bytes: 1024,
            vram_bytes: 0,
            scratch_bytes: 0,
            threads: 2,
        },
        resident_mode: None,
    };
    let mut model = CostModel::new(100).unwrap();
    let plan = CostModel::storage_plan().unwrap();
    let empty = model.retained_storage_bytes().unwrap();
    for id in 1..=MAX_CLASSES as u64 {
        let capability = worker(id);
        for sample in 1..=MAX_SAMPLES as u64 {
            model.observe(&capability, &job, false, sample).unwrap();
        }
        assert_eq!(
            model.estimate(&capability, &job, false).unwrap(),
            (68, true)
        );
    }
    let full = model.retained_storage_bytes().unwrap();
    assert!(empty < full && full <= plan.retained_bytes);
    model
        .observe(&worker(MAX_CLASSES as u64 + 1), &job, false, 10)
        .unwrap();
    assert_eq!(model.samples.len(), MAX_CLASSES);
    assert_eq!(
        model.estimate(&worker(1), &job, false).unwrap(),
        (100, false)
    );
    for id in 1..=MAX_CLASSES as u64 + 1 {
        model.forget_worker(WorkerId(id));
    }
    let drained = model.retained_storage_bytes().unwrap();
    assert!(model.samples.is_empty() && model.insertion_order.is_empty());
    assert!(empty < drained && drained < full); // ring capacity survives removals
    assert_eq!(
        model.estimate(&worker(2), &job, false).unwrap(),
        (100, false)
    );
    eprintln!(
        "bounded_scheduler_storage retained_bytes={} selection_bytes={} total_bytes={} empty_bytes={empty} full_bytes={full} drained_bytes={drained} classes={MAX_CLASSES} samples_per_class={MAX_SAMPLES}",
        plan.retained_bytes, plan.selection_bytes, plan.total_bytes().unwrap()
    );
}
