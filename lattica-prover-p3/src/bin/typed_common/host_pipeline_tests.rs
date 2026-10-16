use super::*;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc, Mutex,
};
use std::time::Duration;

#[test]
fn preparation_overlaps_proving_without_moving_the_caller() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    pool.install(|| {
        let caller = std::thread::current().id();
        let (entered, wait_entered) = mpsc::channel();
        let (prepared, wait_prepared) = mpsc::channel();
        let wait_entered = Mutex::new(wait_entered);
        let finished = AtomicUsize::new(0);
        let stats = run(
            &[0, 1, 2],
            |task| {
                if *task == 1 {
                    wait_entered
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))?;
                    prepared.send(())?;
                }
                Ok(())
            },
            |task, ()| {
                assert_eq!(std::thread::current().id(), caller);
                if *task == 0 {
                    entered.send(())?;
                    wait_prepared.recv_timeout(Duration::from_secs(5))?;
                }
                Ok(*task)
            },
            |task, output| {
                assert_eq!(*task, output);
                assert_eq!(finished.fetch_add(1, Ordering::SeqCst), *task);
                Ok(())
            },
            |_, _| false,
        )
        .unwrap();
        assert_eq!(finished.load(Ordering::SeqCst), 3);
        assert_eq!(stats.rounds, 3);
        assert_eq!(stats.dependency_barriers, 0);
        assert!(stats.concurrent_seconds > 0.0);
    });
}

#[test]
fn parents_wait_for_successful_retirement_and_the_root_is_drained() {
    let finished = AtomicU64::new(0);
    let tasks = [(0, 0), (1, 0), (2, 0b11), (3, 0b100)];
    let stats = run(
        &tasks,
        |&(_, children)| {
            assert_eq!(finished.load(Ordering::SeqCst) & children, children);
            Ok(())
        },
        |&(id, _), ()| Ok(id),
        |&(id, _), output| {
            assert_eq!(id, output);
            assert_eq!(finished.fetch_or(1 << id, Ordering::SeqCst) & (1 << id), 0);
            Ok(())
        },
        |&(_, children), &(producer, _)| children & (1 << producer) != 0,
    )
    .unwrap();
    assert_eq!(finished.load(Ordering::SeqCst), 0b1111);
    assert_eq!(stats.dependency_barriers, 2);
}

#[test]
fn failed_retirement_blocks_prefetch_and_discards_speculative_output() {
    let prepared = AtomicUsize::new(0);
    let proved = AtomicUsize::new(0);
    let finished = AtomicUsize::new(0);
    let result = run(
        &[0, 1, 2],
        |_| {
            prepared.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_, ()| {
            proved.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_, ()| {
            finished.fetch_add(1, Ordering::SeqCst);
            Err("verification rejected".into())
        },
        |_, _| false,
    );
    assert_eq!(result.err().unwrap().to_string(), "verification rejected");
    assert_eq!(prepared.load(Ordering::SeqCst), 2);
    assert_eq!(proved.load(Ordering::SeqCst), 2);
    assert_eq!(finished.load(Ordering::SeqCst), 1);
}

#[test]
fn proof_failure_drains_the_cpu_branch_and_does_not_publish_a_root() {
    let finished = AtomicUsize::new(0);
    let result = run(
        &[0, 1, 2],
        |_| Ok(()),
        |task, ()| {
            if *task == 1 {
                Err("GPU rejected".into())
            } else {
                Ok(())
            }
        },
        |_, ()| {
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_, _| false,
    );
    assert_eq!(result.err().unwrap().to_string(), "GPU rejected");
    assert_eq!(finished.load(Ordering::SeqCst), 1);
}

#[test]
fn empty_and_single_task_pipelines_finish_without_prefetch() {
    for count in 0..=1 {
        let tasks = vec![(); count];
        let finished = AtomicUsize::new(0);
        let stats = run(
            &tasks,
            |_| Ok(()),
            |_, ()| Ok(()),
            |_, ()| {
                finished.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _| false,
        )
        .unwrap();
        assert_eq!(finished.load(Ordering::SeqCst), count);
        assert_eq!(stats.rounds, count);
    }
}
