use super::*;

#[test]
fn phase_notifications_wake_coordinator_without_retiring_or_reusing_slot() {
    let acknowledged = (std::sync::Mutex::new(false), std::sync::Condvar::new());
    let (_, stats) = scoped_with_progress(
        1,
        |_| (),
        |_, _: (), progress| {
            assert_eq!(progress.slot(), 0);
            progress.notify();
            progress.notify();
            let (seen, timeout) = acknowledged
                .1
                .wait_timeout_while(
                    acknowledged.0.lock().unwrap(),
                    std::time::Duration::from_secs(5),
                    |s| !*s,
                )
                .unwrap();
            assert!(!timeout.timed_out() && *seen);
            42
        },
        |queue| {
            queue.submit(0, ()).unwrap();
            assert!(matches!(queue.receive_event().unwrap(), Event::Progress(0)));
            assert_eq!(queue.idle_slot(), None);
            assert_eq!(queue.submit(0, ()), Err(Error::Slot));
            *acknowledged.0.lock().unwrap() = true;
            acknowledged.1.notify_one();
            let done = queue.receive().unwrap();
            assert_eq!(done.slot, 0);
            assert_eq!(done.result, Ok(42));
            assert_eq!(queue.idle_slot(), Some(0));
            assert!(queue.try_receive_event().unwrap().is_none());
        },
    )
    .unwrap();
    assert_eq!(stats.jobs_started, 1);
}
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[test]
fn refills_before_slow_job_finishes_and_reuses_worker_state() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (values, stats) = scoped_with_state(
        2,
        |_| 0usize,
        |scratch, job: usize| {
            *scratch += 1;
            if job == 0 {
                let (lock, changed) = &*gate;
                let guard = lock.lock().unwrap();
                let (guard, timeout) = changed
                    .wait_timeout_while(guard, std::time::Duration::from_secs(5), |open| !*open)
                    .unwrap();
                assert!(!timeout.timed_out() && *guard, "queue did not refill");
            }
            (job, *scratch)
        },
        |queue| {
            let mut output = [0; 9];
            queue.submit(0, 0).unwrap();
            queue.submit(1, 1).unwrap();
            for next in 2..9 {
                let done = queue.receive().unwrap();
                let (job, used) = done.result.unwrap();
                assert_ne!(job, 0);
                output[job] = used;
                queue.submit(done.slot, next).unwrap();
            }
            // Seven refills completed while the original slow job was outstanding.
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            for _ in 0..2 {
                let (job, used) = queue.receive().unwrap().result.unwrap();
                output[job] = used;
            }
            output
        },
    )
    .unwrap();
    assert_eq!(stats.threads_spawned, 2);
    assert_eq!(stats.jobs_started, 9);
    assert_eq!(values[8], 8);
    assert!(stats.peak_active_workers <= 2);
}

#[test]
fn panics_and_partial_spawns_retire_all_scratch_and_job_owners() {
    struct Owner(Arc<AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let result = scoped_with_state(
        2,
        |_| Owner(dropped.clone()),
        |_, job: Owner| {
            drop(job);
            panic!("worker failure");
        },
        |queue| {
            queue.submit(0, Owner(dropped.clone())).unwrap();
            queue.submit(1, Owner(dropped.clone())).unwrap();
            assert!(queue.receive().unwrap().result.is_err());
            panic!("coordinator failure");
        },
    );
    assert!(matches!(result, Err(Error::CoordinatorPanic)));
    assert_eq!(dropped.load(Ordering::SeqCst), 4);
    let result = scoped_with_spawn_limit(
        4,
        |_| Owner(dropped.clone()),
        |_, _: ()| (),
        |_| panic!("coordinator must not run"),
        Some(2),
    );
    assert!(matches!(result, Err(Error::Spawn)));
    assert_eq!(dropped.load(Ordering::SeqCst), 6);
    assert!(matches!(
        scoped_with_state(
            2,
            |_| panic!("initializer failure"),
            |_: &mut (), _: ()| (),
            |q| {
                let _ = q.submit(0, ());
                let _ = q.receive();
            }
        ),
        Err(Error::WorkerPanic)
    ));
}

#[test]
fn targeted_notifications_wake_the_selected_idle_slot() {
    let (_, stats) = scoped(
        16,
        |job| job,
        |queue| {
            for job in 0..64usize {
                let slot = (job * 7) % 16;
                queue.submit(slot, job).unwrap();
                let done = queue.receive().unwrap();
                assert_eq!(done.slot, slot);
                assert_eq!(done.result.unwrap(), job);
            }
        },
    )
    .unwrap();
    assert_eq!(stats.jobs_started, 64);
    assert_eq!(stats.threads_spawned, 16);
}

#[test]
fn nonblocking_completion_drain_releases_every_finished_slot() {
    scoped(
        3,
        |job| job,
        |queue| {
            assert!(queue.try_receive().unwrap().is_none());
            for slot in 0..3 {
                queue.submit(slot, slot).unwrap();
            }
            let (state, timeout) = queue
                .shared
                .completed
                .wait_timeout_while(
                    queue.shared.lock(),
                    std::time::Duration::from_secs(5),
                    |s| s.done[..3].iter().any(Option::is_none),
                )
                .unwrap();
            assert!(!timeout.timed_out());
            drop(state);
            for slot in 0..3 {
                let done = queue.try_receive().unwrap().expect("completed slot");
                assert_eq!(done.slot, slot);
                assert_eq!(done.result.unwrap(), slot);
            }
            assert!(queue.try_receive().unwrap().is_none());
            queue.submit(0, 7).unwrap();
            assert_eq!(queue.receive().unwrap().result.unwrap(), 7);
        },
    )
    .unwrap();
}
