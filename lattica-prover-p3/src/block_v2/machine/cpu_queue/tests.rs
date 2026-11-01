use super::*;
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
