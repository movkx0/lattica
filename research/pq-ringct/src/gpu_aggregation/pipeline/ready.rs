//! A bounded dependency queue. CPU scopes borrow source data; GPU work remains
//! on the caller thread. The same pool and its numeric caches span all trees.
use super::*;
use std::{collections::BTreeSet, sync::Arc, time::Instant};

pub(crate) fn tree<T: Send, N: Send + Sync>(
    pool: &rayon::ThreadPool,
    leaves: usize,
    prepare_leaf: impl Fn(usize) -> Result<T> + Sync,
    prepare_parent: impl Fn(&N, &N) -> Result<T> + Sync,
    mut consume: impl FnMut(T) -> Result<N>,
) -> Result<N> {
    if leaves == 0 || leaves > 4096 {
        return Err("ready tree leaf capacity".into());
    }
    let mut children = vec![None; leaves];
    let mut parents = vec![None; leaves];
    let mut level: Vec<usize> = (0..leaves).collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
                continue;
            }
            let id = children.len();
            children.push(Some((pair[0], pair[1])));
            parents.push(None);
            parents[pair[0]] = Some(id);
            parents[pair[1]] = Some(id);
            next.push(id);
        }
        level = next;
    }
    let root = level[0];
    let canceled = AtomicBool::new(false);
    struct Cancel<'a>(&'a AtomicBool);
    impl Drop for Cancel<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    pool.in_place_scope(|scope| {
        let _cancel = Cancel(&canceled);
        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        let mut ready: BTreeSet<(bool, usize)> = (0..leaves).map(|id| (true, id)).collect();
        let mut outputs: Vec<Option<Arc<N>>> = (0..children.len()).map(|_| None).collect();
        let (mut active, mut completed, mut peak) = (0usize, 0usize, 0usize);
        let (mut preparation_ns, mut idle_ns) = (0u128, 0u128);
        while completed < children.len() {
            while active < 4 {
                let Some((_, id)) = ready.pop_first() else { break; };
                let inputs = if let Some((left, right)) = children[id] {
                    Some((outputs[left].take().ok_or("missing left dependency")?,
                          outputs[right].take().ok_or("missing right dependency")?))
                } else { None };
                let sender = sender.clone();
                let (prepare_leaf, prepare_parent, canceled) = (&prepare_leaf, &prepare_parent, &canceled);
                scope.spawn(move |_| {
                    let started = Instant::now();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if canceled.load(Ordering::Acquire) { return Err("ready tree canceled".into()); }
                        match inputs {
                            Some((left, right)) => prepare_parent(&left, &right),
                            None => prepare_leaf(id),
                        }
                    })).unwrap_or_else(|_| Err("ready preparation worker panicked".into()));
                    let _ = sender.send((id, result, started.elapsed().as_nanos()));
                });
                active += 1; peak = peak.max(active);
            }
            if active == 0 { return Err("ready tree dependency deadlock".into()); }
            let wait = Instant::now();
            let (id, prepared, elapsed) = receiver.recv().map_err(|_| "ready preparation channel closed")?;
            idle_ns += wait.elapsed().as_nanos(); preparation_ns += elapsed;
            // The permit includes the completed program and the GPU callback.
            let node = consume(prepared?)?;
            outputs[id] = Some(Arc::new(node));
            active -= 1; completed += 1;
            if let Some(parent) = parents[id] {
                let (left, right) = children[parent].ok_or("missing parent geometry")?;
                if outputs[left].is_some() && outputs[right].is_some() { ready.insert((false, parent)); }
            }
        }
        eprintln!("gpu_aggregation_ready_tree leaves={leaves} nodes={completed} peak_live_jobs={peak} preparation_ns={preparation_ns} gpu_wait_ns={idle_ns} persistent_cpu_workers=2");
        Arc::try_unwrap(outputs[root].take().ok_or("missing tree root")?)
            .map_err(|_| "tree root has an unexpected retained owner".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn odd_trees_preserve_all_leaves_and_start_parents_before_last_leaf() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        for count in [1, 2, 3, 7, 16, 31] {
            let live = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            let started_leaves = AtomicUsize::new(0);
            let first_parent = AtomicUsize::new(usize::MAX);
            let enter = || {
                peak.fetch_max(live.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            };
            let root = tree(
                &pool,
                count,
                |i| {
                    enter();
                    started_leaves.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![i])
                },
                |a: &Vec<usize>, b: &Vec<usize>| {
                    enter();
                    let _ = first_parent.compare_exchange(
                        usize::MAX,
                        started_leaves.load(Ordering::SeqCst),
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                    assert_eq!(a.last().unwrap() + 1, b[0]);
                    Ok(a.iter().chain(b).copied().collect::<Vec<_>>())
                },
                |value| {
                    live.fetch_sub(1, Ordering::SeqCst);
                    Ok(value)
                },
            )
            .unwrap();
            assert_eq!(root, (0..count).collect::<Vec<_>>());
            assert_eq!(live.load(Ordering::SeqCst), 0);
            assert!(peak.load(Ordering::SeqCst) <= 4);
            if count >= 16 {
                assert!(first_parent.load(Ordering::SeqCst) < count);
            }
        }
    }
    #[test]
    fn failed_or_panicking_preparation_and_failed_consumer_retire_the_scope() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        for panic in [false, true] {
            assert!(tree(
                &pool,
                12,
                |i| {
                    if i == 1 {
                        if panic {
                            panic!("injected");
                        }
                        return Err("injected".into());
                    }
                    Ok(i)
                },
                |a, b| Ok(a + b),
                Ok
            )
            .is_err());
        }
        assert!(tree(
            &pool,
            12,
            Ok,
            |a, b| Ok(a + b),
            |_| Err::<usize, _>("GPU failure".into())
        )
        .is_err());
        assert_eq!(tree(&pool, 2, Ok, |a, b| Ok(a + b), Ok).unwrap(), 1);
    }
}
