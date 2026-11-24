//! CPU-only preparation across requests. Permits cover running and ready jobs;
//! the single GPU consumer can retire a permit as soon as its source is gone.
use super::Result;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};

/// Visit one parent position in every tree before advancing to the next.
/// Moving each input once preserves child order and leaves odd tails intact.
pub(crate) fn parent_groups<T>(
    nodes: Vec<Vec<T>>,
    fan_in: usize,
) -> impl Iterator<Item = (usize, Vec<T>)> {
    assert!(fan_in >= 2);
    let mut remaining = nodes.into_iter().map(Vec::into_iter).collect::<Vec<_>>();
    let mut group = 0;
    std::iter::from_fn(move || {
        for _ in 0..remaining.len() {
            let index = group;
            group = (group + 1) % remaining.len();
            let children = remaining[index].by_ref().take(fan_in).collect::<Vec<_>>();
            if !children.is_empty() {
                return Some((index, children));
            }
        }
        None
    })
}

#[derive(Default, Debug, serde::Serialize)]
pub(crate) struct Stats {
    pub workers: usize,
    pub peak_jobs: usize,
    pub peak_bytes: usize,
}
struct State {
    next: usize,
    bytes: usize,
    jobs: usize,
    canceled: bool,
    stats: Stats,
}
struct Window {
    weights: Vec<usize>,
    capacity: usize,
    state: Mutex<State>,
    ready: Condvar,
}
pub(crate) struct Permit {
    window: Arc<Window>,
    bytes: usize,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut s = self.window.state.lock().unwrap();
        s.bytes -= self.bytes;
        s.jobs -= 1;
        self.window.ready.notify_all();
    }
}
impl Window {
    fn take(self: &Arc<Self>) -> Option<(usize, Permit)> {
        let mut s = self.state.lock().unwrap();
        loop {
            if s.canceled || s.next == self.weights.len() {
                return None;
            }
            let bytes = self.weights[s.next];
            if bytes <= self.capacity - s.bytes {
                let index = s.next;
                s.next += 1;
                s.bytes += bytes;
                s.jobs += 1;
                s.stats.peak_bytes = s.stats.peak_bytes.max(s.bytes);
                s.stats.peak_jobs = s.stats.peak_jobs.max(s.jobs);
                return Some((
                    index,
                    Permit {
                        window: Arc::clone(self),
                        bytes,
                    },
                ));
            }
            s = self.ready.wait(s).unwrap();
        }
    }
    fn cancel(&self) {
        self.state.lock().unwrap().canceled = true;
        self.ready.notify_all();
    }
}
struct Cancel(Arc<Window>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) fn run<T: Send>(
    weights: &[usize],
    capacity: usize,
    workers: usize,
    prepare: impl Fn(usize) -> Result<T> + Sync,
    mut consume: impl FnMut(usize, T, Permit) -> Result<()>,
) -> Result<Stats> {
    if !(1..=16).contains(&workers)
        || weights.len() > 65536
        || weights.iter().any(|&w| w == 0 || w > capacity)
    {
        return Err("invalid weighted preparation admission".into());
    }
    let workers = workers.min(weights.len());
    let window = Arc::new(Window {
        weights: weights.to_vec(),
        capacity,
        ready: Condvar::new(),
        state: Mutex::new(State {
            next: 0,
            bytes: 0,
            jobs: 0,
            canceled: false,
            stats: Stats {
                workers,
                ..Stats::default()
            },
        }),
    });
    std::thread::scope(|scope| -> Result<()> {
        let _cancel = Cancel(Arc::clone(&window));
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        for worker in 0..workers {
            let sender = sender.clone();
            let window = Arc::clone(&window);
            let prepare = &prepare;
            handles.push(std::thread::Builder::new().name(format!("typed-prepare-{worker}"))
                .spawn_scoped(scope, move || {
                    let source = crate::graph_proofs::compiled_source_fingerprint();
                    let _geometry = lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheScope::begin_with_precomputed(source);
                    let _native = crate::component_tree::native_shape::cache::Scope::begin_with_precomputed(source);
                    while let Some((index, permit)) = window.take() {
                        let value = if _geometry.is_err() || _native.is_err() {
                            Err("typed worker metadata initialization".into())
                        } else {
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(index)))
                                .unwrap_or_else(|_| Err("typed preparation worker panicked".into()))
                        };
                        if sender.send((index, value, permit)).is_err() { break; }
                    }
                }).map_err(|e| e.to_string())?);
        }
        drop(sender);
        let result = (|| {
            let mut pending = BTreeMap::new();
            let mut expected = 0;
            while expected < weights.len() {
                let (index, value, permit) = receiver
                    .recv()
                    .map_err(|_| "typed preparation channel closed")?;
                let value = value?;
                if index < expected || pending.insert(index, (value, permit)).is_some() {
                    return Err("duplicate typed preparation output".into());
                }
                while let Some((value, permit)) = pending.remove(&expected) {
                    consume(expected, value, permit)?;
                    expected += 1;
                }
            }
            Ok(())
        })();
        window.cancel();
        drop(receiver);
        for handle in handles {
            handle.join().map_err(|_| "typed worker join failure")?;
        }
        result
    })?;
    let mut state = window.state.lock().unwrap();
    if state.bytes != 0 || state.jobs != 0 {
        return Err("typed preparation permit leaked".into());
    }
    Ok(std::mem::take(&mut state.stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn early_release_overlaps_next_preparation_and_preserves_order() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut seen = Vec::new();
        let stats = run(
            &[8, 2, 3, 1],
            8,
            16,
            |i| {
                if i == 1 {
                    tx.send(()).unwrap();
                }
                Ok(i)
            },
            |i, value, permit| {
                assert_eq!(i, value);
                drop(permit);
                if i == 0 {
                    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
                }
                seen.push(i);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, [0, 1, 2, 3]);
        assert!(stats.peak_bytes <= 8);
        assert_eq!(stats.workers, 4);
    }
    #[test]
    fn failures_panics_and_oversized_jobs_cancel_and_join() {
        assert!(run(&[9], 8, 2, |_| Ok(()), |_, _, _| Ok(())).is_err());
        for failure in 0..3 {
            let result = run(
                &[8; 20],
                8,
                16,
                |i| {
                    if i == 2 && failure == 0 {
                        return Err("prepare failed".into());
                    }
                    if i == 2 && failure == 1 {
                        panic!("injected preparation panic");
                    }
                    Ok(())
                },
                |i, _, _| {
                    if i == 2 && failure == 2 {
                        Err("consumer failed".into())
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
        }
    }
}
