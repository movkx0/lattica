//! CPU-only preparation, one ordered GPU consumer, at most four live jobs.
//! A permit covers compilation, queued output and consuming GPU work together.
use super::Result;
mod ready;

pub(crate) fn tree_programs<T: Send, N: Send + Sync>(
    leaves: usize,
    execution: &crate::execution::ProvingContext,
    prepare_leaf: impl Fn(usize) -> Result<T> + Sync,
    prepare_parent: impl Fn(&N, &N) -> Result<T> + Sync,
    program: impl Fn(&T) -> std::sync::Arc<lattica_prover_p3::block_v2::machine::program::Program>
        + Sync,
    mut consume: impl FnMut(T) -> Result<N>,
) -> Result<N> {
    let pool = execution
        .aggregation_pool()
        .ok_or("persistent aggregation pool required")?;
    let authority = execution.aggregation_cpu_authority();
    let prepare = |value: T| {
        let program = program(&value);
        let prefix = authority.prepare_cpu_only(&program, 512 << 20)?;
        Ok((value, program, prefix))
    };
    ready::tree(
        &pool,
        leaves,
        |i| prepare(prepare_leaf(i)?),
        |left, right| prepare(prepare_parent(left, right)?),
        |(value, program, (prefix, report))| {
            execution.install_aggregation_cpu_prefixes(vec![(program, prefix, report)])?;
            consume(value)
        },
    )
}
/// CPU identity hashing shares the same compiler permit and never acquires a
/// GPU session. Only this ordered consumer installs prefixes or dispatches GPU.
pub(crate) fn programs<T: Send>(
    count: usize,
    parallel: bool,
    gpu_identity: bool,
    execution: &crate::execution::ProvingContext,
    prepare: impl Fn(usize) -> Result<T> + Sync,
    program: impl Fn(&T) -> std::sync::Arc<lattica_prover_p3::block_v2::machine::program::Program>
        + Sync,
    mut consume: impl FnMut(Vec<(usize, T)>) -> Result<()>,
) -> Result<()> {
    let authority = (parallel && !gpu_identity).then(|| execution.aggregation_cpu_authority());
    ordered_batches(
        count,
        parallel,
        if gpu_identity { 4 } else { 1 },
        |index| {
            let value = prepare(index)?;
            let program = program(&value);
            let prefix = authority
                .as_ref()
                .map(|a| a.prepare_cpu_only(&program, 512 << 20))
                .transpose()?;
            Ok((value, program, prefix))
        },
        |cohort| {
            if gpu_identity {
                execution.prepare_aggregation_identities(
                    &cohort
                        .iter()
                        .map(|(_, (_, p, _))| std::sync::Arc::clone(p))
                        .collect::<Vec<_>>(),
                )?;
            }
            let mut values = Vec::new();
            let mut prefixes = Vec::new();
            for (index, (value, program, prefix)) in cohort {
                if let Some((prefix, report)) = prefix {
                    prefixes.push((program, prefix, report));
                }
                values.push((index, value));
            }
            if !prefixes.is_empty() {
                execution.install_aggregation_cpu_prefixes(prefixes)?;
            }
            consume(values)
        },
    )
}
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Condvar, Mutex,
    },
};
struct Window {
    available: Mutex<usize>,
    ready: Condvar,
    canceled: AtomicBool,
}
struct Permit<'a>(&'a Window);
struct Cancel<'a>(&'a Window);
impl Drop for Cancel<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.available.lock().unwrap() += 1;
        self.0.ready.notify_all();
    }
}
impl Window {
    fn acquire(&self) -> Option<Permit<'_>> {
        let mut available = self.available.lock().unwrap();
        while *available == 0 && !self.canceled.load(Ordering::Acquire) {
            available = self.ready.wait(available).unwrap();
        }
        if self.canceled.load(Ordering::Acquire) {
            return None;
        }
        *available -= 1;
        Some(Permit(self))
    }
    fn cancel(&self) {
        let _available = self.available.lock().unwrap();
        self.canceled.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}
pub(crate) fn ordered<T: Send>(
    count: usize,
    parallel: bool,
    prepare: impl Fn(usize) -> Result<T> + Sync,
    mut consume: impl FnMut(usize, T) -> Result<()>,
) -> Result<()> {
    ordered_batches(count, parallel, 1, prepare, |values| {
        for (index, value) in values {
            consume(index, value)?;
        }
        Ok(())
    })
}
pub(crate) fn ordered_batches<T: Send>(
    count: usize,
    parallel: bool,
    width: usize,
    prepare: impl Fn(usize) -> Result<T> + Sync,
    mut consume: impl FnMut(Vec<(usize, T)>) -> Result<()>,
) -> Result<()> {
    if !(1..=4).contains(&width) {
        return Err("preparation cohort exceeds ready window".into());
    }
    if !parallel {
        for first in (0..count).step_by(width) {
            let mut cohort = Vec::new();
            for index in first..count.min(first + width) {
                cohort.push((index, prepare(index)?));
            }
            consume(cohort)?;
        }
        return Ok(());
    }
    let window = Window {
        available: Mutex::new(4),
        ready: Condvar::new(),
        canceled: AtomicBool::new(false),
    };
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        let _cancel = Cancel(&window);
        let mut workers = Vec::new();
        for _ in 0..2 {
            let sender = sender.clone();
            let prepare = &prepare;
            let next = &next;
            let window = &window;
            workers.push(scope.spawn(move || {
                // These caches contain numeric facts only. Workers own their
                // scopes; no GPU session or coordinator cache crosses threads.
                let source=crate::graph_proofs::compiled_source_fingerprint();
                let _geometry=lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheScope::begin_with_precomputed(source)
                    .expect("fresh preparation worker geometry cache");
                let _native=crate::component_tree::native_shape::cache::Scope::begin_with_precomputed(source)
                    .expect("fresh preparation worker native cache");
                while let Some(permit) = window.acquire() {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(index)))
                            .unwrap_or_else(|_| {
                                Err("aggregation preparation worker panicked".into())
                            });
                    if sender.send((index, result, permit)).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(sender);
        let result = (|| {
            let mut pending = BTreeMap::new();
            let mut expected = 0;
            let mut cohort = Vec::new();
            let mut permits = Vec::new();
            while expected < count {
                let (index, value, permit) = receiver
                    .recv()
                    .map_err(|_| "aggregation preparation channel closed")?;
                if index < expected || pending.insert(index, (value, permit)).is_some() {
                    return Err("duplicate preparation output".into());
                }
                while let Some((value, permit)) = pending.remove(&expected) {
                    cohort.push((expected, value?));
                    permits.push(permit);
                    expected += 1;
                    if cohort.len() == width || expected == count {
                        consume(std::mem::take(&mut cohort))?;
                        permits.clear();
                    }
                }
            }
            Ok(())
        })();
        window.cancel();
        drop(receiver);
        for worker in workers {
            worker
                .join()
                .map_err(|_| "aggregation preparation worker join failed")?;
        }
        result
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_consumption_and_bounded_live_jobs() {
        let live = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let mut seen = Vec::new();
        ordered(
            80,
            true,
            |i| {
                let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                Ok(i)
            },
            |i, value| {
                assert_eq!(i, value);
                seen.push(i);
                live.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, (0..80).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) <= 4);
    }
    #[test]
    fn failures_and_panics_join_workers_without_waiting_for_consumption() {
        for failure in [0, 1, 7] {
            assert!(ordered(
                100,
                true,
                |i| if i == failure {
                    Err("prepare failed".into())
                } else {
                    Ok(i)
                },
                |_, _| Ok(())
            )
            .is_err());
            assert!(ordered(100, true, Ok, |i, _| if i == failure {
                Err("consume failed".into())
            } else {
                Ok(())
            })
            .is_err());
        }
        assert!(ordered(
            100,
            true,
            |i| {
                assert_ne!(i, 2);
                Ok(i)
            },
            |_, _| Ok(())
        )
        .is_err());
        assert!(
            std::panic::catch_unwind(|| ordered(100, true, Ok, |_, _| panic!(
                "GPU consumer panic"
            )))
            .is_err()
        );
    }
    #[test]
    fn identity_cohorts_preserve_order_and_release_all_permits_on_error() {
        for count in 0..21 {
            let mut seen = Vec::new();
            ordered_batches(count, true, 4, Ok, |cohort| {
                assert!(cohort.len() <= 4);
                seen.extend(cohort.into_iter().map(|(i, value)| {
                    assert_eq!(i, value);
                    i
                }));
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, (0..count).collect::<Vec<_>>());
        }
        assert!(ordered_batches(
            20,
            true,
            4,
            |i| if i == 3 {
                Err("failed final cohort member".into())
            } else {
                Ok(i)
            },
            |_| Ok(())
        )
        .is_err());
        assert!(ordered_batches(20, true, 8, Ok, |_| Ok(())).is_err());
    }
}
