//! Planning-session hints and explicitly reserved, cleared compiler buffers.
use super::*;
use crate::execution::retained_resources::{Ledger, Reservation};
use lattica_prover_p3::block_v2::machine::program::CountingBacking;

pub(super) struct Buffer {
    pub backing: CountingBacking,
    pub geometry: Option<NativeGeometry>,
}
pub(super) type Buffers = [Option<Buffer>; cpu_queue::MAX_WORKERS];
pub(super) fn empty() -> Buffers {
    core::array::from_fn(|_| None)
}
pub(super) fn bytes(buffers: &Buffers) -> Result<usize, CompileError> {
    buffers.iter().flatten().try_fold(0, |sum, b| {
        add(
            sum,
            b.backing
                .retained_bytes()
                .map_err(|_| CompileError::Shape("native saved backing"))?,
        )
    })
}
pub(super) fn trim(buffers: &mut Buffers, limit: usize) -> Result<usize, CompileError> {
    let mut held = bytes(buffers)?;
    while held > limit {
        let slot = buffers
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.as_ref().map(|b| (i, b.backing.retained_bytes().unwrap())))
            .max_by_key(|(_, n)| *n)
            .unwrap();
        drop(buffers[slot.0].take()); // destruction precedes returning credits
        held -= slot.1;
    }
    Ok(held)
}

#[derive(Clone, Copy)]
struct Cost {
    geometry: NativeGeometry,
    ns: u128,
    peak: usize,
    used: u64,
}
pub(super) struct Hints {
    costs: [Option<Cost>; MAX],
    clock: u64,
}
impl Default for Hints {
    fn default() -> Self {
        Self {
            costs: [None; MAX],
            clock: 0,
        }
    }
}
impl Hints {
    fn related(&self, g: NativeGeometry) -> Option<&Cost> {
        self.costs
            .iter()
            .flatten()
            .find(|c| c.geometry == g)
            .or_else(|| {
                // A fixed native AIR width supplies comparable operation families.
                // Scale a nearby measured shape by its public work estimate. This
                // predicts time only; capacity hints still require exact geometry.
                self.costs
                    .iter()
                    .flatten()
                    .filter(|c| c.geometry.width == g.width)
                    .min_by_key(|c| geometry_work(c.geometry).abs_diff(geometry_work(g)))
            })
    }
    pub fn contains(&self, g: NativeGeometry) -> bool {
        self.related(g).is_some()
    }
    pub fn estimate(&self, storage: NativePlanningStorage) -> u128 {
        if let Some(c) = self.related(storage.geometry) {
            return work(storage).saturating_mul(c.ns) / geometry_work(c.geometry);
        }
        let (ns, units) = self
            .costs
            .iter()
            .flatten()
            .fold((0u128, 0u128), |(n, w), c| {
                (
                    n.saturating_add(c.ns),
                    w.saturating_add(geometry_work(c.geometry)),
                )
            });
        work(storage).saturating_mul(ns.max(1)) / units.max(1)
    }
    pub fn order(&self, indices: &mut [usize], storage: &[Option<NativePlanningStorage>; MAX]) {
        // Compute each key once. Sorting must not repeatedly search the cost
        // history or recompute its calibration, and must not allocate a cache.
        let mut costs = [0; MAX];
        for &i in indices.iter() {
            costs[i] = self.estimate(storage[i].unwrap());
        }
        indices.sort_unstable_by_key(|&i| (core::cmp::Reverse(costs[i]), i));
    }
    pub fn cap(&self, storage: NativePlanningStorage, limits: ConstructionLimits) -> usize {
        let learned = self
            .costs
            .iter()
            .flatten()
            .find(|c| c.geometry == storage.geometry)
            .map_or(0, |c| c.peak.saturating_add(c.peak / 8));
        initial_cap(storage, limits)
            .max(learned)
            .min(limits.max_requested_program_bytes)
    }
    pub fn observe(&mut self, storage: NativePlanningStorage, ns: u128, peak: usize) {
        if ns == 0 {
            return;
        }
        self.clock = self.clock.saturating_add(1);
        let i = self
            .costs
            .iter()
            .position(|c| c.is_some_and(|c| c.geometry == storage.geometry))
            .or_else(|| self.costs.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                self.costs
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, c)| c.unwrap().used)
                    .unwrap()
                    .0
            });
        let prior = self.costs[i].filter(|c| c.geometry == storage.geometry);
        self.costs[i] = Some(Cost {
            geometry: storage.geometry,
            ns: prior.map_or(ns, |c| c.ns / 2 + ns / 2),
            peak: prior.map_or(peak, |c| c.peak.max(peak)),
            used: self.clock,
        });
    }
}

/// One authenticated planning session. Only supplemental ledger claims can
/// outlive a window; the borrowed original scratch is never cached or split.
/// Field order drops buffers before releasing their claim, including unwind.
pub(crate) struct Session {
    pub(super) buffers: Buffers,
    pub(super) claim: Option<Reservation>,
    pub(super) hints: Hints,
}
impl Default for Session {
    fn default() -> Self {
        Self {
            buffers: empty(),
            claim: None,
            hints: Hints::default(),
        }
    }
}
impl Session {
    pub fn resolve(
        &mut self,
        requests: &[Request<'_>],
        limits: ConstructionLimits,
        original: &Reservation,
        ledger: &Ledger,
    ) -> Result<[Option<ResolvedBound>; MAX], CompileError> {
        super::resolve(
            requests,
            limits,
            Some(phase::Backing { original, ledger }),
            self,
        )
    }
    pub(super) fn clear(&mut self) {
        self.buffers = empty();
        self.claim = None;
    }
    pub(super) fn admit<'a>(
        &mut self,
        backing: &'a phase::Backing<'a>,
        original: usize,
        ready: usize,
        workers: usize,
    ) -> Result<phase::Permit<'a>, CompileError> {
        if workers <= 8
            || ready <= 8
            || self.claim.as_ref().is_some_and(|c| {
                !c.belongs_to(backing.ledger)
                    || c.requirements()
                        .get(crate::execution::retained_resources::Category::PhaseScratch)
                        .host as usize
                        > (3usize << 30).saturating_sub(original)
            })
        {
            self.clear();
        }
        match backing.admit_reusing(original, ready, workers, self.claim.take()) {
            Ok(permit) => Ok(permit),
            Err(error) => {
                self.clear();
                Err(error)
            }
        }
    }
}
