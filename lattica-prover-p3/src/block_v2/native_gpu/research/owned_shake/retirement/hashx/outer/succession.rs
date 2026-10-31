//! All remaining outer backend plans are fixed under the original native
//! attempt before native zero. Only opaque original scratch can consume them.
use super::*;

pub(super) const SUCCESSORS: usize = 8;

/// The fixed queue retains its full exact-capacity backing until destruction.
/// Its enclosing independent metadata reservation must outlive this owner.
pub struct HashxOuterSuccessors {
    backends: Vec<Option<PreissuedOuterBackend>>,
    attempt: Rc<Attempt>,
    startup: Requirements,
    pcs: Bytes,
    ledger: Ledger,
    next: usize,
}

fn expected_step(completed: usize, requested: usize) -> bool {
    completed < SUCCESSORS && completed.checked_add(1) == Some(requested)
}

impl PreissuedHashxOuterBackend {
    /// The enclosing sequence opt-in must already have preclaimed complete
    /// metadata before the original PCS assignment. It requires every queued
    /// plan before allowing native dispatch and permits no later replacement.
    pub fn preissue_successors(
        &self,
        backends: [PreissuedOuterBackend; SUCCESSORS],
        metadata: &Reservation,
        ledger: &Ledger,
    ) -> Result<HashxOuterSuccessors> {
        check_ledger(ledger)?;
        if !metadata.belongs_to(ledger)
            || !metadata.belongs_to(&self.ledger)
            || metadata.requirements().get(Category::PhaseScratch).host
                < HashxOuterSuccessors::additional_host_bytes()? as u64
        {
            return Err(Error::Authority);
        }
        for backend in &backends {
            check_footprint(
                backend.footprint(),
                self.startup.get(Category::PhaseScratch),
                self.pcs,
            )?;
            backend
                .check_execution_selection()
                .map_err(|_| Error::Planner)?;
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(SUCCESSORS)
            .map_err(|_| Error::Admission)?;
        if slots.capacity() != SUCCESSORS {
            return Err(Error::Admission);
        }
        for backend in backends {
            slots.push(Some(backend));
        }
        Ok(HashxOuterSuccessors {
            backends: slots,
            attempt: Rc::clone(&self.attempt),
            startup: self.startup,
            pcs: self.pcs,
            ledger: ledger.clone(),
            next: 0,
        })
    }
}

impl HashxOuterSuccessors {
    fn check_queue(&self) -> Result<()> {
        if self.next > SUCCESSORS
            || self.backends.len() != SUCCESSORS
            || self.backends.capacity() != SUCCESSORS
            || self.backends[..self.next].iter().any(Option::is_some)
            || self.backends[self.next..].iter().any(Option::is_none)
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// Called at native entry while the ticket keeps this complete queue and
    /// its independent reservation alive throughout all ten native attempts.
    pub fn check_before_native(
        &self,
        first: &PreissuedHashxOuterBackend,
        ledger: &Ledger,
    ) -> Result<()> {
        self.check_queue()?;
        check_ledger(ledger)?;
        if self.next != 0
            || !Rc::ptr_eq(&self.attempt, &first.attempt)
            || self.startup != first.startup
            || self.pcs != first.pcs
        {
            return Err(Error::Authority);
        }
        for backend in self.backends.iter().flatten() {
            backend
                .check_execution_selection()
                .map_err(|_| Error::Planner)?;
        }
        Ok(())
    }

    /// Numbers describe only the next fixed queue entry. This validates no
    /// successful proof or accepted leaf/parent; the enclosing B owner does.
    pub fn check_originals(
        &self,
        scratch: &HashxOuterScratch,
        preparation: &Reservation,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> Result<()> {
        self.check_queue()?;
        scratch.check_originals(preparation, verifier, ledger)?;
        if !Rc::ptr_eq(&self.attempt, &scratch.attempt)
            || self.next != scratch.outer_step
            || self.startup != scratch.startup
            || self.pcs != scratch.pcs_bytes
            || !scratch.pcs.belongs_to(&self.ledger)
            || !scratch.wrappers.belongs_to(&self.ledger)
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// Consuming terminal refusal: an entry cannot be replaced or retried.
    /// The enclosing owner separately restores its actual retired Session's
    /// sealed startup. This method neither starts nor reconstructs a runtime.
    pub fn bind_successor<'inputs>(
        mut self,
        mut scratch: HashxOuterScratch,
        expected: usize,
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
        preparation: &Reservation,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> Result<(HashxOuterBackend<'inputs>, Self)> {
        self.check_originals(&scratch, preparation, verifier, ledger)?;
        if !expected_step(self.next, expected) {
            return Err(Error::Authority);
        }
        let backend = self.backends[self.next].take().ok_or(Error::Authority)?;
        check_footprint(
            backend.footprint(),
            self.startup.get(Category::PhaseScratch),
            self.pcs,
        )?;
        let backend = backend
            .bind(program, public, witness)
            .map_err(|_| Error::Planner)?;
        self.next = expected;
        scratch.outer_step = expected;
        self.check_originals(&scratch, preparation, verifier, ledger)?;
        Ok((HashxOuterBackend { backend, scratch }, self))
    }

    pub fn additional_host_bytes() -> Result<usize> {
        let parts = [
            // Full exact vector backing plus input/moved array/iterator copies.
            SUCCESSORS * size_of::<Option<PreissuedOuterBackend>>(),
            8 * size_of::<[PreissuedOuterBackend; SUCCESSORS]>(),
            8 * size_of::<core::array::IntoIter<PreissuedOuterBackend, SUCCESSORS>>(),
            8 * size_of::<Self>(),
            8 * size_of::<Result<Self>>(),
            8 * size_of::<HashxOuterScratch>(),
            8 * size_of::<HashxOuterBackend<'static>>(),
            8 * size_of::<(HashxOuterBackend<'static>, Self)>(),
            8 * size_of::<Result<(HashxOuterBackend<'static>, Self)>>(),
            8 * size_of::<PreissuedOuterBackend>(),
            8 * size_of::<Option<PreissuedOuterBackend>>(),
            8 * size_of::<OuterBackendAdmission<'static>>(),
            8 * size_of::<core::result::Result<OuterBackendAdmission<'static>, String>>(),
            8 * size_of::<Vec<Option<PreissuedOuterBackend>>>(),
            8 * size_of::<core::result::Result<(), std::collections::TryReserveError>>(),
            8 * size_of::<core::result::Result<(), String>>(),
            8 * size_of::<Result<()>>(),
            8 * size_of::<Result<usize>>(),
            8 * size_of::<Requirements>(),
            8 * size_of::<OuterSourceFootprint>(),
            8 * size_of::<Bytes>(),
            8 * size_of::<Ledger>(),
            8 * size_of::<Rc<Attempt>>(),
            8 * size_of::<usize>(),
            // Independent Rc allocation/control block lifetime and bounded
            // source-selector/iterator/error/scalar frames. B source/planning
            // helper claims are additionally retained, never replaced here.
            8 * size_of::<usize>(),
            32 << 10,
        ];
        parts
            .into_iter()
            .try_fold(core::mem::size_of_val(&parts) * 8, |sum, bytes| {
                sum.checked_add(bytes).ok_or(Error::Admission)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successors_require_exact_next_step_and_stop_after_nine_outer_phases() {
        assert!(expected_step(0, 1));
        assert!(expected_step(7, 8));
        for (completed, requested) in [(0, 0), (0, 2), (4, 3), (4, 4), (4, 6), (8, 8), (8, 9)] {
            assert!(!expected_step(completed, requested));
        }
        assert!(!expected_step(usize::MAX, 0));
        assert!(!expected_step(0, usize::MAX));
        assert!(
            HashxOuterSuccessors::additional_host_bytes().unwrap()
                > SUCCESSORS * size_of::<Option<PreissuedOuterBackend>>()
        );
    }
}
