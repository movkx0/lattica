//! Destroy actual report storage before reclaiming its unchanged original.
use super::*;

// The original reservation remains after both payloads on every exit. The
// private generic form permits focused destructor tests without changing the
// production Payload/Encoding layouts or accepting a public callback.
struct Retiring<P, E> {
    payload: Option<P>,
    encoding: Option<E>,
    original: Reservation,
}

impl<P, E> Retiring<P, E> {
    fn finish(mut self) -> Reservation {
        drop(self.payload.take());
        drop(self.encoding.take());
        self.original
    }
}

impl PhaseReportOwner {
    /// Complete added call storage, charged before any report reclamation.
    /// This does not include the enclosing bank's own source/lineage/return
    /// state or a later reunite call, which the bank must charge separately.
    pub(crate) const fn reclamation_caller_host_bytes() -> usize {
        8 * (size_of::<Self>()
            + size_of::<Result<Reservation, (Error, Self)>>()
            + size_of::<(Error, Self)>()
            + size_of::<Retiring<Box<Payload>, Encoding>>()
            + size_of::<Box<Payload>>()
            + size_of::<Option<Box<Payload>>>()
            + size_of::<Encoding>()
            + size_of::<Option<Encoding>>()
            + size_of::<Vec<u8>>()
            + size_of::<Reservation>()
            + size_of::<PhaseIdentity>()
            + size_of::<Requirements>()
            + size_of::<Bytes>()
            + size_of::<Error>()
            + size_of::<Option<Error>>()
            + size_of::<&Self>()
            + size_of::<&Reservation>()
            + size_of::<&Ledger>()
            + size_of::<bool>()
            + 8 * size_of::<usize>())
    }

    /// Consume the exact original report only after every identity and caller
    /// charge check passes. Refusal returns this entire owner unchanged.
    /// Success destroys its actual Box payload and encoding Vec before moving
    /// the same original report reservation out; no quota counters change.
    /// This is neither bank lineage nor proof success or next-phase authority.
    pub(crate) fn reclaim_original(
        self,
        expected: PhaseIdentity,
        caller: &Reservation,
        ledger: &Ledger,
    ) -> Result<Reservation, (Error, Self)> {
        let error = if !self.reservation.belongs_to(ledger) || !caller.belongs_to(ledger) {
            Some(Error::WrongLedger)
        } else if self.reservation.requirements() != Self::requirements()
            || caller.requirements().get(Category::PhaseScratch).host
                < Self::reclamation_caller_host_bytes() as u64
        {
            Some(Error::WrongReservation)
        } else if self.payload.identity != expected {
            Some(Error::InvalidIdentity)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((error, self));
        }
        let Self {
            payload,
            encoding,
            reservation,
        } = self;
        Ok(Retiring {
            payload: Some(payload),
            encoding: Some(encoding),
            original: reservation,
        }
        .finish())
    }
}

#[cfg(test)]
mod tests;
