//! The only research recording entry evaluates the actual retained request AIR.
//! No callback or generic AIR crosses the core boundary, and the exclusive
//! original preparation claim remains borrowed through its recorded result.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::PeriodicSource;
use p3_air::Air;

impl PendingNativePreparation<'_> {
    pub(crate) fn record<'claim>(
        &'claim mut self,
        ledger: &'claim Ledger,
    ) -> Result<shake_recording::PreparedShake<'claim>> {
        if !self.is_for(self.plan.owner, self.plan.index, ledger) {
            return Err(Error::WrongReservation);
        }
        let air = self.plan.air;
        let census = self.plan.census;
        let columns = census.geometry().periodic_columns();
        if air.column_count() != columns
            || (0..columns)
                .any(|index| air.column_len(index) != Some(census.geometry().periodic_length()))
            || air.max_constraint_degree() != Some(7)
        {
            return Err(Error::Shape);
        }
        let mut recorder =
            shake_recording::ShakeRecorder::begin(census, &mut self.reservation, ledger)
                .map_err(|_| Error::Recording)?;
        // These are concrete closed enum arms. The core receives an existing
        // Builder borrow; it never accepts a user-supplied AIR or callback.
        match air {
            ShakeSegmentAir::Single(source) => source.eval(recorder.builder_mut()),
            ShakeSegmentAir::Batch(source) => source.eval(recorder.builder_mut()),
        }
        for index in 0..columns {
            let output = recorder
                .periodic_column_mut(index)
                .map_err(|_| Error::Recording)?;
            match air {
                ShakeSegmentAir::Single(source) => source.fill_column(index, output),
                ShakeSegmentAir::Batch(source) => source.fill_column(index, output),
            }
            // Any dynamic source error is destroyed while the same original
            // preparation token and recorder remain live.
            .map_err(|_| Error::Recording)?;
        }
        let recorded = recorder.finish().map_err(|_| Error::Recording)?;
        if air
            .num_constraints()
            .is_some_and(|count| count != recorded.constraints())
        {
            return Err(Error::Shape);
        }
        Ok(recorded)
    }
}

#[cfg(test)]
mod tests;
