//! Prepare immutable metadata before any wallet arithmetic. The bounded raw
//! graph survives until GPU normalization; no device program or trace is made.
use super::*;
use crate::block_v2::gpu_hash::device::WalletProofMinimum;
use crate::block_v2::gpu_quotient_prover::program::ProgramShape;
use crate::block_v2::machine::verifier::periodic::Source as StaticPeriodicSource;
mod periodic;

pub(crate) struct Prepared {
    pub(super) recorded: symbolic::RecordedUni,
    pub(super) shape: ProgramShape,
    pub(super) rows: usize,
    host_allowance: usize,
    pub(super) periodic: Option<periodic::Source>,
}

impl Prepared {
    pub(crate) fn new<A: Air<symbolic::Builder> + StaticPeriodicSource>(
        air: &A,
        rows: usize,
        extension: Extension,
        host_allowance: usize,
    ) -> Result<Self, String> {
        Self::new_with_source(air, air, rows, extension, host_allowance)
    }

    /// An independently supplied public source keeps native research AIRs out
    /// of the core crate without invoking their owned periodic table builders.
    pub(crate) fn new_with_source<A: Air<symbolic::Builder>, S: StaticPeriodicSource + ?Sized>(
        air: &A,
        source: &S,
        rows: usize,
        extension: Extension,
        host_allowance: usize,
    ) -> Result<Self, String> {
        // The recording remains live while periodic tables are constructed.
        // Those tables then survive normalization and program lowering. Keep
        // the complete symbolic/compiler envelope reserved across these phases
        // instead of admitting each owner against the full request allowance.
        let periodic_allowance = host_allowance
            .checked_sub(symbolic::HOST_BYTES as usize)
            .ok_or("wallet symbolic recording exceeds host allowance")?;
        // Validate simple geometry before recording even a trusted AIR.
        WalletProofMinimum::new(rows, air.width(), air.num_periodic_columns(), extension)?;
        let recorded = symbolic::RecordedUni::new(air)
            .map_err(|e| format!("wallet symbolic recording: {e:?}"))?;
        let shape = ProgramShape::for_recording(&recorded, extension)?;
        let periodic = periodic::Source::new_with_source(air, source, rows, periodic_allowance)?;
        let prepared = Self {
            recorded,
            shape,
            rows,
            host_allowance,
            periodic,
        };
        prepared.check_host_allowance(host_allowance)?;
        eprintln!(
            "bounded_wallet_preparation_host_admission symbolic_workspace_bytes={} periodic_staging_bytes={} aggregate_bytes={} allowance_bytes={} whole_proof=false",
            symbolic::HOST_BYTES,
            prepared.periodic_host_bytes(),
            prepared.required_host_bytes()?,
            host_allowance,
        );
        Ok(prepared)
    }

    pub(super) fn periodic_host_bytes(&self) -> usize {
        self.periodic.as_ref().map_or(0, |p| p.host_bytes())
    }

    fn required_host_bytes(&self) -> Result<usize, String> {
        self.periodic_host_bytes()
            .checked_add(symbolic::HOST_BYTES as usize)
            .ok_or_else(|| "wallet preparation host storage overflow".into())
    }

    /// Recheck a prepared value against the actual proving configuration before
    /// starting normalization, transcript or randomness arithmetic.
    pub(super) fn check_host_allowance(&self, allowance: usize) -> Result<(), String> {
        if self.required_host_bytes()? > allowance {
            return Err("wallet preparation aggregate exceeds host allowance".into());
        }
        Ok(())
    }

    /// Keep the entire preparation envelope charged while later operations
    /// execute. It includes the compiled program that outlives normalization.
    /// Retaining this conservative partition avoids releasing bytes while any
    /// preparation owner is still live; it is not whole-proof host accounting.
    pub(crate) fn operation_host_allowance(&self) -> Result<usize, String> {
        self.host_allowance
            .checked_sub(self.required_host_bytes()?)
            .filter(|&remaining| remaining != 0)
            .ok_or_else(|| "wallet preparation leaves no operation host allowance".into())
    }

    pub(super) fn check_operation_host_allowance(&self, configured: usize) -> Result<(), String> {
        if configured != self.operation_host_allowance()? {
            return Err("wallet operation host allowance differs from prepared budget".into());
        }
        Ok(())
    }

    /// Use the same immutable budget for witness work, public readback and PCS
    /// operations. No caller can accidentally reinstate the full process cap.
    pub(crate) fn config<E: PcsField>(&self) -> Result<ProvingConfig<E>, String> {
        if self.shape.extension != E::DEVICE_EXTENSION {
            return Err("wallet configuration field differs from prepared program".into());
        }
        let assigned = self.operation_host_allowance()?;
        let config = crate::block_v2::profile::make_gpu_proving_config::<E>(assigned)
            .map_err(|e| e.to_string())?;
        let configured = config.pcs().host_output_budget();
        self.check_operation_host_allowance(configured)?;
        eprintln!(
            "bounded_wallet_operation_host_admission preparation_bytes={} operation_bytes={} request_bytes={} whole_proof=false",
            self.required_host_bytes()?, configured, self.host_allowance,
        );
        Ok(config)
    }

    pub(crate) fn minimum(&self) -> Result<WalletProofMinimum, String> {
        let layout = self.recorded.layout();
        WalletProofMinimum::new(
            self.rows,
            layout.main_width,
            layout.num_periodic_columns,
            self.shape.extension,
        )?
        .with_program(self.shape, self.operation_host_allowance()?)?
        .with_periodic(self.periodic.as_ref().map(|p| p.shape()))
    }
}

#[cfg(test)]
mod tests;
