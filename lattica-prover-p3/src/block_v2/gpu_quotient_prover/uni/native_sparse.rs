//! Closed metadata for recorded alpha-prime and challenge-x sparse AIRs.
//! These source AIRs have no maximum-degree hint. The exact normalized degree
//! determines the hiding quotient; this continuation preserves that behavior.
use super::*;
use crate::block_v2::{native_gpu::sparse_preparation::{SparseGeometry, SparseKind}, profile};
use p3_air::BaseAir;

const QUOTIENT_CHUNKS: usize = 16;

struct Metadata { geometry: SparseGeometry }
impl Metadata {
    fn from_geometry(geometry: SparseGeometry) -> Result<Self, String> {
        let expected = match geometry.kind() {
            SparseKind::AlphaPrime39 => (256, 506, 8, 82),
            SparseKind::ChallengeX44 => (256, 506, 8, 82),
        };
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns()) != expected
            || geometry.periodic_values() != 6720
        {
            return Err("closed sparse continuation geometry changed".into());
        }
        Ok(Self { geometry })
    }
}
impl BaseAir<Val> for Metadata {
    fn width(&self) -> usize { self.geometry.width() }
    fn num_public_values(&self) -> usize { self.geometry.public_values() }
    fn num_periodic_columns(&self) -> usize { self.geometry.periodic_columns() }
    fn max_constraint_degree(&self) -> Option<usize> { None }
    // Preserve each native AIR's default all-column next-row metadata.
}

pub(crate) fn normalize(
    config: &profile::Config, geometry: SparseGeometry, prepared: Prepared, run: &Run,
) -> Result<Normalized, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.rows != geometry.rows() {
        return Err("closed sparse recording height differs from source".into());
    }
    // The expectation is checked against the actual normalized relation; it
    // never becomes BaseAir's degree hint or replaces symbolic evaluation.
    prepared.normalize_for_profile::<profile::Challenge, Metadata>(config, &metadata, run, QUOTIENT_CHUNKS)
}

pub(crate) fn prove(
    config: &profile::Config, geometry: SparseGeometry, prepared: Normalized,
    trace: DeviceMatrix, public_values: &[Val], run: &Run,
) -> Result<Proof<profile::Config>, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.quotient_chunks() != QUOTIENT_CHUNKS {
        return Err("closed sparse normalized quotient profile changed".into());
    }
    prove_prepared(config, &metadata, trace, public_values, run, PreparationInput::Normalized(prepared))
}
