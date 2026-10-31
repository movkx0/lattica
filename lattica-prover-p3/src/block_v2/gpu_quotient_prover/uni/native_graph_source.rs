//! Closed metadata for recorded Statement and PrivateProof source AIRs.
//! These source AIRs have no maximum-degree hint. The exact normalized degree
//! determines the hiding quotient; this continuation preserves that behavior.
use super::*;
use crate::block_v2::{native_gpu::graph_source_preparation::{GraphSourceGeometry, GraphSourceKind}, profile};
use p3_air::BaseAir;

const QUOTIENT_CHUNKS: usize = 16;

struct Metadata { geometry: GraphSourceGeometry }
impl Metadata {
    fn from_geometry(geometry: GraphSourceGeometry) -> Result<Self, String> {
        let expected = match geometry.kind() {
            GraphSourceKind::Statement => (16384, 496, 8, 2),
            GraphSourceKind::PrivateProof => (8192, 469, 4, 3),
        };
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns()) != expected
            || geometry.period() != 64
        {
            return Err("closed graph-source continuation geometry changed".into());
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
    config: &profile::Config, geometry: GraphSourceGeometry, prepared: Prepared, run: &Run,
) -> Result<Normalized, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.rows != geometry.rows() {
        return Err("closed graph-source recording height differs from source".into());
    }
    // The expectation is checked against the actual normalized relation; it
    // never becomes BaseAir's degree hint or replaces symbolic evaluation.
    prepared.normalize_for_profile::<profile::Challenge, Metadata>(config, &metadata, run, QUOTIENT_CHUNKS)
}

pub(crate) fn prove(
    config: &profile::Config, geometry: GraphSourceGeometry, prepared: Normalized,
    trace: DeviceMatrix, public_values: &[Val], run: &Run,
) -> Result<Proof<profile::Config>, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.quotient_chunks() != QUOTIENT_CHUNKS {
        return Err("closed graph-source normalized quotient profile changed".into());
    }
    prove_prepared(config, &metadata, trace, public_values, run, PreparationInput::Normalized(prepared))
}
