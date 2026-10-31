//! Closed metadata for the already-recorded native SHAKE lane sources.
//! This private continuation never accepts or evaluates an AIR callback.
use super::*;
use crate::block_v2::{
    native_gpu::shake_preparation::{ShakeLaneLayout, ShakePreparationGeometry},
    profile,
};
use p3_air::BaseAir;

const PUBLIC_VALUES: usize = 216;
const PERIODIC_COLUMNS: usize = 42;
const PERIODIC_LENGTH: usize = 128;
const MAX_CONSTRAINT_DEGREE: usize = 7;
const QUOTIENT_CHUNKS: usize = 16;

/// Only fixed metadata methods exist; this deliberately implements no Air.
/// The actual source was evaluated once by the closed research owner before
/// its opaque recording entered this crate-private continuation.
struct Metadata {
    width: usize,
}

impl Metadata {
    fn from_geometry(geometry: ShakePreparationGeometry) -> Result<Self, String> {
        let width = match geometry.layout() {
            ShakeLaneLayout::Singleton => 517,
            ShakeLaneLayout::HomogeneousBatch => 518,
        };
        if geometry.width() != width
            || geometry.rows() != 4096 * geometry.permutations()
            || geometry.public_values() != PUBLIC_VALUES
            || geometry.periodic_columns() != PERIODIC_COLUMNS
            || geometry.periodic_length() != PERIODIC_LENGTH
        {
            return Err("closed SHAKE continuation source geometry changed".into());
        }
        Ok(Self { width })
    }
}

impl BaseAir<Val> for Metadata {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(MAX_CONSTRAINT_DEGREE)
    }
    // Match the original AIRs' default all-column next-row metadata. The
    // native PCS adapter census separately charges its temporary Vec backing.
}

/// Consume exact recorded public data and check actual normalized degree and
/// program bounds before private trace generation. The source's degree-seven
/// hint implies sixteen hiding chunks; no caller selects or supplies a hint.
pub(crate) fn normalize(
    config: &profile::Config,
    geometry: ShakePreparationGeometry,
    prepared: Prepared,
    run: &Run,
) -> Result<Normalized, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.rows != geometry.rows() {
        return Err("closed SHAKE recording height differs from source".into());
    }
    prepared.normalize_for_profile::<profile::Challenge, Metadata>(
        config,
        &metadata,
        run,
        QUOTIENT_CHUNKS,
    )
}

/// Continue exactly the ordinary uni transcript and PCS using sealed public
/// metadata. No private trace or proof may enter this API from another crate.
pub(crate) fn prove(
    config: &profile::Config,
    geometry: ShakePreparationGeometry,
    prepared: Normalized,
    trace: DeviceMatrix,
    public_values: &[Val],
    run: &Run,
) -> Result<Proof<profile::Config>, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.quotient_chunks() != QUOTIENT_CHUNKS {
        return Err("closed SHAKE normalized quotient profile changed".into());
    }
    prove_prepared(
        config,
        &metadata,
        trace,
        public_values,
        run,
        PreparationInput::Normalized(prepared),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::native_gpu::{shake_preparation::ShakePreparationPlan, ShakeTraceSpec};

    #[test]
    fn closed_metadata_matches_both_pinned_lane_profiles() {
        for plan in [
            ShakePreparationPlan::singleton(ShakeTraceSpec {
                input_len: 0,
                output_len: 137,
                first_permutation: 0,
                permutations: 1,
            })
            .unwrap(),
            ShakePreparationPlan::batch(ShakeTraceSpec {
                input_len: 4 * 136,
                output_len: 137,
                first_permutation: 0,
                permutations: 4,
            })
            .unwrap(),
        ] {
            let geometry = plan.geometry();
            let metadata = Metadata::from_geometry(geometry).unwrap();
            let layout = AirLayout::from_air::<Val>(&metadata);
            assert_eq!(layout.main_width, geometry.width());
            assert_eq!(layout.num_public_values, 216);
            assert_eq!(layout.num_periodic_columns, 42);
            assert_eq!(layout.preprocessed_width, 0);
            assert_eq!(layout.permutation_width, 0);
            assert_eq!(metadata.max_constraint_degree(), Some(7));
            assert_eq!(metadata.num_constraints(), None);
            assert_eq!(
                metadata.main_next_row_columns(),
                (0..geometry.width()).collect::<Vec<_>>()
            );
            assert_eq!(
                QUOTIENT_CHUNKS,
                2 * MAX_CONSTRAINT_DEGREE.next_power_of_two()
            );
        }
    }

    #[test]
    fn actual_lane_sources_keep_the_closed_degree_and_next_row_metadata() {
        let single = include_str!("../../../../../research/pq-ringct/src/shake_air/lane.rs");
        let batch = include_str!("../../../../../research/pq-ringct/src/shake_air/lane/batch.rs");
        assert!(single.contains("const MAX_CONSTRAINT_DEGREE: usize = 7;"));
        assert!(single.contains("Some(MAX_CONSTRAINT_DEGREE)"));
        assert!(batch.contains("Some(super::MAX_CONSTRAINT_DEGREE)"));
        for source in [single, batch] {
            assert!(!source.contains("fn main_next_row_columns("));
            assert!(!source.contains("fn num_constraints("));
        }
    }
}
