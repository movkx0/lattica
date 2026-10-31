//! Closed metadata for the already-recorded native AES lane sources.
//! This private continuation never accepts or evaluates an AIR callback.
use super::*;
use crate::block_v2::{
    native_gpu::aes_preparation::AesPreparationGeometry,
    profile,
};
use p3_air::BaseAir;

const PUBLIC_VALUES: usize = 12;
const PERIODIC_COLUMNS: usize = 31;
const PERIODIC_LENGTH: usize = 64;
const MAX_CONSTRAINT_DEGREE: usize = 7;
const QUOTIENT_CHUNKS: usize = 16;

/// Only fixed metadata methods exist; this deliberately implements no Air.
/// The actual source was evaluated once by the closed research owner before
/// its opaque recording entered this crate-private continuation.
struct Metadata {
    width: usize,
}

impl Metadata {
    fn from_geometry(geometry: AesPreparationGeometry) -> Result<Self, String> {
        let width = 417;
        if geometry.width() != width
            || geometry.rows() != (1024 * geometry.blocks()).next_power_of_two()
            || geometry.public_values() != PUBLIC_VALUES
            || geometry.periodic_columns() != PERIODIC_COLUMNS
            || geometry.periodic_length() != PERIODIC_LENGTH
        {
            return Err("closed AES continuation source geometry changed".into());
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
    geometry: AesPreparationGeometry,
    prepared: Prepared,
    run: &Run,
) -> Result<Normalized, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.rows != geometry.rows() {
        return Err("closed AES recording height differs from source".into());
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
    geometry: AesPreparationGeometry,
    prepared: Normalized,
    trace: DeviceMatrix,
    public_values: &[Val],
    run: &Run,
) -> Result<Proof<profile::Config>, String> {
    let metadata = Metadata::from_geometry(geometry)?;
    if prepared.quotient_chunks() != QUOTIENT_CHUNKS {
        return Err("closed AES normalized quotient profile changed".into());
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
    use crate::block_v2::native_gpu::{aes_preparation::AesPreparationPlan, AesTraceSpec};

    #[test]
    fn closed_aes_metadata_keeps_native_degree_period_and_padded_tail() {
        for blocks in [1, 3, 5, 64] {
            let source = AesPreparationPlan::new(AesTraceSpec {
                domain: 11, start_counter: u32::MAX, output_len: blocks * 16 - 3,
                first_block: 0, blocks,
            }).unwrap();
            let metadata = Metadata::from_geometry(source.geometry()).unwrap();
            assert_eq!(metadata.width(), 417);
            assert_eq!(metadata.num_public_values(), 12);
            assert_eq!(metadata.num_periodic_columns(), 31);
            assert_eq!(metadata.max_constraint_degree(), Some(7));
            assert_eq!(source.geometry().rows(), (1024 * blocks).next_power_of_two());
            assert_eq!(metadata.main_next_row_columns().len(), 417);
        }
        assert_eq!(QUOTIENT_CHUNKS, 16);
    }
}
