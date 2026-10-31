//! Preparation payload only. Engine, configuration, openings, output, stacks,
//! allocator/driver overhead and reports are separate lifetime obligations.
use super::{add, mul, Error, Geometry};
use crate::block_v2::{
    gpu_hash::device::PeriodicShape,
    machine::{symbolic, verifier::periodic::Source},
};
use crate::{config::Val, joinsplit_air as js};

pub(super) const MAX_HOST_BYTES: usize = 32 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PreparationResources {
    pub symbolic_compiler_bytes: usize,
    pub periodic_source_words: usize,
    pub periodic_staging_bytes: usize,
    pub borrowed_witness_bytes: usize,
    pub owner_inline_bytes: usize,
    pub required_payload_bytes: usize,
}

impl PreparationResources {
    pub(super) fn new(geometry: Geometry) -> Result<Self, Error> {
        geometry.check()?;
        let source = js::JoinSplitAir;
        let count = source.count();
        if count != geometry.periodic_columns {
            return Err(Error::Geometry);
        }
        let shape = PeriodicShape::new(
            geometry.rows.ilog2(),
            (0..count).map(|i| source.len(i).unwrap_or(0)),
        )
        .map_err(|_| Error::Geometry)?;
        if shape.input_words() != 90_464 || shape.metadata_words() != 2 * count {
            return Err(Error::Geometry);
        }
        // Exactly uni::admission::periodic::Source's conservative retained
        // field/canonical/flattened-word overlap, descriptor and length census.
        let periodic_staging_bytes = add(
            add(
                mul(shape.input_words(), core::mem::size_of::<Val>() + 16)?,
                mul(
                    count,
                    core::mem::size_of::<Vec<Val>>()
                        + core::mem::size_of::<Vec<u64>>()
                        + core::mem::size_of::<usize>(),
                )?,
            )?,
            mul(shape.metadata_words(), 8)?,
        )?;
        if periodic_staging_bytes != 2_173_512 || symbolic::HOST_BYTES != 192 << 20 {
            return Err(Error::Geometry);
        }
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let borrowed_witness_bytes = core::mem::size_of::<js::Witness>();
        if borrowed_witness_bytes != 2_464 {
            return Err(Error::Geometry);
        }
        let owner_inline_bytes = core::mem::size_of::<super::PreparedNote<'static>>();
        let required_payload_bytes = add(
            add(symbolic_compiler_bytes, periodic_staging_bytes)?,
            add(borrowed_witness_bytes, owner_inline_bytes)?,
        )?;
        Ok(Self {
            symbolic_compiler_bytes,
            periodic_source_words: shape.input_words(),
            periodic_staging_bytes,
            borrowed_witness_bytes,
            owner_inline_bytes,
            required_payload_bytes,
        })
    }
}
