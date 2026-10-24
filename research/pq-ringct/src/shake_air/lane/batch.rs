//! Homogeneous batches preserve the independently tested single-permutation
//! lane AIR. Only the iota sequence resets between permutations; every state,
//! scratch, and byte-commitment register is carried through the boundary.
//!
//! Counts are powers of two, so no inactive permutation or unauthenticated
//! padding selector is needed. A new counter constrains the exact number and
//! the final block phase. All trusted schedules still have period 128.

use super::*;

mod constraints;
mod partition;
pub use partition::{verify_batched_request, verify_committed_batched_request, ShakeBatchPartition, ShakeSegmentAir};
#[cfg(test)]
mod tests;
mod witness;
#[cfg(feature = "opencl")]
mod gpu;

pub const WIDTH: usize = super::WIDTH + 1;
const PERMUTATION: usize = super::WIDTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    FullAbsorb,
    FullSqueeze,
}

#[derive(Clone, Debug)]
pub struct BatchShakeAir {
    descriptor: Descriptor,
    first_permutation: usize,
    permutations: usize,
    height: usize,
    kind: Kind,
}

impl BatchShakeAir {
    pub fn full_absorb(descriptor: Descriptor, first: usize, count: usize) -> Result<Self, Error> {
        Self::new(descriptor, first, count, Kind::FullAbsorb)
    }
    pub fn full_squeeze(descriptor: Descriptor, first: usize, count: usize) -> Result<Self, Error> {
        Self::new(descriptor, first, count, Kind::FullSqueeze)
    }
    fn new(descriptor: Descriptor, first: usize, count: usize, kind: Kind) -> Result<Self, Error> {
        if !count.is_power_of_two() {
            return Err(Error::Segment);
        }
        ShakeAir::new(descriptor, first, count)?;
        let end = first.checked_add(count).ok_or(Error::Overflow)?;
        let height = HEIGHT.checked_mul(count).ok_or(Error::Overflow)?;
        // Stay within the established machine-domain ceiling, even before
        // memory admission. This is an allocation bound, not a soundness knob.
        if height > 1 << 24 {
            return Err(Error::Length);
        }
        match kind {
            Kind::FullAbsorb if end <= descriptor.input_len / RATE => {}
            Kind::FullSqueeze
                if first >= descriptor.absorb_permutations()
                    && end
                        <= descriptor.absorb_permutations() - 1 + descriptor.output_len / RATE => {}
            _ => return Err(Error::Segment),
        }
        Ok(Self {
            descriptor,
            first_permutation: first,
            permutations: count,
            height,
            kind,
        })
    }
    pub fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    pub fn first_permutation(&self) -> usize {
        self.first_permutation
    }
    pub fn permutations(&self) -> usize {
        self.permutations
    }
    pub fn height(&self) -> usize {
        self.height
    }
    fn absorbs(&self) -> bool {
        self.kind == Kind::FullAbsorb
    }
    fn last_absorption(&self) -> bool {
        false
    }
    fn fixed_schedule(&self) -> Vec<Vec<Val>> {
        LaneShakeAir::new(self.descriptor, self.first_permutation)
            .unwrap()
            .fixed_schedule()
    }
}

impl BaseAir<Val> for BatchShakeAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.fixed_schedule()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(super::MAX_CONSTRAINT_DEGREE)
    }
}
