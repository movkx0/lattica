//! Immutable scheduling for the paired-wrapper research candidate.
//!
//! A schedule is not a proof, a memory admission or a height-closure receipt.
//! Native segmentation and native AIR registration remain unchanged.
use super::{err, require, Error, Partition, Request, RequestDescriptor, Result, SegmentInfo};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShakeWrapperLayout {
    #[default]
    Singleton,
    /// Exactly two consecutive native segments per recursive wrapper, with a
    /// singleton only for the odd final segment. Currently research-only.
    PairedV1,
}

impl ShakeWrapperLayout {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Singleton => "singleton",
            Self::PairedV1 => "paired-v1",
        }
    }

    /// Fail before any proof dispatch. A construction limit on ProgramBuilder
    /// alone does not admit symbolic AIR/compiler scratch or prove recursive
    /// height closure through the transaction graph and final aggregation.
    pub fn require_executable(self) -> Result<()> {
        match self {
            Self::Singleton => Ok(()),
            Self::PairedV1 => Err(Error(
                concat!(
                    "paired-v1 refused before proof dispatch: qualification incomplete; ",
                    "missing source-derived native-verifier/compiler scratch admission, ",
                    "recursive output ownership reservations, and complete ",
                    "component/transaction/final-aggregate height closure; ",
                    "no fallback or proof retry was attempted"
                )
                .into(),
            )),
        }
    }

    fn members(self) -> usize {
        match self {
            Self::Singleton => 1,
            Self::PairedV1 => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShakeWrapperSpan {
    pub first_segment: usize,
    pub segment_count: usize,
    pub first_unit: usize,
    pub units: usize,
}

/// Scheduling counts only. They are not measured proving work or speedup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShakeWrapperCounts {
    pub native_proofs: usize,
    pub recursive_leaves: usize,
    pub recursive_parents: usize,
}

/// Borrows the immutable exact request. Construction validates the complete
/// native partition before yielding any pair, and allocates no new storage.
pub struct ShakeWrapperSchedule<'a> {
    segments: &'a [SegmentInfo],
    layout: ShakeWrapperLayout,
}

impl Request {
    pub fn shake_wrapper_schedule(
        &self,
        layout: ShakeWrapperLayout,
    ) -> Result<ShakeWrapperSchedule<'_>> {
        let Partition::Shake(partition) = &self.partition else {
            return Err(Error("SHAKE wrapper layout used for AES request".into()));
        };
        require(
            self.descriptor == RequestDescriptor::Shake(partition.descriptor()),
            "SHAKE wrapper request/partition descriptor mismatch",
        )?;
        let total = partition.descriptor().permutations().map_err(err)?;
        validate_coverage(&self.segments, total)?;
        require(
            partition.segments().len() == self.segments.len(),
            "SHAKE wrapper native partition length mismatch",
        )?;
        for (segment, air) in self.segments.iter().zip(partition.segments()) {
            require(
                segment.first_unit == air.first_permutation()
                    && segment.units == air.permutations()
                    && segment.height == air.height()
                    && segment.width == p3_air::BaseAir::width(air),
                "SHAKE wrapper native registration mismatch",
            )?;
        }
        Ok(ShakeWrapperSchedule {
            segments: &self.segments,
            layout,
        })
    }
}

fn validate_coverage(segments: &[SegmentInfo], total: usize) -> Result<()> {
    require(
        !segments.is_empty() && total != 0,
        "empty SHAKE wrapper schedule",
    )?;
    let mut end = 0usize;
    for segment in segments {
        require(
            segment.first_unit == end && segment.units != 0,
            "missing, duplicate, overlapping or reordered SHAKE wrapper segment",
        )?;
        end = end
            .checked_add(segment.units)
            .ok_or_else(|| Error("SHAKE wrapper coverage overflow".into()))?;
        require(end <= total, "SHAKE wrapper segment outside request")?;
    }
    require(end == total, "incomplete SHAKE wrapper segment coverage")
}

impl ShakeWrapperSchedule<'_> {
    pub fn counts(&self) -> ShakeWrapperCounts {
        let recursive_leaves = self.segments.len().div_ceil(self.layout.members());
        ShakeWrapperCounts {
            native_proofs: self.segments.len(),
            recursive_leaves,
            recursive_parents: recursive_leaves - 1,
        }
    }

    pub fn groups(&self) -> impl ExactSizeIterator<Item = ShakeWrapperSpan> + '_ {
        self.segments
            .chunks(self.layout.members())
            .enumerate()
            .map(|(index, segments)| {
                let first = &segments[0];
                let last = &segments[segments.len() - 1];
                ShakeWrapperSpan {
                    first_segment: index * self.layout.members(),
                    segment_count: segments.len(),
                    first_unit: first.first_unit,
                    // The complete interval was checked before construction.
                    units: last.first_unit + last.units - first.first_unit,
                }
            })
    }
}

#[cfg(test)]
mod tests;
