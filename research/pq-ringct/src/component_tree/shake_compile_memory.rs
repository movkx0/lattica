//! Caller-owned backing outside the bounded ProgramBuilder. The formula pins
//! the lane SHAKE AIR and current verifier helpers; it is not an RSS limit or
//! an ownership token, and does not admit retained native/recursive proofs.
use super::*;
use core::mem::size_of;
use p3_air::AirBuilder;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakeGroupFootprintError {
    Empty,
    UnsupportedProfile,
    Overflow,
}
impl core::fmt::Display for ShakeGroupFootprintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SHAKE compiler footprint: {self:?}")
    }
}
type AdmissionResult<T> = core::result::Result<T, ShakeGroupFootprintError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakeGroupCompileFootprint {
    pub symbolic: verifier::uni::BoundedSymbolicAllowance,
    pub input_backing_bytes: usize,
    pub returned_wire_bytes: usize,
    pub helper_bytes: usize,
    pub auxiliary_peak_bytes: usize,
}

fn add(a: usize, b: usize) -> AdmissionResult<usize> {
    a.checked_add(b).ok_or(ShakeGroupFootprintError::Overflow)
}
fn bytes<T>(count: usize) -> AdmissionResult<usize> {
    count
        .checked_mul(size_of::<T>())
        .ok_or(ShakeGroupFootprintError::Overflow)
}

impl ShakeGroupCompileFootprint {
    /// Allocation-free on success. The enclosing planner reserves program
    /// construction and auxiliary bytes together, before endpoint preparation.
    /// No measured peak, proof contents or witness values determine this bound.
    pub fn for_group(members: usize, limits: ConstructionLimits) -> AdmissionResult<Self> {
        if members == 0 {
            return Err(ShakeGroupFootprintError::Empty);
        }
        if !(cfg!(all(not(debug_assertions), target_arch = "x86_64"))
            && shake_air::lane::PERIODIC_COLUMNS == 42
            && shake_air::lane::SCHEDULE_PERIOD == 128
            && shake_air::PUBLIC_VALUES == 216
            && lattica_prover_p3::block_v2::profile::LOG_BLOWUP == 4)
        {
            return Err(ShakeGroupFootprintError::UnsupportedProfile);
        }
        type Builder = verifier::uni::BoundedSymbolicBuilder;
        type Expr = <Builder as AirBuilder>::Expr;
        type Public = <Builder as AirBuilder>::PublicVar;
        let symbolic = verifier::uni::BoundedSymbolicAllowance::REQUIRED;
        let input_backing_bytes = bytes::<Val>(limits.max_input_values)?
            .checked_mul(2)
            .ok_or(ShakeGroupFootprintError::Overflow)?;
        let returned_wire_bytes = bytes::<Wire>(limits.max_input_values)?;
        let mut helper_bytes = 0;
        // AIR descriptors have no heap payload. Doubling covers Vec capacity.
        helper_bytes = add(
            helper_bytes,
            bytes::<shake_air::lane::batch::ShakeSegmentAir>(members)?
                .checked_mul(2)
                .ok_or(ShakeGroupFootprintError::Overflow)?,
        )?;
        // One 42 x 128 periodic table at a time; include the original column
        // used by vec![column; 42] and spare/overlapping backing conservatively.
        helper_bytes = add(helper_bytes, bytes::<Val>(2 * 43 * 128)?)?;
        helper_bytes = add(helper_bytes, bytes::<Vec<Val>>(2 * 42)?)?;
        // AIR eval owns public[216], periodic[42], counter[5], updates[4][4].
        // Four times payload covers collection growth overlap; expression Arc
        // children belong to the recorder quota, not these outer Vec buffers.
        helper_bytes = add(helper_bytes, bytes::<Public>(4 * 216)?)?;
        helper_bytes = add(helper_bytes, bytes::<Expr>(4 * (42 + 5 + 16))?)?;
        // Both boundary-index arrays, endpoint extraction/clones, header and
        // public wires, field-hash input copies, and native next-row indices.
        helper_bytes = add(
            helper_bytes,
            bytes::<usize>(4 * 108 + 2 * shake_air::lane::batch::WIDTH)?,
        )?;
        helper_bytes = add(
            helper_bytes,
            bytes::<Wire>(8 * 108 + 4 * (HEADER + 8) + 8 * 110)?,
        )?;
        helper_bytes = add(helper_bytes, bytes::<Val>(4 * (HEADER + 8) + 8 * 110)?)?;
        // Quotient Vec headers (at most 32 chunks), transcript input/output
        // growth and one at-most-64-bit sample. PCS arrays otherwise live on
        // the stack or in the separately bounded ProofInputs return buffers.
        helper_bytes = add(helper_bytes, bytes::<Vec<[Wire; 3]>>(4 * 32)?)?;
        helper_bytes = add(helper_bytes, bytes::<Wire>(4 * (4 + 8 + 64))?)?;
        // Pinned native Goldilocks Poseidon2 constructors move three vectors
        // (4x8 initial, 4x8 final, 22 internal constants). Count four complete
        // sets for hash helpers and CPU folding, including vector headers.
        helper_bytes = add(helper_bytes, bytes::<Val>(4 * (4 * 8 + 4 * 8 + 22))?)?;
        helper_bytes = add(helper_bytes, bytes::<Vec<Val>>(4 * 3)?)?;
        let auxiliary_peak_bytes = [
            symbolic.workspace_bytes,
            symbolic.retained_graph_bytes,
            input_backing_bytes,
            returned_wire_bytes,
            helper_bytes,
        ]
        .into_iter()
        .try_fold(0, add)?;
        // Detect overflow in the enclosing program + auxiliary reservation,
        // even though the program builder enforces its own component quota.
        add(limits.max_requested_program_bytes, auxiliary_peak_bytes)?;
        Ok(Self {
            symbolic,
            input_backing_bytes,
            returned_wire_bytes,
            helper_bytes,
            auxiliary_peak_bytes,
        })
    }
}

pub(super) fn air(
    contract: &Contract,
    member: &ShakeGroupMember<'_>,
) -> Result<shake_air::lane::batch::ShakeSegmentAir> {
    use shake_air::lane::batch::{BatchShakeAir, ShakeSegmentAir};
    let Kind::Shake(descriptor) = contract.kind else {
        return Err(Error("SHAKE proof used for non-SHAKE contract".into()));
    };
    if member.count == 1 {
        return shake_air::lane::LaneShakeAir::new(descriptor, member.first as usize)
            .map(ShakeSegmentAir::Single)
            .map_err(err);
    }
    BatchShakeAir::full_absorb(descriptor, member.first as usize, member.count as usize)
        .or_else(|_| {
            BatchShakeAir::full_squeeze(descriptor, member.first as usize, member.count as usize)
        })
        .map(ShakeSegmentAir::Batch)
        .map_err(err)
}
