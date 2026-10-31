//! Recovery accepts only the exact owners returned by this closed issuer.
//! Same-ledger/category checks supplement provenance; they do not replace it.
use super::*;

pub(super) fn output(claim: &mut SlotClaim, originals: (Reservation, Reservation))
    -> Result<(), AffineNativeOperationFailure>
{
    let mut valid = true;
    for original in [originals.0, originals.1] {
        if let Err((_error, original)) = claim.reunite(original) {
            // A partial or foreign claim cannot create a reusable output slot.
            core::mem::forget(original);
            valid = false;
        }
    }
    if valid { Ok(()) } else { Err(AffineNativeOperationFailure::Authority) }
}

/// Only a no-start refusal or exact core retirement reaches this function.
/// Process every original even if one check fails, preserving uncertain credit.
pub(super) fn phase(mut partition: OriginalPhasePartition<'_, '_>,
    originals: [Reservation; 5]) -> Result<(), AffineNativeOperationFailure>
{
    let mut valid = true;
    for original in originals {
        if let Err((_error, original)) = partition.reunite(original) {
            core::mem::forget(original);
            valid = false;
        }
    }
    if !valid { return Err(AffineNativeOperationFailure::Authority); }
    partition.restore().map_err(|_poisoned| AffineNativeOperationFailure::Authority)
}

/// Both output and backend originals are restored on terminal refusal.
pub(super) fn all(partition: OriginalPhasePartition<'_, '_>, originals: [Reservation; 5],
    claim: &mut SlotClaim, empty_output: Option<(Reservation, Reservation)>)
    -> Result<(), AffineNativeOperationFailure>
{
    let output_result = match empty_output {
        Some(originals) => output(claim, originals),
        None => Ok(()),
    };
    let phase_result = phase(partition, originals);
    output_result.and(phase_result)
}
