//! Allocation-free census inside the private request/output owners.
//! This checks backing geometry only; the ordinary constructors still enforce
//! the native relation's canonical input and witness contract.
use super::*;
use core::mem::size_of;

pub(crate) struct InputSource;

impl InputSource {
    pub(crate) const fn input_backing_bytes() -> usize {
        (input_layout::RING_POLYS + input_layout::RECIPIENT_POLYS)
            * size_of::<CanonicalPoly>()
            + INPUTS * (SPENDING_KEY_POLYS + COMMITMENT_KEY_POLYS)
                * size_of::<SignedPoly>()
    }
    pub(crate) const fn packed_backing_bytes() -> usize {
        input_layout::BYTES
    }
    pub(crate) const fn output_backing_bytes() -> usize {
        STATEMENT_BYTES + PROOF_BYTES
            + OUTPUTS * COMMITMENT_KEY_POLYS * size_of::<SignedPoly>()
    }
    pub(crate) const fn packing_inline_bytes() -> usize {
        // pack/pack_with_entropy: borrowed request, entropy transport/result,
        // owned packed Vec, fallible return, cursor and serialization closure.
        size_of::<&PrivateSpendRequest>()
            + 2 * size_of::<PrivateEntropy>()
            + size_of::<Result<PrivateEntropy, String>>()
            + size_of::<PackedSpendInputs>()
            + size_of::<Result<PackedSpendInputs, String>>()
            + size_of::<usize>()
            + size_of::<(&mut Vec<u64>, &mut usize)>()
            + 2 * size_of::<u64>()
    }
    pub(crate) fn check_request(request: &PrivateSpendRequest) -> bool {
        // A request owns no public mutation API after its validating
        // constructor. Length AND capacity bind all four backing allocations;
        // accepting an oversized Vec merely because len matches is unsound.
        request.public.ring.len() == input_layout::RING_POLYS
            && request.public.ring.capacity() == input_layout::RING_POLYS
            && request.public.recipients.len() == input_layout::RECIPIENT_POLYS
            && request.public.recipients.capacity() == input_layout::RECIPIENT_POLYS
            && request.witness.spending_keys.len() == INPUTS * SPENDING_KEY_POLYS
            && request.witness.spending_keys.capacity() == INPUTS * SPENDING_KEY_POLYS
            && request.witness.commitment_keys.len() == INPUTS * COMMITMENT_KEY_POLYS
            && request.witness.commitment_keys.capacity() == INPUTS * COMMITMENT_KEY_POLYS
    }
    pub(crate) fn check_output(output: &PrivateSpendOutput) -> bool {
        output.statement.len() == STATEMENT_BYTES
            && output.statement.capacity() == STATEMENT_BYTES
            && output.proof.len() == PROOF_BYTES
            && output.proof.capacity() == PROOF_BYTES
            && output.output_keys.polynomials.len() == OUTPUTS * COMMITMENT_KEY_POLYS
            && output.output_keys.polynomials.capacity() == OUTPUTS * COMMITMENT_KEY_POLYS
    }
}
