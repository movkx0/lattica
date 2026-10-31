//! Final aggregate artifact and negative-probe qualification inside its existing
//! admitted verification phase. Original root ownership never moves or clones.
//! No public key is adopted from bytes and no codec result confers acceptance.
use super::*;
use lattica_prover_p3::block_v2::{codec, profile,
    machine::backend::RegisteredVerificationFailure};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha3::{Digest, Sha3_256};

mod codec_frames;
mod disk;
mod geometry;
mod packet;
mod storage;

/// Fixed observations only. Success is constructed after decoded proof and
/// packet destruction. The enclosing FinalVerification still borrows the root.
#[derive(Clone, Copy, Default, serde::Serialize)]
pub(crate) struct FinalQualificationReport {
    pub(crate) artifact_round_trip: bool,
    pub(crate) public_mutation_rejected: bool,
    pub(crate) proof_mutation_rejected: bool,
    pub(crate) decoded_positive_checks: usize,
    pub(crate) packet_bytes: usize,
    pub(crate) proof_bytes: usize,
    pub(crate) packet_sha3_256: [u8; 32],
    pub(crate) file_device: u64,
    pub(crate) file_inode: u64,
    pub(crate) height: usize,
    pub(crate) public_values: usize,
    pub(crate) source_fingerprint: [u8; 32],
    pub(crate) compiled_source_fingerprint: [u8; 32],
    pub(crate) batch_profile: [u8; 32],
    pub(crate) context: [u8; 32],
    pub(crate) encoding_ns: u128,
    pub(crate) disk_round_trip_ns: u128,
    pub(crate) decoding_ns: u128,
    pub(crate) decoded_cpu_verification_ns: u128,
    pub(crate) canonical_encoding_ns: u128,
    pub(crate) mutation_cpu_verification_ns: u128,
    pub(crate) elapsed_ns: u128,
}

fn sha3(bytes: &[u8]) -> [u8; 32] { Sha3_256::digest(bytes).into() }

pub(super) fn planning_frames() -> OwnedResult<usize> { storage::planning_frames() }

/// Called while final phase facts are derived, before the complete schedule is
/// sealed or proof execution begins. The same derivation is rechecked at use.
pub(super) fn requirements(merge: &MergeSource) -> OwnedResult<Requirements> {
    let limits = storage::Limits::from_source(merge)?;
    combine(&[
        requirement(Category::PhaseScratch, add(limits.payload_bytes()?, storage::frames()?)?)?,
        requirement(Category::IndependentVerifier, RegisteredVerifier::classified_call_extra_bytes())?,
    ])
}

fn packet_buffer(capacity: usize) -> OwnedResult<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(capacity).map_err(|_| FinalFailure::Capacity)?;
    if buffer.capacity() != capacity { return Err(FinalFailure::Capacity); }
    buffer.resize(capacity, 0);
    Ok(buffer)
}

fn numerical_rejection(result: core::result::Result<(), RegisteredVerificationFailure>)
    -> OwnedResult<()>
{
    match result {
        Err(RegisteredVerificationFailure::RelationRejected(diagnostic)) => {
            drop(diagnostic);
            Ok(())
        }
        // Admission, configuration and allocation refusal earn no mutation
        // credit. Their bounded diagnostics die under the current reservation.
        other => { drop(other); Err(FinalFailure::Verification) }
    }
}

fn mutations(key: &BatchKey, decoded: &mut BatchProof,
    statements: &[LeafStatement]) -> OwnedResult<()>
{
    let public_word = decoded.public[crate::ordered_aggregation::contract::ROOT];
    decoded.public[crate::ordered_aggregation::contract::ROOT] += Val::ONE;
    let public_rejection = numerical_rejection(key.verifier.verify_classified(
        &decoded.proof, &decoded.public));
    decoded.public[crate::ordered_aggregation::contract::ROOT] = public_word;
    public_rejection?;
    key.verify_expected(decoded, statements).map_err(|_| FinalFailure::Verification)?;

    // Change one actual opening value without changing any shape, vector length,
    // terminal, cap or degree. Only numerical rejection can qualify this probe.
    let value = decoded.proof.opened_values.instances.first_mut()
        .and_then(|instance| instance.base_opened_values.trace_local.first_mut())
        .ok_or(FinalFailure::Source)?;
    let original = *value;
    *value += profile::Challenge::ONE;
    let proof_rejection = numerical_rejection(key.verifier.verify_classified(
        &decoded.proof, &decoded.public));
    *decoded.proof.opened_values.instances.first_mut()
        .and_then(|instance| instance.base_opened_values.trace_local.first_mut())
        .ok_or(FinalFailure::Source)? = original;
    proof_rejection?;
    key.verify_expected(decoded, statements).map_err(|_| FinalFailure::Verification)?;
    Ok(())
}

pub(super) fn run(root: &Retained<FinalNode<'_>>, plan: &FinalPhasePlan<'_>,
    execution: &ExecutionAccess<'_>) -> OwnedResult<FinalQualificationReport>
{
    let ordinal = plan.source.merge_count().checked_sub(1).ok_or(FinalFailure::Order)?;
    let merge = plan.source.merge(ordinal).ok_or(FinalFailure::Order)?;
    let verification = plan.phase_binding(2 * plan.source.merge_count())?;
    if execution.binding() != verification || verification.kind() != PhaseKind::FinalVerify
        || !root.belongs_to(execution)
        || root.binding() != plan.phase_binding(2 * ordinal + 1)?
        || !plan.fresh_only() || !contains(verification.facts().scratch, requirements(merge)?)
    { return Err(FinalFailure::Authority); }
    memory::check_node(root.get(), plan, ordinal)?;
    let node = root.get();
    let key = node.key();
    let proof = node.proof();
    if !core::ptr::eq(node.source, plan.source) || node.merge != ordinal
        || key.span() != (0, plan.source.scope().total())
    { return Err(FinalFailure::Coverage); }
    let limits = storage::Limits::from_source(merge)?;
    let shape = limits.envelope.cases.iter().find(|shape| shape.rows == key.height)
        .ok_or(FinalFailure::Source)?;
    let header = packet::Header {
        compiled_source: plan.source.compiled_source_fingerprint(),
        source: plan.source.source_fingerprint(),
        batch_profile: key.batch_profile(), context: plan.source.scope().context(),
        merge: ordinal, first: key.span().0 as usize, count: key.span().1 as usize,
        total: key.total() as usize, height: key.height, public: &proof.public, cap: &key.cap,
    };
    let started = Instant::now();
    // Both packets coexist with the original proof/key and full decoder quota.
    // The second packet becomes disk readback, then canonical re-encoding.
    let mut encoded = packet_buffer(limits.packet_capacity)?;
    let mut readback = packet_buffer(limits.packet_capacity)?;
    let timed = Instant::now();
    let proof_bytes = codec::encode_registered_proof_into(&proof.proof,
        &mut encoded[packet::HEADER_BYTES..]).map_err(|_| FinalFailure::Report)?.len();
    if proof_bytes > shape.encoded_inner_bytes { return Err(FinalFailure::Capacity); }
    let packet_bytes = add(packet::HEADER_BYTES, proof_bytes)?;
    packet::encode(header, proof_bytes, &mut encoded[..packet::HEADER_BYTES])?;
    packet::validate(&encoded[..packet_bytes], header, proof_bytes)?;
    let digest = sha3(&encoded[..packet_bytes]);
    let encoding_ns = timed.elapsed().as_nanos();
    let timed = Instant::now();
    let provenance = disk::roundtrip(&encoded[..packet_bytes], &mut readback[..packet_bytes], digest)?;
    let disk_round_trip_ns = timed.elapsed().as_nanos();
    let timed = Instant::now();
    let inner = packet::validate(&readback[..packet_bytes], header, proof_bytes)?;
    // This exact height's cumulative nested-Vec PLUS canonical quota is no
    // greater than the source-admitted maximum. Never pass a larger cap here.
    let raw = codec::decode_registered_proof_bounded(inner, shape.decoded_cumulative_bytes)
        .map_err(|_| FinalFailure::Report)?;
    let mut decoded = BatchProof { public: proof.public, proof: raw };
    let decoding_ns = timed.elapsed().as_nanos();
    let timed = Instant::now();
    key.verify_expected(&decoded, plan.statements).map_err(|_| FinalFailure::Verification)?;
    let decoded_cpu_verification_ns = timed.elapsed().as_nanos();
    let timed = Instant::now();
    let canonical_bytes = codec::encode_registered_proof_into(&decoded.proof,
        &mut readback[packet::HEADER_BYTES..]).map_err(|_| FinalFailure::Report)?.len();
    if canonical_bytes != proof_bytes { return Err(FinalFailure::Report); }
    packet::encode(header, canonical_bytes, &mut readback[..packet::HEADER_BYTES])?;
    if readback[..packet_bytes] != encoded[..packet_bytes] { return Err(FinalFailure::Report); }
    let canonical_encoding_ns = timed.elapsed().as_nanos();
    let timed = Instant::now();
    mutations(key, &mut decoded, plan.statements)?;
    let mutation_cpu_verification_ns = timed.elapsed().as_nanos();
    drop(decoded);
    drop(readback);
    drop(encoded);
    Ok(FinalQualificationReport {
        artifact_round_trip: true, public_mutation_rejected: true, proof_mutation_rejected: true,
        decoded_positive_checks: 3, packet_bytes, proof_bytes, packet_sha3_256: digest,
        file_device: provenance.device, file_inode: provenance.inode, height: key.height,
        public_values: PUBLIC_VALUES, source_fingerprint: header.source,
        compiled_source_fingerprint: header.compiled_source, batch_profile: header.batch_profile,
        context: header.context, encoding_ns, disk_round_trip_ns, decoding_ns,
        decoded_cpu_verification_ns, canonical_encoding_ns, mutation_cpu_verification_ns,
        elapsed_ns: started.elapsed().as_nanos(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_numerical_rejection_earns_mutation_credit() {
        assert!(numerical_rejection(Ok(())).is_err());
        for error in [RegisteredVerificationFailure::Admission(String::new()),
            RegisteredVerificationFailure::Configuration(String::new()),
            RegisteredVerificationFailure::Allocation(String::new())]
        { assert!(numerical_rejection(Err(error)).is_err()); }
        assert!(numerical_rejection(Err(RegisteredVerificationFailure::RelationRejected(String::new()))).is_ok());
    }
}
