//! Private original-ledger transport prerequisites, never dispatch authority.
//! The future reviewed driver must retain this owner before creating Attempt.
use super::*;
use crate::component_tree::owned_shake::transport_shape::{HeightShape, TransportEnvelope};
use lattica_prover_p3::block_v2::{codec, profile};
use super::super::super::super::super::CpuEnvelope;
use super::header::{CAP_ROOTS, HEADER_BYTES, PACKET_LIMIT, PUBLICS};

mod claims;
mod codec_frames;
mod source;

type AdmissionResult<T> = core::result::Result<T, ParentCompileError>;
const HEIGHTS: usize = 18;
const DECODE_LIMIT: usize = 64 << 20;
const TRAILING_PROBE_BYTES: usize = 1;
const ROOT_ORDINAL: usize = PARENTS - 1;

// Complete data precede both originals in declaration/drop order. Neither
// original may be split out, copied, converted to a numeric receipt or exposed.
pub(in super::super) struct PreissuedRootTransport<'bound, 'source, 'request> {
    source: &'bound ParentSourceBound<'source, 'request>,
    spec: Spec,
    header: [Val; HEADER],
    envelope: TransportEnvelope,
    cpu: CpuEnvelope,
    payload: Reservation,
    fixed: Reservation,
}

/// Incremental transport claims only; original root/key/runtime remain live
/// under their separate existing owners. This is no whole-worker fit receipt.
#[derive(Clone, Copy)]
pub(in super::super) struct RootTransportPlanReport {
    pub(in super::super) cpu_heights: usize,
    pub(in super::super) codec_heights: usize,
    pub(in super::super) fixed_host_bytes: u64,
    pub(in super::super) packet_and_decoder_host_bytes: u64,
    pub(in super::super) verifier_host_bytes: u64,
    pub(in super::super) additional_host_bytes: u64,
    pub(in super::super) packet_limit_bytes: usize,
    pub(in super::super) decoder_limit_bytes: usize,
    pub(in super::super) max_inner_bytes: usize,
    pub(in super::super) max_packet_bytes: usize,
    pub(in super::super) max_packet_and_probe_bytes: usize,
    pub(in super::super) max_decoder_cumulative_bytes: usize,
}

fn packet_with_probe(inner: usize) -> AdmissionResult<usize> {
    let bytes = HEADER_BYTES.checked_add(inner)
        .and_then(|bytes| bytes.checked_add(TRAILING_PROBE_BYTES))
        .ok_or(ParentCompileError::Overflow)?;
    if inner < 8 || bytes > PACKET_LIMIT {
        return Err(ParentCompileError::Capacity);
    }
    Ok(bytes)
}

fn check_envelope(envelope: &TransportEnvelope) -> AdmissionResult<()> {
    if HEADER_BYTES != 2480 || PUBLICS != HEADER + 8 || CAP_ROOTS != 64
        || PACKET_LIMIT != 2 << 20 || profile::MAX_PROOF_BYTES != PACKET_LIMIT
        || codec::REGISTERED_PROOF_STORAGE_LIMIT_BYTES != DECODE_LIMIT
        || codec::REGISTERED_PROOF_MAGIC != b"LBV2RP02"
        || envelope.cases.len() != HEIGHTS
    {
        return Err(ParentCompileError::Source);
    }
    let mut max_inner = 0;
    let mut max_decode = 0;
    for (index, case) in envelope.cases.iter().enumerate() {
        if case.rows != 8usize << index
            || case.decoded_cumulative_bytes > DECODE_LIMIT
            || case.encoded_inner_bytes != case.canonical_bytes.checked_add(8)
                .ok_or(ParentCompileError::Overflow)?
            || case.decoded_cumulative_bytes != case.decoded_vector_bytes
                .checked_add(case.canonical_bytes).ok_or(ParentCompileError::Overflow)?
        {
            return Err(ParentCompileError::Source);
        }
        packet_with_probe(case.encoded_inner_bytes)?;
        max_inner = max_inner.max(case.encoded_inner_bytes);
        max_decode = max_decode.max(case.decoded_cumulative_bytes);
    }
    if max_inner != envelope.encoded_inner_bytes
        || max_decode != envelope.decoded_cumulative_bytes
    {
        return Err(ParentCompileError::Source);
    }
    Ok(())
}

impl<'bound, 'source, 'request> PreissuedRootTransport<'bound, 'source, 'request> {
    // Source+Ledger and this name do not enforce temporal order. This inactive
    // prerequisite requires a separately reviewed callsite before Attempt.
    pub(in super::super) fn reserve_before_native(
        source: &'bound ParentSourceBound<'source, 'request>,
        ledger: &Ledger,
    ) -> AdmissionResult<Self> {
        // Only fixed size arithmetic precedes this admission. The future
        // driver's own caller covers the function entry and ledger bootstrap.
        let fixed = ledger.admit_phase(claims::fixed()?)
            .map_err(|_| ParentCompileError::Capacity)?;
        source.check_original_request(source.request.owner, ledger)?;
        let envelope = TransportEnvelope::for_root().map_err(|_| ParentCompileError::Source)?;
        check_envelope(&envelope)?;
        let cpu = CpuEnvelope::source()?;
        let payload = ledger.admit_phase(claims::payload(cpu)?)
            .map_err(|_| ParentCompileError::Capacity)?;
        let (_, expected) = super::super::super::super::specs(source, ROOT_ORDINAL)?;
        let [_, _, spec] = expected;
        let header = source::header(&spec, &source.request.context)?;
        Ok(Self { source, spec, header, envelope, cpu, payload, fixed })
    }

    pub(super) fn check(&self, ledger: &Ledger) -> AdmissionResult<()> {
        self.source.check_original_request(self.source.request.owner, ledger)?;
        if !self.fixed.belongs_to(ledger) || !self.payload.belongs_to(ledger)
            || self.fixed.requirements() != claims::fixed()?
            || self.payload.requirements() != claims::payload(self.cpu)?
            || self.cpu != CpuEnvelope::source()?
            || self.envelope != TransportEnvelope::for_root().map_err(|_| ParentCompileError::Source)?
            || (self.spec.first, self.spec.count, self.spec.level) != (0, 122, 3)
        {
            return Err(ParentCompileError::Authority);
        }
        check_envelope(&self.envelope)
    }

    pub(super) fn source(&self) -> &'bound ParentSourceBound<'source, 'request> { self.source }
    pub(super) fn expected_spec(&self) -> &Spec { &self.spec }
    pub(super) fn expected_header(&self) -> &[Val; HEADER] { &self.header }
    pub(super) fn envelope(&self) -> &TransportEnvelope { &self.envelope }
    pub(super) fn cpu_heights(&self) -> usize { self.cpu.heights }
    pub(super) fn decoder_limit(&self) -> usize { DECODE_LIMIT }

    pub(in super::super) fn plan_report(&self, ledger: &Ledger) -> AdmissionResult<RootTransportPlanReport> {
        self.check(ledger)?;
        let fixed = self.fixed.requirements().total().map_err(|_| ParentCompileError::Overflow)?;
        let payload = self.payload.requirements();
        let payload_bytes = payload.total().map_err(|_| ParentCompileError::Overflow)?;
        let with_probe = packet_with_probe(self.envelope.encoded_inner_bytes)?;
        Ok(RootTransportPlanReport {
            cpu_heights: self.cpu.heights,
            codec_heights: self.envelope.cases.len(),
            fixed_host_bytes: fixed.host,
            packet_and_decoder_host_bytes: payload.get(Category::PhaseScratch).host,
            verifier_host_bytes: payload.get(Category::IndependentVerifier).host,
            additional_host_bytes: fixed.host.checked_add(payload_bytes.host).ok_or(ParentCompileError::Overflow)?,
            packet_limit_bytes: PACKET_LIMIT,
            decoder_limit_bytes: DECODE_LIMIT,
            max_inner_bytes: self.envelope.encoded_inner_bytes,
            max_packet_bytes: with_probe - TRAILING_PROBE_BYTES,
            max_packet_and_probe_bytes: with_probe,
            max_decoder_cumulative_bytes: self.envelope.decoded_cumulative_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
