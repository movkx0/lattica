//! Inactive, consuming transport check of the final root owned by one Component.
//!
//! No packet, decoded proof, verifier, acceptance or runtime continuation escapes.
//! This draft has no module wiring or driver. Its future driver must reserve A's
//! complete transport owner before Attempt/PendingNative; Source+Ledger and the
//! constructor name alone do not enforce that temporal order.
use super::*;
use crate::component_tree::{NodeKey, NodeProof, Spec, HEADER};
use lattica_prover_p3::block_v2::codec;

mod admission;
mod header;

pub(super) use admission::PreissuedRootTransport;
use header::{HeaderProbeReport, RootHeaderValues, HEADER_BYTES, PACKET_LIMIT};

type TransportResult<T> = core::result::Result<T, ParentCompileError>;
const PUBLICS: usize = HEADER + 8;
const ROOT_ORDINAL: usize = PARENTS - 1;

// Fixed observations only, with no derived Clone/Copy. They remain borrowed
// from the original-ledger report owner through their last reporting use.
pub(in crate::component_tree::owned_shake) struct RootTransportMeasurements {
    pub(in crate::component_tree::owned_shake) cpu_heights: usize,
    pub(in crate::component_tree::owned_shake) codec_heights: usize,
    pub(in crate::component_tree::owned_shake) packet_bytes: usize,
    pub(in crate::component_tree::owned_shake) inner_bytes: usize,
    pub(in crate::component_tree::owned_shake) positive_checks: usize,
    pub(in crate::component_tree::owned_shake) header_probes: HeaderProbeReport,
    pub(in crate::component_tree::owned_shake) original_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) encoding_ns: u128,
    pub(in crate::component_tree::owned_shake) header_checks_ns: u128,
    pub(in crate::component_tree::owned_shake) decoding_ns: u128,
    pub(in crate::component_tree::owned_shake) decoded_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) reencoding_ns: u128,
    // Actual action interval: first numerical verification through packet
    // destruction. Excludes preissue, prior proving and final root destruction.
    pub(in crate::component_tree::owned_shake) elapsed_ns: u128,
}

pub(super) struct RetainedRootTransportReport<'bound, 'source, 'request> {
    measurements: RootTransportMeasurements,
    original: PreissuedRootTransport<'bound, 'source, 'request>,
}

impl RetainedRootTransportReport<'_, '_, '_> {
    pub(super) fn measurements(
        &self,
        ledger: &Ledger,
    ) -> TransportResult<&RootTransportMeasurements> {
        self.original.check(ledger)?;
        Ok(&self.measurements)
    }
}

// Only this private module constructs the action. An immutable output adapter
// supplies its own original fields, and this action checks the exact owner.
// Neither arbitrary callbacks nor externally paired root/originals are used.
pub(in crate::component_tree::owned_shake) struct RootTransportAction<
    'phase,
    'bound,
    'source,
    'request,
> {
    child: &'phase AcceptedChild<'bound, 'source, 'request>,
    transport: &'phase PreissuedRootTransport<'bound, 'source, 'request>,
    ledger: &'phase Ledger,
}

impl<'bound, 'source, 'request> Component<'bound, 'source, 'request> {
    pub(super) fn roundtrip_root(
        self,
        transport: PreissuedRootTransport<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> TransportResult<RetainedRootTransportReport<'bound, 'source, 'request>> {
        transport.check(ledger)?;
        let source = transport.source();
        let retirement = self
            .originals
            .check(source.request.owner, ledger)
            .map_err(|_| ParentCompileError::Authority)?;
        let accepted = self.root.report();
        if !self.caller.belongs_to(ledger)
            || self.report.native_proofs != NATIVE
            || self.report.leaf_proofs != LEAVES
            || self.report.parent_proofs != PARENTS
            || self.report.workflow_admitted
            || self
                .originals
                .outer_step()
                .map_err(|_| ParentCompileError::Authority)?
                != HashxOuterStep::Parent3
            || accepted.parent != ROOT_ORDINAL
            || accepted.retirement != retirement
            || !accepted.source_key_authenticated
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
        {
            return Err(ParentCompileError::Authority);
        }
        let child = AcceptedChild::Parent(self.root);
        child.check_original(
            source,
            super::super::super::SourceNode::Parent(ROOT_ORDINAL),
            ledger,
        )?;
        let action = RootTransportAction {
            child: &child,
            transport: &transport,
            ledger,
        };
        let measurements = child.output().roundtrip_root_transport(&action)?;
        drop(action);
        // Every temporary packet/decoded object already died inside the
        // action. Destroy the actual root under its original claim while the
        // additive transport reservation and this Component's support/caller
        // remain live. The final diagnostics retain the transport originals.
        drop(child);
        Ok(RetainedRootTransportReport {
            measurements,
            original: transport,
        })
    }
}

fn packet() -> TransportResult<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(PACKET_LIMIT)
        .map_err(|_| ParentCompileError::Capacity)?;
    if result.capacity() != PACKET_LIMIT {
        return Err(ParentCompileError::Capacity);
    }
    result.resize(PACKET_LIMIT, 0);
    Ok(result)
}

impl RootTransportAction<'_, '_, '_, '_> {
    // Called only by the closed retained-output adapter with its own fields.
    // The encoder borrows the original proof. The sole decoded proof stays
    // local under the original transport reservation and is never returned.
    pub(in crate::component_tree::owned_shake) fn roundtrip_original(
        &self,
        owner: &output::RetainedNodeOutput<'_>,
        key: &NodeKey,
        proof: &NodeProof,
        request: &ReservedShakeRequest,
    ) -> TransportResult<RootTransportMeasurements> {
        self.transport.check(self.ledger)?;
        let source = self.transport.source();
        if !core::ptr::eq(owner, self.child.output())
            || !core::ptr::eq(self.child.source(), source)
            || !core::ptr::eq(request, source.request.owner)
            || !owner.belongs_to(self.ledger)
            || &key.spec != self.transport.expected_spec()
            || key.height != self.child.height()
            || key.cap.as_slice() != &self.child.cap()[..]
            || key.cap.capacity() != super::super::super::super::ROOTS
            || proof.public.len() != PUBLICS
            || proof.public[..HEADER] != self.transport.expected_header()[..]
        {
            return Err(ParentCompileError::Source);
        }
        let public: &[Val; PUBLICS] = proof
            .public
            .as_slice()
            .try_into()
            .map_err(|_| ParentCompileError::Source)?;
        let values = RootHeaderValues {
            height: key.height,
            public,
            cap: self.child.cap(),
        };
        let shape = self
            .transport
            .envelope()
            .cases
            .iter()
            .find(|case| case.rows == key.height)
            .ok_or(ParentCompileError::Source)?;
        let started = std::time::Instant::now();
        let positive_started = std::time::Instant::now();
        key.verifier
            .verify_classified(&proof.proof, public)
            .map_err(|_| ParentCompileError::Source)?;
        let original_verification_ns = positive_started.elapsed().as_nanos();

        // A's caller and payload claims already cover both full outer packets,
        // the full bounded decoder/canonical quota, and the retained original
        // proof/key/runtime separately. No admission happens in this action.
        let mut encoded = packet()?;
        let mut canonical = packet()?;
        let encoding_started = std::time::Instant::now();
        let inner_bytes = codec::encode_registered_proof_into(
            &proof.proof,
            &mut encoded[HEADER_BYTES..],
        )
        .map_err(|_| ParentCompileError::Source)?
        .len();
        if inner_bytes > shape.encoded_inner_bytes {
            return Err(ParentCompileError::Source);
        }
        let packet_bytes = HEADER_BYTES
            .checked_add(inner_bytes)
            .ok_or(ParentCompileError::Overflow)?;
        // Preissue checks this for all 18 conservative shapes, including the
        // one extra trailing-byte probe inside the same full-packet allowance.
        if packet_bytes >= PACKET_LIMIT {
            return Err(ParentCompileError::Capacity);
        }
        header::encode_header(values, inner_bytes, &mut encoded[..HEADER_BYTES])
            .map_err(|_| ParentCompileError::Source)?;
        let encoding_ns = encoding_started.elapsed().as_nanos();

        let header_started = std::time::Instant::now();
        let checked = header::validate_packet(&encoded[..packet_bytes], values)
            .map_err(|_| ParentCompileError::Source)?;
        let initial_header_ns = header_started.elapsed().as_nanos();
        let decoding_started = std::time::Instant::now();
        let decoded = codec::decode_registered_proof_bounded(
            checked.inner(),
            self.transport.decoder_limit(),
        )
        // Core postcard errors conflate codec/storage/allocation failures.
        // This ordinary-path error earns no negative or storage-only credit.
        .map_err(|_| ParentCompileError::Source)?;
        let decoding_ns = decoding_started.elapsed().as_nanos();
        let positive_started = std::time::Instant::now();
        key.verifier
            .verify_classified(&decoded, public)
            .map_err(|_| ParentCompileError::Source)?;
        let decoded_verification_ns = positive_started.elapsed().as_nanos();

        let reencoding_started = std::time::Instant::now();
        let canonical_inner = codec::encode_registered_proof_into(
            &decoded,
            &mut canonical[HEADER_BYTES..],
        )
        .map_err(|_| ParentCompileError::Source)?
        .len();
        if canonical_inner != inner_bytes {
            return Err(ParentCompileError::Source);
        }
        header::encode_header(values, canonical_inner, &mut canonical[..HEADER_BYTES])
            .map_err(|_| ParentCompileError::Source)?;
        if canonical[..packet_bytes] != encoded[..packet_bytes] {
            return Err(ParentCompileError::Source);
        }
        let reencoding_ns = reencoding_started.elapsed().as_nanos();
        drop(decoded);

        // These mutate only packet2 after canonical equality, never packet1 or
        // either proof. They observe typed framing/binding refusals and have
        // no cryptographic mutation/relation-rejection meaning.
        let header_started = std::time::Instant::now();
        let header_probes =
            header::probe_packet(&encoded[..packet_bytes], &mut canonical, values)
                .map_err(|_| ParentCompileError::Source)?;
        let header_checks_ns = initial_header_ns
            .checked_add(header_started.elapsed().as_nanos())
            .ok_or(ParentCompileError::Overflow)?;
        drop(canonical);
        drop(encoded);
        Ok(RootTransportMeasurements {
            cpu_heights: self.transport.cpu_heights(),
            codec_heights: self.transport.envelope().cases.len(),
            packet_bytes,
            inner_bytes,
            positive_checks: 2,
            header_probes,
            original_verification_ns,
            encoding_ns,
            header_checks_ns,
            decoding_ns,
            decoded_verification_ns,
            reencoding_ns,
            elapsed_ns: started.elapsed().as_nanos(),
        })
    }
}
