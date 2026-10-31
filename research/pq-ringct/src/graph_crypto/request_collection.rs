//! A closed, pre-admitted collection of the graph's three SHAKE requests.
//!
//! The immutable source graph/fixture and authenticated profile already exist
//! and require separate enclosing admission. This owner covers its new request
//! copies, serialization workspace and collection metadata, never full E_graph.
//! This CPU-reference serializer issues no proving or GPU execution receipt.

use super::{request_owner, Policy, Request, ReservedShakeRequest, ShakeRequestPlan};
use crate::{
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    rust_verify::{
        committed_backend::{
            Operation, PolynomialKind, PolynomialValues, TranscriptPart, UnprovedRelationGraph,
        },
        D, Q, QHAT,
    },
};
use core::mem::size_of;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

const COUNT: usize = 3;
const MAX_TRANSCRIPT_PARTS: usize = 256;
const PP_DOMAIN: &[u8] = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1";
const PP_INPUT_BYTES: usize = PP_DOMAIN.len() + 32 + 32;
const SERIALIZER_FIXED_BYTES: usize =
    size_of::<Vec<u8>>() + size_of::<Shake256>() + size_of::<Shake256Reader>() + 49 + 32 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    MissingRequest,
    RequestOrder,
    SetupIdentity,
    SourceIdentity,
    ProfileIdentity,
    TranscriptParts,
    PolynomialKind,
    Noncanonical,
    Overflow,
    WrongLedger,
    WrongReservation,
    SourceChanged,
    Request(request_owner::Error),
}
impl From<request_owner::Error> for Error {
    fn from(error: request_owner::Error) -> Self {
        Self::Request(error)
    }
}
type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    ParametersPp,
    HashAlpha,
    HashX,
}
impl Kind {
    pub(crate) const ALL: [Self; COUNT] = [Self::ParametersPp, Self::HashAlpha, Self::HashX];

    fn ordinal(self) -> usize {
        match self {
            Self::ParametersPp => 0,
            Self::HashAlpha => 1,
            Self::HashX => 2,
        }
    }

    fn output_len(self) -> usize {
        if self == Self::HashX {
            137
        } else {
            32
        }
    }

    fn of(operation: &Operation) -> Option<Self> {
        match operation {
            Operation::ParametersPp { .. } => Some(Self::ParametersPp),
            Operation::HashAlpha { .. } => Some(Self::HashAlpha),
            Operation::HashX { .. } => Some(Self::HashX),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Entry {
    kind: Kind,
    operation: usize,
    input_len: usize,
    requirement: Requirements,
    request_bounds: request_owner::Bounds,
}

/// Fixed source-derived requested storage, not observed capacity or RSS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    pub(crate) input_bytes: [usize; COUNT],
    pub(crate) native_segments: [usize; COUNT],
    pub(crate) serialization_buffer_bytes: usize,
    pub(crate) serialization_temporary_bytes: usize,
    pub(crate) retained_bytes: u64,
    pub(crate) admitted_bytes: u64,
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}

fn combine(into: &mut Requirements, other: Requirements) -> Result<()> {
    for category in Category::ALL {
        into.add(category, other.get(category))
            .map_err(|_| Error::Overflow)?;
    }
    Ok(())
}

fn canonical_values<'a>(
    kind: PolynomialKind,
    values: &'a PolynomialValues,
) -> Result<&'a [u64; D]> {
    let PolynomialKind::Canonical { modulus } = kind else {
        return Err(Error::PolynomialKind);
    };
    if !matches!(modulus, Q | QHAT) {
        return Err(Error::PolynomialKind);
    }
    let PolynomialValues::Canonical(values) = values else {
        return Err(Error::PolynomialKind);
    };
    if values
        .iter()
        .any(|&value| value >= modulus || value > u32::MAX as u64)
    {
        return Err(Error::Noncanonical);
    }
    Ok(values)
}

fn source_length(graph: &UnprovedRelationGraph, operation: &Operation) -> Result<usize> {
    match operation {
        Operation::ParametersPp {
            setup_seed,
            context,
            ..
        } => {
            if *setup_seed != graph.setup_seed() {
                return Err(Error::SetupIdentity);
            }
            // IDs are opaque and belong to this immutable graph. Its accessor
            // enforces that invariant; no caller-supplied operation is accepted.
            let _ = graph.byte_string(*context);
            Ok(PP_INPUT_BYTES)
        }
        Operation::HashAlpha { parts, .. } | Operation::HashX { parts, .. } => {
            if parts.is_empty() || parts.len() > MAX_TRANSCRIPT_PARTS {
                return Err(Error::TranscriptParts);
            }
            let mut length = 0;
            for part in parts {
                let bytes = match part {
                    TranscriptPart::Bytes(id) => {
                        let _ = graph.byte_string(*id);
                        32
                    }
                    TranscriptPart::Polynomial(id) => {
                        let node = graph.polynomial(*id);
                        canonical_values(node.kind, &node.values)?;
                        4 * D
                    }
                };
                length = add(length, bytes)?;
            }
            Ok(length)
        }
        _ => Err(Error::SourceChanged),
    }
}

/// No heap allocation, graph clone, manifest construction or serialization.
/// The exact graph borrow and profile are fixed here and cannot be replaced
/// during construction. Profile authentication is a separate graph obligation.
pub(crate) struct GraphShakeCollectionPlan<'graph> {
    graph: &'graph UnprovedRelationGraph,
    profile: [u8; 32],
    policy: Policy,
    entries: [Entry; COUNT],
    metadata: Requirements,
    temporary: Requirements,
    retained: Requirements,
    whole: Requirements,
    bounds: Bounds,
}

impl<'graph> GraphShakeCollectionPlan<'graph> {
    pub(crate) fn new(
        profile: [u8; 32],
        graph: &'graph UnprovedRelationGraph,
        policy: Policy,
    ) -> Result<Self> {
        let mut entries = [None; COUNT];
        let mut found = 0;
        let mut retained = Requirements::default();
        let mut maximum_input = 0;
        for (operation_index, operation) in graph.operations().iter().enumerate() {
            let Some(kind) = Kind::of(operation) else {
                continue;
            };
            if Kind::ALL.get(found) != Some(&kind) {
                return Err(Error::RequestOrder);
            }
            let input_len = source_length(graph, operation)?;
            let (_, request_bounds, requirement) = ShakeRequestPlan::source_geometry(
                operation_index,
                0,
                input_len,
                kind.output_len(),
                policy,
            )?;
            combine(&mut retained, requirement)?;
            maximum_input = maximum_input.max(input_len);
            entries[found] = Some(Entry {
                kind,
                operation: operation_index,
                input_len,
                requirement,
                request_bounds,
            });
            found += 1;
        }
        if found != COUNT {
            return Err(Error::MissingRequest);
        }
        let entries = entries.map(|entry| entry.expect("fixed complete SHAKE inventory"));
        // Conservatively charge fixed construction/ownership headers as well
        // as all request-owner headers already present in their own recipes.
        let metadata_bytes = add(
            add(
                size_of::<Self>(),
                size_of::<ReservedGraphShakeRequests<'graph>>(),
            )?,
            size_of::<[Option<ReservedShakeRequest>; COUNT]>(),
        )?;
        let metadata = Requirements::single(
            Category::RegisteredMetadata,
            Bytes {
                host: u64::try_from(metadata_bytes).map_err(|_| Error::Overflow)?,
                device: 0,
            },
        );
        combine(&mut retained, metadata)?;
        let serialization_temporary_bytes = add(maximum_input, SERIALIZER_FIXED_BYTES)?;
        let temporary = Requirements::single(
            Category::CompilerInputs,
            Bytes {
                host: u64::try_from(serialization_temporary_bytes).map_err(|_| Error::Overflow)?,
                device: 0,
            },
        );
        let mut whole = retained;
        combine(&mut whole, temporary)?;
        let bounds = Bounds {
            input_bytes: entries.map(|entry| entry.input_len),
            native_segments: entries.map(|entry| entry.request_bounds.selected_segments),
            serialization_buffer_bytes: maximum_input,
            serialization_temporary_bytes,
            retained_bytes: retained.total().map_err(|_| Error::Overflow)?.host,
            admitted_bytes: whole.total().map_err(|_| Error::Overflow)?.host,
        };
        Ok(Self {
            graph,
            profile,
            policy,
            entries,
            metadata,
            temporary,
            retained,
            whole,
            bounds,
        })
    }

    pub(crate) fn requirements(&self) -> Requirements {
        self.whole
    }
    pub(crate) fn retained_requirements(&self) -> Requirements {
        self.retained
    }
    pub(crate) fn bounds(&self) -> Bounds {
        self.bounds
    }

    pub(crate) fn construct(
        self,
        mut reservation: Reservation,
        ledger: &Ledger,
    ) -> Result<ReservedGraphShakeRequests<'graph>> {
        if !reservation.belongs_to(ledger) {
            return Err(Error::WrongLedger);
        }
        let allowance = ledger.snapshot().allowance;
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device > 8u64 << 30
            || reservation.requirements() != self.whole
        {
            return Err(Error::WrongReservation);
        }
        let metadata = reservation
            .split(self.metadata)
            .map_err(|_| Error::WrongReservation)?;
        let temporary = reservation
            .split(self.temporary)
            .map_err(|_| Error::WrongReservation)?;
        // Locals are declared in token-before-data order. Every error or unwind
        // destroys serialized bytes and completed children before those tokens.
        let mut requests: [Option<ReservedShakeRequest>; COUNT] = core::array::from_fn(|_| None);
        let mut serialized = Vec::with_capacity(self.bounds.serialization_buffer_bytes);
        for entry in self.entries {
            let token = reservation
                .split(entry.requirement)
                .map_err(|_| Error::WrongReservation)?;
            serialized.clear();
            serialize(self.graph, entry, &mut serialized)?;
            let plan = ShakeRequestPlan::new(
                self.profile,
                entry.operation,
                0,
                &serialized,
                entry.kind.output_len(),
                self.policy,
            )?;
            if plan.requirements() != entry.requirement || plan.bounds() != entry.request_bounds {
                return Err(Error::SourceChanged);
            }
            let request = plan.construct(token, ledger)?;
            requests[entry.kind.ordinal()] = Some(request);
        }
        // The original serialization copy is gone before its own reservation.
        drop(serialized);
        drop(temporary);
        debug_assert_eq!(reservation.requirements(), Requirements::default());
        drop(reservation);
        Ok(ReservedGraphShakeRequests {
            requests: requests
                .map(|request| request.expect("constructed complete SHAKE inventory")),
            graph: self.graph,
            profile: self.profile,
            bounds: self.bounds,
            metadata,
        })
    }
}

fn append(out: &mut Vec<u8>, bytes: &[u8], expected: usize) -> Result<()> {
    if add(out.len(), bytes.len())? > expected || expected > out.capacity() {
        return Err(Error::SourceChanged);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// The closed encoding matches pp_input_bytes and TranscriptAir::serialize,
/// without allocating their intermediate kinds/values/roots/word Vecs.
fn serialize(graph: &UnprovedRelationGraph, entry: Entry, out: &mut Vec<u8>) -> Result<()> {
    let operation = graph
        .operations()
        .get(entry.operation)
        .ok_or(Error::SourceChanged)?;
    if Kind::of(operation) != Some(entry.kind) {
        return Err(Error::SourceChanged);
    }
    match operation {
        Operation::ParametersPp {
            setup_seed,
            context,
            ..
        } => {
            if *setup_seed != graph.setup_seed() {
                return Err(Error::SetupIdentity);
            }
            let mut setup = [0u8; 49];
            setup[..32].copy_from_slice(setup_seed);
            setup[32..38].copy_from_slice(&[64, 4, 4, 4, 5, 5]);
            setup[38..40].copy_from_slice(&256u16.to_le_bytes());
            setup[40..44].copy_from_slice(&(Q as u32).to_le_bytes());
            setup[44..48].copy_from_slice(&(QHAT as u32).to_le_bytes());
            setup[48] = 44;
            let mut state = Shake256::default();
            state.update(&setup);
            let mut reader = state.finalize_xof();
            let mut digest = [0; 32];
            reader.read(&mut digest);
            append(out, PP_DOMAIN, entry.input_len)?;
            append(out, &digest, entry.input_len)?;
            append(out, &graph.byte_string(*context).values, entry.input_len)?;
        }
        Operation::HashAlpha { parts, .. } | Operation::HashX { parts, .. } => {
            if parts.is_empty() || parts.len() > MAX_TRANSCRIPT_PARTS {
                return Err(Error::TranscriptParts);
            }
            for part in parts {
                match part {
                    TranscriptPart::Bytes(id) => {
                        append(out, &graph.byte_string(*id).values, entry.input_len)?
                    }
                    TranscriptPart::Polynomial(id) => {
                        let node = graph.polynomial(*id);
                        for &value in canonical_values(node.kind, &node.values)? {
                            append(out, &(value as u32).to_le_bytes(), entry.input_len)?;
                        }
                    }
                }
            }
        }
        _ => return Err(Error::SourceChanged),
    }
    if out.len() != entry.input_len {
        return Err(Error::SourceChanged);
    }
    Ok(())
}

/// Every child payload precedes its own token; the complete array precedes
/// collection metadata. The source graph is only borrowed, never charged here.
pub(crate) struct ReservedGraphShakeRequests<'graph> {
    requests: [ReservedShakeRequest; COUNT],
    graph: &'graph UnprovedRelationGraph,
    profile: [u8; 32],
    bounds: Bounds,
    metadata: Reservation,
}
impl ReservedGraphShakeRequests<'_> {
    /// Borrowing keeps all request and collection charges live through native
    /// owners, compiler output and synchronous actual-context phase cleanup.
    pub(crate) fn request_for(
        &self,
        graph: &UnprovedRelationGraph,
        profile: [u8; 32],
        kind: Kind,
    ) -> Result<&Request> {
        if !core::ptr::eq(self.graph, graph) {
            return Err(Error::SourceIdentity);
        }
        if self.profile != profile {
            return Err(Error::ProfileIdentity);
        }
        Ok(self.requests[kind.ordinal()].request())
    }

    pub(crate) fn bounds(&self) -> Bounds {
        self.bounds
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.metadata.belongs_to(ledger)
            && self
                .requests
                .iter()
                .all(|request| request.belongs_to(ledger))
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
