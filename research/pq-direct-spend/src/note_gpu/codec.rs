//! Bounded decoder for exactly postcard(Proof<config::MyConfig>).
//! This keeps the existing PQNOTE1 envelope and legacy quadratic encoding.
use super::{
    quota::{Quota, Reservation, LEDGER_BYTES},
    *,
};
use crate::{note, Context, Profile, GOLDILOCKS_MODULUS};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use serde::de::DeserializeSeed;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{cell::Cell, rc::Rc};

mod schema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DecodeReceipt {
    pub packet_capacity_bytes: usize,
    pub expected_statement_backing_bytes: usize,
    pub fixed_owner_bytes: usize,
    pub decoded_backing_ceiling_bytes: usize,
    pub decoded_backing_requested_bytes: usize,
    pub canonical_buffer_bytes: usize,
    pub reserved_bytes: usize,
    pub vector_allocations: usize,
    pub cryptographic_verification_performed: bool,
}

/// A bounded, canonical, shape-admitted artifact, not a verified transaction.
/// No Clone: every retained proof shares the enclosing session quota through
/// its unique reservation. Proof and packet fields are destroyed before it.
pub struct DecodedArtifact {
    proof: Proof,
    packet: Vec<u8>,
    public: [Val; 26],
    context: Context,
    receipt: DecodeReceipt,
    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    produced: Option<super::proving::qualification::RetainedProducer>,
    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    produced_cpu: Option<super::workflow::cpu::RetainedCpuProducer>,
    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    verification: Option<PreAdmittedScratch>,
    _reservation: Reservation,
}

impl DecodedArtifact {
    pub fn proof(&self) -> &Proof {
        &self.proof
    }
    pub fn canonical_packet(&self) -> &[u8] {
        &self.packet
    }
    pub fn public(&self) -> &[Val; 26] {
        &self.public
    }
    pub fn context(&self) -> Context {
        self.context
    }
    pub fn receipt(&self) -> DecodeReceipt {
        self.receipt
    }

    #[cfg(all(
        test,
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) fn mutate_opening_for_test(&mut self) {
        // A fixed negative test only: keep every owner and geometry intact,
        // change one authenticated opening, and require numerical rejection.
        self.proof.opened_values.trace_local[0] += Challenge::ONE;
    }

    // Only reviewed sibling planners may add temporary work to this exact
    // artifact's ledger. All other live decoded owners remain charged.
    pub(super) fn reserve_scratch(&self, bytes: usize) -> Result<ScratchGuard<'_>, Error> {
        #[cfg(all(
            feature = "note-gpu-proving-experiment",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        if let Some(scratch) = &self.verification {
            return scratch.borrow(&self._reservation, bytes);
        }
        Ok(ScratchGuard::Reserved {
            _reservation: self._reservation.reserve_related(bytes)?,
            _artifact: std::marker::PhantomData,
        })
    }

    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) fn retain_producer(
        &mut self,
        producer: super::proving::qualification::RetainedProducer,
        verification: PreAdmittedScratch,
    ) -> Result<(), Error> {
        if self.produced.is_some()
            || self.produced_cpu.is_some()
            || self.verification.is_some()
            || !producer.belongs_to(&self._reservation)
            || !verification.reservation.same_ledger(&self._reservation)
        {
            return Err(Error::ResourceLimit);
        }
        self.produced = Some(producer);
        self.verification = Some(verification);
        Ok(())
    }

    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) fn retain_cpu_producer(
        &mut self,
        producer: super::workflow::cpu::RetainedCpuProducer,
        verification: PreAdmittedScratch,
    ) -> Result<(), Error> {
        if self.produced.is_some()
            || self.produced_cpu.is_some()
            || self.verification.is_some()
            || !producer.belongs_to(&self._reservation)
            || !verification.reservation.same_ledger(&self._reservation)
        {
            return Err(Error::ResourceLimit);
        }
        self.produced_cpu = Some(producer);
        self.verification = Some(verification);
        Ok(())
    }

    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) fn retain_verification(
        &mut self,
        verification: PreAdmittedScratch,
    ) -> Result<(), Error> {
        if self.verification.is_some() || !verification.reservation.same_ledger(&self._reservation)
        {
            return Err(Error::ResourceLimit);
        }
        self.verification = Some(verification);
        Ok(())
    }

    pub(super) fn same_ledger(&self, reservation: &Reservation) -> bool {
        self._reservation.same_ledger(reservation)
    }
}

/// A verifier invocation either owns a new reservation from the artifact's
/// original ledger or exclusively borrows the producer's preceding claim.
/// Reentrant verification cannot spend one pre-admission twice.
pub(super) enum ScratchGuard<'a> {
    Reserved {
        _reservation: Reservation,
        _artifact: std::marker::PhantomData<&'a DecodedArtifact>,
    },
    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    PreAdmitted(&'a PreAdmittedScratch),
}

impl Drop for ScratchGuard<'_> {
    fn drop(&mut self) {
        #[cfg(all(
            feature = "note-gpu-proving-experiment",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        if let Self::PreAdmitted(scratch) = self {
            scratch.busy.set(false);
        }
    }
}

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(super) struct PreAdmittedScratch {
    busy: Cell<bool>,
    reservation: Reservation,
}

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
impl PreAdmittedScratch {
    pub(super) fn new(reservation: Reservation) -> Self {
        Self {
            busy: Cell::new(false),
            reservation,
        }
    }

    fn borrow(&self, original: &Reservation, bytes: usize) -> Result<ScratchGuard<'_>, Error> {
        if !self.reservation.same_ledger(original)
            || self.reservation.reserved_bytes() < bytes
            || self.busy.replace(true)
        {
            return Err(Error::ResourceLimit);
        }
        Ok(ScratchGuard::PreAdmitted(self))
    }
}

/// A shared budget across all simultaneously retained decoded artifacts.
/// The caller must use one session for owners sharing the same allowance.
/// Reservations survive dropping/moving the session because artifacts retain
/// its ledger. This is requested backing, not a complete process/RSS bound.
pub struct DecodeSession {
    quota: Rc<Quota>,
}

impl DecodeSession {
    pub fn new(host_allowance: usize) -> Result<Self, Error> {
        Ok(Self {
            quota: Quota::new(host_allowance)?,
        })
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        self.quota.snapshot()
    }

    /// Research producer stages share this exact ledger with decoded artifacts;
    /// they cannot reset the allowance while older owners remain live.
    pub(super) fn reserve_for_producer(&self, bytes: usize) -> Result<Reservation, Error> {
        self.quota.reserve(bytes).map_err(Into::into)
    }

    pub fn decode(
        &self,
        packet: Vec<u8>,
        expected: &note::Statement,
        context: Context,
    ) -> Result<DecodedArtifact, Error> {
        let geometry = Geometry::pinned()?;
        let required = requirements(&packet, expected, geometry)?;
        // Admit the packet's full actual capacity, expected caller backing,
        // complete decoder ceiling and temporary canonical re-encoding before
        // parsing or making even the first proof vector allocation.
        let reservation = self.quota.reserve(required.reserved_bytes)?;
        let packet = packet;
        let public = expected_public(expected, context)?;
        decode_reserved(
            reservation,
            packet,
            public,
            context,
            expected.public.capacity(),
        )
    }
}

/// Only this module and the fixed producer can supply authenticated publics.
/// The caller's actual token, never a numeric receipt, survives parsing and
/// moves into the artifact. Ordinary decode and GPU handoff share this code.
pub(super) fn decode_reserved(
    reservation: Reservation,
    packet: Vec<u8>,
    public: [Val; 26],
    context: Context,
    expected_capacity: usize,
) -> Result<DecodedArtifact, Error> {
    let geometry = Geometry::pinned()?;
    let payload_bytes = packet
        .len()
        .checked_sub(ARTIFACT_HEADER_BYTES)
        .ok_or(Error::MalformedArtifact)?;
    let required = requirements_for(
        payload_bytes,
        packet.capacity(),
        expected_capacity,
        geometry,
    )?;
    if reservation.reserved_bytes() < required.reserved_bytes {
        return Err(Error::ResourceLimit);
    }
    // Declare the owning payload after the token so failures/unwinds destroy
    // it before releasing the reservation, including the incoming packet.
    let packet = packet;
    header(&packet, &public, context)?;
    let payload = &packet[ARTIFACT_HEADER_BYTES..];
    let storage = Storage::new(required.decoded_backing_ceiling_bytes, payload.len());
    let mut decoder = postcard::Deserializer::from_bytes(payload);
    let proof = schema::Seed::<Proof>::new(&storage)
        .deserialize(&mut decoder)
        .map_err(|_| storage.error())?;
    if !decoder
        .finalize()
        .map_err(|_| Error::MalformedArtifact)?
        .is_empty()
    {
        return Err(Error::MalformedArtifact);
    }
    shape::check(&proof, geometry)?;
    let mut canonical = storage
        .reserve::<u8>(payload.len(), true)
        .map_err(|_| storage.error())?;
    canonical.resize(payload.len(), 0);
    if postcard::to_slice(&proof, &mut canonical).map_err(|_| Error::MalformedArtifact)? != payload
    {
        return Err(Error::NonCanonical);
    }
    drop(canonical);
    let receipt = DecodeReceipt {
        decoded_backing_requested_bytes: storage.vector_bytes.get(),
        vector_allocations: storage.allocations.get(),
        // The producer deliberately retains its larger preceding ceiling.
        reserved_bytes: reservation.reserved_bytes(),
        ..required
    };
    Ok(DecodedArtifact {
        proof,
        packet,
        public,
        context,
        receipt,
        #[cfg(all(
            feature = "note-gpu-proving-experiment",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        produced: None,
        #[cfg(all(
            feature = "note-gpu-proving-experiment",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        produced_cpu: None,
        #[cfg(all(
            feature = "note-gpu-proving-experiment",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        verification: None,
        _reservation: reservation,
    })
}

/// Exact conservative reservation required in an otherwise empty session,
/// including its ledger. Spare capacity in either input is charged in full.
pub fn decode_required_bytes(packet: &Vec<u8>, expected: &note::Statement) -> Result<usize, Error> {
    add(
        requirements(packet, expected, Geometry::pinned()?)?.reserved_bytes,
        LEDGER_BYTES,
    )
}

fn requirements(
    packet: &Vec<u8>,
    expected: &note::Statement,
    g: Geometry,
) -> Result<DecodeReceipt, Error> {
    let payload = packet
        .len()
        .checked_sub(ARTIFACT_HEADER_BYTES)
        .ok_or(Error::MalformedArtifact)?;
    if expected.public.len() != g.public_values {
        return Err(Error::MalformedArtifact);
    }
    requirements_for(payload, packet.capacity(), expected.public.capacity(), g)
}

pub(super) fn requirements_for(
    payload: usize,
    packet_capacity: usize,
    expected_capacity: usize,
    g: Geometry,
) -> Result<DecodeReceipt, Error> {
    if payload == 0
        || payload > MAX_PROOF_BYTES
        || expected_capacity < g.public_values
        || packet_capacity < add(ARTIFACT_HEADER_BYTES, payload)?
    {
        return Err(Error::MalformedArtifact);
    }
    let caller = mul(expected_capacity, core::mem::size_of::<u64>())?;
    let fixed = add(
        core::mem::size_of::<DecodedArtifact>(),
        core::mem::size_of::<Storage>(),
    )?;
    let decoded = g.decoded_backing_ceiling_bytes()?;
    let required = add(
        add(packet_capacity, caller)?,
        add(fixed, add(decoded, payload)?)?,
    )?;
    if add(required, LEDGER_BYTES)? > WORKER_HOST_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(DecodeReceipt {
        packet_capacity_bytes: packet_capacity,
        expected_statement_backing_bytes: caller,
        fixed_owner_bytes: fixed,
        decoded_backing_ceiling_bytes: decoded,
        decoded_backing_requested_bytes: 0,
        canonical_buffer_bytes: payload,
        reserved_bytes: required,
        vector_allocations: 0,
        cryptographic_verification_performed: false,
    })
}

pub(super) fn expected_public(
    expected: &note::Statement,
    context: Context,
) -> Result<[Val; 26], Error> {
    if expected.profile != Profile::PrivateNoteDirectV1 {
        return Err(Error::Profile);
    }
    if expected.context != context {
        return Err(Error::Context);
    }
    if expected.public.len() != 26 {
        return Err(Error::Statement);
    }
    if expected
        .public
        .iter()
        .any(|&value| value >= GOLDILOCKS_MODULUS)
    {
        return Err(Error::NonCanonical);
    }
    use lattica_prover_p3::joinsplit_air as js;
    if expected.public[js::PI_FEE] != 0
        || expected.public[js::PI_MINT] != 0
        || expected.public[js::PI_NF..js::PI_NF + 4]
            == expected.public[js::PI_NF + 4..js::PI_NF + 8]
    {
        return Err(Error::Statement);
    }
    // Same profile/context binding as context_binding, using only fixed stack
    // buffers. No temporary public Vec escapes the admitted decoder owner.
    let mut hash = Shake256::default();
    hash.update(Profile::PrivateNoteDirectV1.tag().as_bytes());
    hash.update(&context.0);
    let mut digest = [0u8; 32];
    hash.finalize_xof().read(&mut digest);
    for i in 0..4 {
        let word =
            u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().unwrap()) % GOLDILOCKS_MODULUS;
        if expected.public[js::PI_TXBIND + i] != word {
            return Err(Error::Context);
        }
    }
    Ok(std::array::from_fn(|i| Val::from_u64(expected.public[i])))
}

fn header(packet: &[u8], public: &[Val; 26], context: Context) -> Result<(), Error> {
    // requirements already admitted the complete fixed header and payload.
    if &packet[..8] != MAGIC {
        return Err(Error::Profile);
    }
    if packet[8..40] != context.0 {
        return Err(Error::Context);
    }
    for (i, value) in public.iter().enumerate() {
        let start = 40 + 8 * i;
        let word = u64::from_le_bytes(packet[start..start + 8].try_into().unwrap());
        if word >= GOLDILOCKS_MODULUS {
            return Err(Error::NonCanonical);
        }
        if word != value.as_canonical_u64() {
            return Err(Error::Statement);
        }
    }
    let length = u64::from_le_bytes(
        packet[ARTIFACT_HEADER_BYTES - 8..ARTIFACT_HEADER_BYTES]
            .try_into()
            .unwrap(),
    );
    if length != (packet.len() - ARTIFACT_HEADER_BYTES) as u64 {
        return Err(Error::MalformedArtifact);
    }
    Ok(())
}

struct Storage {
    vector_limit: usize,
    canonical_limit: usize,
    vector_bytes: Cell<usize>,
    canonical_bytes: Cell<usize>,
    allocations: Cell<usize>,
    items: Cell<usize>,
    failure: Cell<Option<Error>>,
}
impl Storage {
    fn new(vector_limit: usize, canonical_limit: usize) -> Self {
        Self {
            vector_limit,
            canonical_limit,
            vector_bytes: Cell::new(0),
            canonical_bytes: Cell::new(0),
            allocations: Cell::new(0),
            items: Cell::new(0),
            failure: Cell::new(None),
        }
    }
    fn reject(&self, error: Error) -> postcard::Error {
        if self.failure.get().is_none() {
            self.failure.set(Some(error));
        }
        postcard::Error::SerdeDeCustom
    }
    fn error(&self) -> Error {
        self.failure.get().unwrap_or(Error::MalformedArtifact)
    }
    fn item(&self) -> Result<(), postcard::Error> {
        let items = self
            .items
            .get()
            .checked_add(1)
            .ok_or_else(|| self.reject(Error::ResourceLimit))?;
        if items > 1 << 20 || self.failure.get().is_some() {
            return Err(self.reject(Error::ResourceLimit));
        }
        self.items.set(items);
        Ok(())
    }
    fn reserve<T>(&self, count: usize, canonical: bool) -> Result<Vec<T>, postcard::Error> {
        let bytes = count
            .checked_mul(core::mem::size_of::<T>())
            .ok_or_else(|| self.reject(Error::ResourceLimit))?;
        let (counter, limit) = if canonical {
            (&self.canonical_bytes, self.canonical_limit)
        } else {
            (&self.vector_bytes, self.vector_limit)
        };
        let next = counter
            .get()
            .checked_add(bytes)
            .ok_or_else(|| self.reject(Error::ResourceLimit))?;
        if next > limit || self.failure.get().is_some() {
            return Err(self.reject(Error::ResourceLimit));
        }
        counter.set(next);
        let mut values = Vec::new();
        if values.try_reserve_exact(count).is_err()
            || (core::mem::size_of::<T>() != 0 && values.capacity() != count)
        {
            return Err(self.reject(Error::ResourceLimit));
        }
        self.allocations
            .set(self.allocations.get() + usize::from(bytes != 0));
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn preadmitted_scratch_requires_original_ledger_capacity_and_exclusive_borrow() {
        let quota = Quota::new(LEDGER_BYTES + 128).unwrap();
        let original = quota.reserve(0).unwrap();
        let other = Quota::new(LEDGER_BYTES + 128).unwrap().reserve(0).unwrap();
        let scratch = PreAdmittedScratch::new(quota.reserve(128).unwrap());
        let before = quota.snapshot();
        assert!(scratch.borrow(&other, 128).is_err());
        assert!(scratch.borrow(&original, 129).is_err());
        assert!(!scratch.busy.get());
        let guard = scratch.borrow(&original, 128).unwrap();
        assert!(scratch.borrow(&original, 1).is_err());
        assert_eq!(quota.snapshot(), before);
        drop(guard);
        assert!(!scratch.busy.get());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = scratch.borrow(&original, 128).unwrap();
            panic!("fixed scratch unwind canary");
        }));
        assert!(panic.is_err());
        assert!(!scratch.busy.get());
        let guard = scratch.borrow(&original, 128).unwrap();
        drop(guard);
        drop(scratch);
        assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
    }

    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn reserved_decoder_transfers_original_token_without_a_replacement_admission() {
        let expected = super::super::tests::statement();
        let packet =
            super::super::tests::packet(&super::super::tests::fixture(&[4, 4, 4, 1]), &expected);
        let bytes = requirements(&packet, &expected, Geometry::pinned().unwrap())
            .unwrap()
            .reserved_bytes;
        let quota = Quota::new(LEDGER_BYTES + bytes).unwrap();
        let token = quota.reserve(bytes).unwrap();
        let public = expected_public(&expected, expected.context).unwrap();
        let before = quota.snapshot();
        let artifact = decode_reserved(
            token,
            packet,
            public,
            expected.context,
            expected.public.capacity(),
        )
        .unwrap();
        assert_eq!(quota.snapshot(), before);
        assert_eq!(artifact.receipt().reserved_bytes, bytes);
        assert_eq!(artifact.public(), &public);
        drop(artifact);
        assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
    }

    #[test]
    fn advertised_length_is_rejected_before_backing_allocation() {
        let storage = Storage::new(1 << 20, 0);
        let length = postcard::to_allocvec(&257usize).unwrap();
        let mut decoder = postcard::Deserializer::from_bytes(&length);
        assert!(schema::Seed::<Vec<Val>>::new(&storage)
            .deserialize(&mut decoder)
            .is_err());
        assert_eq!(storage.vector_bytes.get(), 0);
        assert_eq!(storage.allocations.get(), 0);
    }

    #[test]
    fn quadratic_values_decode_on_stack_and_reject_noncanonical_coefficients() {
        let value = Challenge::new([Val::from_u64(7), Val::from_u64(11)]);
        let bytes = postcard::to_allocvec(&value).unwrap();
        let storage = Storage::new(0, 0);
        let mut decoder = postcard::Deserializer::from_bytes(&bytes);
        let decoded = schema::Seed::<Challenge>::new(&storage)
            .deserialize(&mut decoder)
            .unwrap();
        assert_eq!(decoded, value);
        assert!(decoder.finalize().unwrap().is_empty());
        assert_eq!(storage.allocations.get(), 0);
        let bad = postcard::to_allocvec(&GOLDILOCKS_MODULUS).unwrap();
        let mut decoder = postcard::Deserializer::from_bytes(&bad);
        assert!(schema::Seed::<Val>::new(&storage)
            .deserialize(&mut decoder)
            .is_err());
        assert_eq!(storage.allocations.get(), 0);
    }

    #[test]
    fn nested_allocations_accumulate_without_reusing_the_same_allowance() {
        let nested = vec![vec![Val::ZERO; 4]; 2];
        let bytes = postcard::to_allocvec(&nested).unwrap();
        let exact = 2 * core::mem::size_of::<Vec<Val>>() + 8 * core::mem::size_of::<Val>();
        for limit in [exact - 1, exact] {
            let storage = Storage::new(limit, 0);
            let mut decoder = postcard::Deserializer::from_bytes(&bytes);
            let result = schema::Seed::<Vec<Vec<Val>>>::new(&storage).deserialize(&mut decoder);
            assert_eq!(result.is_ok(), limit == exact);
            assert!(storage.vector_bytes.get() <= limit);
            if result.is_ok() {
                assert_eq!(storage.vector_bytes.get(), exact);
            }
        }
    }
}
