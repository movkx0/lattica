//! Fresh configuration census for the fixed private-note research profile.
//! Worker policy overrides are refused before construction and rechecked around
//! the existing activation checks. No configuration or dispatch API is public.
use super::{add, mul, Error, Geometry, PreparedNote};
use crate::block_v2::{
    extension_mmcs::CandidateExtensionMmcs,
    gpu_hash::{device, CandidateMmcs},
    normalization_workspace::HeapNormalizedDft,
    pcs_field::ProvingConfig,
    profile,
    randomness::ProofRng,
    resident_pcs::ResidentState,
    wallet_worker,
};
use crate::config::{Challenge, MyCompress, MyHash, Val, ValMmcs};
use crate::note_research_quota::Reservation;
use device::note_runtime::NoteDeviceLease;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_uni_stark::StarkGenericConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Pinned Rust ArcInner allocation-request layout. Keep the helper local so
// unsupported/debug builds still compile and fail through Geometry::pinned,
// rather than depending on the release-only verifier helper's cfg visibility.
fn arc_bytes<T>() -> usize {
    #[repr(C)]
    struct Allocation<T> {
        _strong: std::sync::atomic::AtomicUsize,
        _weak: std::sync::atomic::AtomicUsize,
        _value: T,
    }
    core::mem::size_of::<Allocation<T>>()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ConfigurationCensus {
    permutation_backing_bytes: usize,
    cpu_mmcs_backing_bytes: usize,
    shared_rng_backing_bytes: usize,
    empty_dft_cache_backing_bytes: usize,
    resident_state_backing_bytes: usize,
    device_rng_backing_bytes: usize,
    runtime_host_envelope_bytes: usize,
    inline_configuration_and_seeds_bytes: usize,
    retained_and_known_temporary_bytes: usize,
    // Zero is valid only under the private policy-absence capability below.
    worker_policy_parse_peak_bytes: Option<usize>,
    policy_override_refusal_required: bool,
    complete_creation_admitted: bool,
}

impl ConfigurationCensus {
    /// Source-pinned to the existing fresh resident constructor, not a new
    /// cryptographic configuration. Successful planning allocates nothing and
    /// reads neither entropy, environment, worker files nor device state.
    pub fn new() -> Result<Self, Error> {
        Geometry::pinned()?;
        // Same pinned Arc/cache layout already used by profile::verification.
        #[repr(C)]
        struct EmptyCache {
            _lock: std::sync::atomic::AtomicUsize,
            _map: std::collections::BTreeMap<usize, usize>,
        }
        // Initial permutation, hash/compress clones, one FRI MMCS clone and
        // ResidentState's independent opening-FRI MMCS snapshot: 1+2+2+2.
        let permutation_backing_bytes = 7 * (32 + 22 + 32) * 8;
        let cpu_mmcs_backing_bytes = mul(3, arc_bytes::<ValMmcs>())?;
        // Three MMCS snapshots, one hiding stream, one independent quotient
        // stream. Arc clones used by active consumers do not duplicate RNGs.
        let shared_rng_backing_bytes = mul(5, ProofRng::host_storage_bytes())?;
        let empty_dft_cache_backing_bytes = mul(6, arc_bytes::<EmptyCache>())?;
        let resident_state_backing_bytes = add(
            arc_bytes::<ResidentState<Challenge>>(),
            arc_bytes::<std::sync::atomic::AtomicBool>(),
        )?;
        // Original salts, opening-FRI salts, hiding, quotient. The reference
        // FRI snapshot remains host-side and is not an additional GPU stream.
        let device_rng_backing_bytes = mul(4, device::retained_stream_host_backing())?;
        // Maintained pure core census: engine metadata/staging, the session,
        // maximum transcript family and its shared scratch quota. Reserving
        // this throughout creation deliberately includes the future second
        // challenger. It remains additive to proof payloads and driver limits.
        let runtime_host_envelope_bytes =
            device::opening_runtime_host_bound().map_err(|_| Error::ResourceLimit)?;
        let inline_configuration_and_seeds_bytes = add(
            core::mem::size_of::<NoteConfiguration>(),
            core::mem::size_of::<FreshSeeds>(),
        )?;
        let mut retained_and_known_temporary_bytes = 0;
        for bytes in [
            permutation_backing_bytes,
            cpu_mmcs_backing_bytes,
            shared_rng_backing_bytes,
            empty_dft_cache_backing_bytes,
            resident_state_backing_bytes,
            device_rng_backing_bytes,
            runtime_host_envelope_bytes,
            inline_configuration_and_seeds_bytes,
        ] {
            retained_and_known_temporary_bytes = add(retained_and_known_temporary_bytes, bytes)?;
        }
        Ok(Self {
            permutation_backing_bytes,
            cpu_mmcs_backing_bytes,
            shared_rng_backing_bytes,
            empty_dft_cache_backing_bytes,
            resident_state_backing_bytes,
            device_rng_backing_bytes,
            runtime_host_envelope_bytes,
            inline_configuration_and_seeds_bytes,
            retained_and_known_temporary_bytes,
            worker_policy_parse_peak_bytes: Some(0),
            policy_override_refusal_required: true,
            complete_creation_admitted: false,
        })
    }

    pub fn known_payload_bytes(self) -> usize {
        self.retained_and_known_temporary_bytes
    }

    pub fn require_complete_creation(self) -> Result<(), Error> {
        Err(Error::IncompleteLifetimeAdmission)
    }

    /// Internal only. A real same-ledger charge and an already acquired device
    /// capacity owner are required. The exact operation allowance comes from
    /// preparation, so public preprocessing cannot be lent again to PCS work.
    /// This function still grants no public proving or complete-lifetime entry.
    pub(super) fn create_under_reservation(
        self,
        reservation: Reservation,
        prepared: &PreparedNote<'_>,
        mut lease: NoteDeviceLease,
    ) -> Result<NoteConfiguration, Error> {
        if self != Self::new()?
            || reservation.reserved_bytes() < self.known_payload_bytes()
            || !prepared.same_ledger(&reservation)
            || !lease.same_ledger(&reservation)
        {
            return Err(Error::ResourceLimit);
        }
        let operation_allowance = prepared.operation_host_allowance()?;
        if operation_allowance == 0 || operation_allowance > 24 << 30 {
            return Err(Error::ResourceLimit);
        }
        let policy = WorkerPolicyAbsent::capture()?;
        // Keep the original constructor's activation validation. Absence only
        // excludes unbounded policy parsing; it does not bypass enforcement.
        crate::block_v2::challenger::resources::check_worker(true)
            .map_err(|_| Error::Configuration)?;
        policy.recheck()?;
        lease
            .begin_configuration()
            .map_err(|_| Error::Configuration)?;
        let FreshSeeds {
            salts,
            hiding,
            quotient,
        } = FreshSeeds::new(self.inline_configuration_and_seeds_bytes)?;
        let permutation = default_goldilocks_poseidon2_8();
        let mmcs = CandidateMmcs::new(
            MyHash::new(permutation.clone()),
            MyCompress::new(permutation.clone()),
            profile::CAP_HEIGHT,
            salts,
        );
        let extension = CandidateExtensionMmcs::<Val, Challenge, _>::new(mmcs.clone());
        let mut parameters = profile::fri(extension);
        parameters.max_log_arity = 4;
        parameters.num_queries = 96;
        let pcs = crate::block_v2::quotient_pcs::CandidatePcs::<Challenge>::new_resident(
            HeapNormalizedDft::default(),
            mmcs,
            parameters,
            profile::NUM_RANDOM_CODEWORDS,
            hiding,
            operation_allowance,
        )
        .map_err(|_| Error::Configuration)?
        .with_gpu_openings()
        .map_err(|_| Error::Configuration)?
        .with_fused_quotients(quotient);
        policy.recheck()?;
        let pcs = pcs
            .with_gpu_randomness()
            .map_err(|_| Error::Configuration)?;
        policy.recheck()?;
        let challenger = pcs
            .registered_gpu_challenger()
            .map_err(|_| Error::Configuration)?;
        policy.recheck()?;
        let configuration = ProvingConfig::<Challenge>::new(pcs, challenger);
        let session = configuration
            .pcs()
            .quotient_session()
            .map_err(|_| Error::Configuration)?;
        lease
            .bind_proof_session(&session)
            .map_err(|_| Error::Configuration)?;
        Ok(NoteConfiguration {
            configuration,
            lease,
            reservation,
        })
    }
}

/// The configuration cannot outlive its real cumulative payload charge. No
/// Clone, owned configuration escape or public proving method is provided.
pub(super) struct NoteConfiguration {
    configuration: ProvingConfig<Challenge>,
    // The bound session aliases configuration-owned storage. Keep the lease
    // inside this owner, so that alias cannot outlive the configuration charge.
    lease: NoteDeviceLease,
    // Last field: RNGs, MMCS, transcript/session and configuration storage drop
    // before their shared charge, including every fallible creation path.
    reservation: Reservation,
}

impl NoteConfiguration {
    pub(super) fn checked_config(
        &self,
        prepared: &PreparedNote<'_>,
    ) -> Result<&ProvingConfig<Challenge>, Error> {
        if !prepared.same_ledger(&self.reservation) {
            return Err(Error::ResourceLimit);
        }
        self.checked_reserved_config(&self.reservation, prepared.operation_host_allowance()?)
    }

    /// Continuation after the exact PreparedNote recording was consumed. Its
    /// original charge and checked operation allowance remain with NoteAttempt;
    /// there is no new ledger, numeric replacement token or owned-config exit.
    pub(super) fn checked_reserved_config(
        &self,
        preparation_reservation: &Reservation,
        operation_host_allowance: usize,
    ) -> Result<&ProvingConfig<Challenge>, Error> {
        if !preparation_reservation.same_ledger(&self.reservation)
            || !self.lease.same_ledger(&self.reservation)
            || self.configuration.pcs().host_output_budget() != operation_host_allowance
        {
            return Err(Error::ResourceLimit);
        }
        let session = self
            .configuration
            .pcs()
            .quotient_session()
            .map_err(|_| Error::Configuration)?;
        self.lease
            .check_session(&session)
            .map_err(|_| Error::Configuration)?;
        Ok(&self.configuration)
    }
}

/// Cannot be constructed outside this module and never accepts caller-provided
/// policy JSON. The guarded research process uses an explicit env -i whitelist.
/// Runtime selectors and the exclusive GPU lease remain separate obligations.
pub(crate) struct WorkerPolicyAbsent {
    _private: (),
}

impl WorkerPolicyAbsent {
    /// Capture under the enclosing configuration/selector reservation. This
    /// type has private fields and grants policy absence only, not host quota
    /// or GPU authority. Present overrides are refused before their parsing.
    pub(crate) fn capture() -> Result<Self, Error> {
        let absence = Self { _private: () };
        absence.recheck()?;
        Ok(absence)
    }

    pub(crate) fn recheck(&self) -> Result<(), Error> {
        if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some()
            || std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_some()
            || wallet_worker::is_assigned()
        {
            return Err(Error::WorkerPolicy);
        }
        Ok(())
    }
}

/// This material is neither Clone nor Debug, and cannot be requested through a
/// public API. The eventual sealed producer creates it only after reservation;
/// geometry/metadata planning must never consume it. No deterministic seed or
/// thread-local RNG path is provided.
pub(super) struct FreshSeeds {
    pub(super) salts: ChaCha20Rng,
    pub(super) hiding: ChaCha20Rng,
    pub(super) quotient: ChaCha20Rng,
}

impl FreshSeeds {
    pub(super) fn new(allowance: usize) -> Result<Self, Error> {
        if allowance < core::mem::size_of::<Self>() {
            return Err(Error::ResourceLimit);
        }
        let mut fresh = || {
            ChaCha20Rng::try_from_rng(&mut rand::rngs::SysRng)
                .map_err(|_| Error::EntropyUnavailable)
        };
        Ok(Self {
            salts: fresh()?,
            hiding: fresh()?,
            quotient: fresh()?,
        })
    }
}
