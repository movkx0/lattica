//! Executable internal fixed-note qualification path. The real original ledger
//! pays before selection, Context/Program, configuration or private work. This
//! qualification entry does not grant production dispatch or claim an opaque heap/stack
//! census: the unchanged external process/VRAM guard still owns that envelope.
use super::{
    add, config::ConfigurationCensus, preparation::NoteCompletion, preparation::OperationResources,
    selection::NoteSelection, Error, Geometry, PreparedNote,
};
use crate::block_v2::{
    gpu_hash::{self, device::note_runtime::NoteDevicePlan, device::DeviceSession, engine},
    quotient_pcs,
};
use crate::note_research_quota::Reservation;
use core::mem::size_of;
use engine::{note_ocl_wrapper_census, owned_runtime::OwnedRuntime, owned_runtime::Retirement};

mod environment;
use environment::SealedNoteEnvironment;

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
use super::preparation::EncodedPayload;

/// Successful native output only after exact runtime retirement. This feature-
/// gated research owner cannot be constructed from caller bytes or cloned. It
/// lends immutable encoding/public views and retains the original operation
/// charge until the actual encoded allocation is destroyed.
#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub struct OwnedEncodedNote {
    payload: EncodedPayload,
    retirement: Retirement,
}

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
impl OwnedEncodedNote {
    pub fn encoded(&self) -> &[u8] {
        &self.payload.encoded
    }

    pub fn public(&self) -> &[crate::config::Val; 26] {
        &self.payload.public
    }

    pub fn same_ledger(&self, token: &Reservation) -> bool {
        self.payload.reservation.same_ledger(token)
    }

    pub fn retained_operation_bytes(&self) -> usize {
        self.payload.reservation.reserved_bytes()
    }

    /// Native NoteRun interval from its validated successful report. Runtime
    /// startup/configuration and final runtime retirement are outside it.
    pub fn proof_scope_ns(&self) -> u128 {
        self.payload.proof_scope_ns
    }

    /// Managed-allocation high-water mark from this exact retired Engine.
    /// Excludes opaque context/driver storage and total process device memory.
    pub fn managed_device_peak_bytes(&self) -> usize {
        self.retirement.managed_peak_bytes
    }

    pub fn runtime_retired(&self) -> bool {
        self.retirement.managed_live_bytes == 0
            && self.retirement.host_tree_live_bytes == 0
            && self.retirement.lease_released
    }
}

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
impl<'w> PreparedNote<'w> {
    /// Pure source-backing charge for the optional qualification entry below.
    /// Public production/research dispatch diagnostics remain disabled.
    pub fn qualification_runtime_bytes(&self) -> Result<usize, Error> {
        Resources::new().map(|resources| resources.total)
    }

    /// Execute the isolated native-note research experiment. No arbitrary
    /// callback, seed, runtime, bytes or caller-created admission token enters.
    ///
    /// # Safety
    /// The dedicated worker must satisfy NoteRuntime::prove's immutable env-
    /// clear and external resource-guard contract for the complete call. It
    /// must not run other tests, use another engine or mutate the environment.
    pub unsafe fn prove_owned_for_qualification(
        self,
        reservation: Reservation,
    ) -> Result<OwnedEncodedNote, Error> {
        // SAFETY: this method forwards its explicit guarded-worker contract.
        let runtime = unsafe { NoteRuntime::prove(self, reservation)? };
        runtime.finish_encoded()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Resources {
    selection: usize,
    device_plan: usize,
    configuration: usize,
    operation: usize,
    source_wrappers: usize,
    retained_runtime: usize,
    environment: usize,
    inline: usize,
    startup: usize,
    total: usize,
}

impl Resources {
    fn new() -> Result<Self, Error> {
        Geometry::pinned()?;
        let selection = NoteSelection::required_payload_bytes()?;
        let device_plan =
            NoteDevicePlan::required_host_bytes().map_err(|_| Error::ResourceLimit)?;
        let configuration = ConfigurationCensus::new()?.known_payload_bytes();
        let operation = OperationResources::new()?.required_host_bytes();
        // NVIDIA is the longer source prefix. This is sizing only; before
        // initialization the actual source-built NoteDevicePlan must also
        // establish the interpreter-only policy used by this census.
        let source_wrappers = note_ocl_wrapper_census::fixed_inventory(true, false)
            .ok_or(Error::ResourceLimit)?
            .total_requested_backing;
        // Configuration has a separate runtime charge. Retain this original
        // outer charge until after its config/session aliases and Engine die,
        // so the configuration's earlier drop cannot lend runtime bytes back.
        let retained_runtime =
            gpu_hash::device::opening_runtime_host_bound().map_err(|_| Error::ResourceLimit)?;
        let environment = SealedNoteEnvironment::requested_bytes()?;
        let inline = add(size_of::<NoteRuntime<'static>>(), size_of::<Self>())?;
        let startup = add(
            add(source_wrappers, retained_runtime)?,
            add(environment, inline)?,
        )?;
        let total = add(
            startup,
            add(add(selection, device_plan)?, add(configuration, operation)?)?,
        )?;
        if total > 32 << 30 {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            selection,
            device_plan,
            configuration,
            operation,
            source_wrappers,
            retained_runtime,
            environment,
            inline,
            startup,
            total,
        })
    }

    fn check(&self, reservation: &Reservation) -> Result<(), Error> {
        if *self != Self::new()? || reservation.reserved_bytes() < self.total {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
}

/// Field order is the lifetime contract on success, error and unwind. A failed
/// report/proof/configuration retires first, then the exact engine, then sealed
/// environment storage, and only finally the original startup reservation.
/// The default internal completion exports no payload. The research feature
/// returns only a typed encoding owner after all runtime aliases have retired.
struct NoteRuntime<'w> {
    completion: Option<NoteCompletion<'w>>,
    runtime: Option<OwnedRuntime>,
    environment: SealedNoteEnvironment,
    reservation: Reservation,
}

impl<'w> NoteRuntime<'w> {
    /// # Safety
    /// Run only in the dedicated env-clear guarded worker described by the
    /// reviewed parent note_startup_environment.py. No code in that process
    /// may mutate environment variables until this owner is destroyed. The
    /// external guard must enforce the unchanged zero-swap process/VRAM and
    /// thread limits; this source-backing owner is not a replacement for it.
    unsafe fn prove(prepared: PreparedNote<'w>, reservation: Reservation) -> Result<Self, Error> {
        let resources = Resources::new()?;
        resources.check(&reservation)?;
        if !prepared.same_ledger(&reservation) {
            return Err(Error::ResourceLimit);
        }
        // SAFETY: the caller's dedicated immutable-process contract covers
        // capture, all legacy helper reads and every subsequent boundary.
        let environment = unsafe { SealedNoteEnvironment::capture()? };
        let mut owner = Self {
            completion: None,
            runtime: None,
            environment,
            reservation,
        };
        // Every subowner is admitted before the first driver query. Splitting
        // transfers the original token; it never reserves against a new quota.
        let selection_token = owner
            .reservation
            .split_off(resources.selection)
            .map_err(|_| Error::ResourceLimit)?;
        let device_token = owner
            .reservation
            .split_off(resources.device_plan)
            .map_err(|_| Error::ResourceLimit)?;
        let configuration_token = owner
            .reservation
            .split_off(resources.configuration)
            .map_err(|_| Error::ResourceLimit)?;
        let operation_token = owner
            .reservation
            .split_off(resources.operation)
            .map_err(|_| Error::ResourceLimit)?;
        if owner.reservation.reserved_bytes() < resources.startup {
            return Err(Error::ResourceLimit);
        }
        let request = owner.environment.request();
        owner.environment.recheck()?;
        let mut selection = NoteSelection::capture(request, selection_token)?;
        let device_plan = selection.plan(request, prepared.device_minimum()?, device_token)?;
        let actual = note_ocl_wrapper_census::fixed_inventory(
            true,
            device_plan.source_specialization_allowed(),
        )
        .ok_or(Error::Configuration)?;
        if actual.total_requested_backing > resources.source_wrappers {
            return Err(Error::ResourceLimit);
        }
        owner.environment.recheck()?;
        let fusion =
            quotient_pcs::initialize_research_from_env().map_err(|_| Error::Configuration)?;
        if !fusion
            || !quotient_pcs::initialize_gpu_quotient_from_env(true, fusion)
                .map_err(|_| Error::Configuration)?
        {
            return Err(Error::Configuration);
        }
        owner.runtime = Some(
            engine::initialize_explicit(engine::Limits::default(), selection.physical())
                .map_err(|_| Error::Configuration)?,
        );
        owner.check_live()?;
        // The existing activation path must BORROW this just-created exact
        // engine. It returns before selection/context construction when the
        // complete stored limits/mode/device tuple matches. A new epoch here
        // is refused, and OwnedRuntime cannot be silently replaced or shut down.
        if gpu_hash::initialize_tracked_from_env().map_err(|_| Error::Configuration)?
            || !gpu_hash::initialize_resident_from_env().map_err(|_| Error::Configuration)?
        {
            return Err(Error::Configuration);
        }
        owner.check_live()?;
        let bootstrap = DeviceSession::new().map_err(|_| Error::Configuration)?;
        let lease = device_plan
            .acquire(&bootstrap)
            .map_err(|_| Error::Configuration)?;
        drop(bootstrap);
        let configuration = ConfigurationCensus::new()?.create_under_reservation(
            configuration_token,
            &prepared,
            lease,
        )?;
        owner.check_live()?;
        let attempt = prepared.into_attempt(configuration, selection, request, operation_token)?;
        owner.completion = Some(attempt.prove());
        owner.check_live()?;
        Ok(owner)
    }

    fn check_live(&self) -> Result<(), Error> {
        self.environment.recheck()?;
        self.runtime
            .as_ref()
            .ok_or(Error::Configuration)?
            .check_live()
            .map_err(|_| Error::Configuration)
    }

    fn completion(&self) -> Result<&NoteCompletion<'w>, Error> {
        self.check_live()?;
        let completion = self.completion.as_ref().ok_or(Error::Preparation)?;
        if !completion.same_ledger(&self.reservation) {
            return Err(Error::ResourceLimit);
        }
        completion.status()?;
        Ok(completion)
    }

    fn finish(mut self) -> Result<Retirement, Error> {
        let status = self.completion().map(|_| ());
        // No alias may survive this destruction: proof, report, config,
        // capacity and all sessions go before the exact Engine owner.
        drop(self.completion.take());
        let runtime = self.runtime.take().ok_or(Error::Configuration)?;
        let retirement = runtime.finish(); // aborts before quota release on uncertainty
        self.environment.recheck()?;
        status?;
        Ok(retirement)
    }

    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    fn finish_encoded(mut self) -> Result<OwnedEncodedNote, Error> {
        self.completion()?;
        let payload = self
            .completion
            .take()
            .ok_or(Error::Preparation)?
            .into_encoded()?;
        // All original configuration/session/capacity aliases were destroyed
        // above. The raw encoding retains its actual original operation token
        // while the runtime still retains its independent startup token.
        let runtime = self.runtime.take().ok_or(Error::Configuration)?;
        let retirement = runtime.finish();
        self.environment.recheck()?;
        Ok(OwnedEncodedNote {
            payload,
            retirement,
        })
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;
