//! Fixed-profile startup ownership for the admitted RingCT research path.
//! A pending owner first reserves in the original worker ledger. Its optional
//! preflight captures bounded immutable environment/device state without opening
//! a context. That exact selection and original token move into the Session.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "owned-gpu-runtime"
))]

use super::{Limits, Session, ACTIVE};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Reservation};
use lattica_prover_p3::block_v2::{gpu_hash::device::ringct_runtime as core, profile};
use std::{
    cell::{RefCell, RefMut},
    marker::PhantomData,
    mem::size_of,
    sync::atomic::Ordering,
};

const WORKER_HOST: u64 = 32 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const CONTEXT_DEVICE: u64 = 4 << 30;
const MAX_ROWS: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeError {
    Configuration,
    Admission,
    WrongLedger,
    Selection,
    ActiveSession,
    MissingOwner,
    Initialization,
    Lifecycle,
}

fn fixed_limits(limits: Limits) -> Result<(), RuntimeError> {
    if crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(limits.host_bytes).is_err()
        || limits.device_bytes != MANAGED_DEVICE
        || !limits.max_rows.is_power_of_two()
        || limits.max_rows > MAX_ROWS
        || profile::NUM_QUERIES != 128
        || profile::LOG_BLOWUP != 4
        || profile::CHALLENGE_FIELD_BITS != 191
        || profile::NUM_RANDOM_CODEWORDS != 4
    {
        return Err(RuntimeError::Configuration);
    }
    Ok(())
}

fn requested(plan: &core::StartupPlan) -> Result<Bytes, RuntimeError> {
    let footprint = plan.footprint();
    if footprint.driver_context_reserve as u64 != CONTEXT_DEVICE {
        return Err(RuntimeError::Configuration);
    }
    // Include overlapping Rust owners. String requests for the copied bounded
    // public identity are already charged by the core source-built census.
    // Engine/context/Run/report/proof storage have their own fixed owners.
    let mut host = footprint.requested_host_bytes;
    for bytes in [
        size_of::<PendingRuntime>(),
        size_of::<PendingRuntimeGuard<'static>>(),
        size_of::<RuntimeLifetime>(),
        size_of::<ReservedRuntime<'static>>(),
        size_of::<OriginalRuntimeBorrow<'static>>(),
        size_of::<Session>(),
        size_of::<ActiveStart>(),
    ] {
        host = host.checked_add(bytes).ok_or(RuntimeError::Admission)?;
    }
    #[cfg(all(feature = "owned-native-shake", not(debug_assertions)))]
    {
        host = host
            .checked_add(continuity::additional_host_bytes())
            .ok_or(RuntimeError::Admission)?;
    }
    #[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
    {
        host = host.checked_add(workflow_originals::additional_host_bytes())
            .ok_or(RuntimeError::Admission)?;
    }
    Ok(Bytes {
        host: u64::try_from(host).map_err(|_| RuntimeError::Admission)?,
        device: u64::try_from(footprint.managed_device_bytes)
            .map_err(|_| RuntimeError::Admission)?,
    })
}

/// No Clone, public payload, numeric authority constructor or token extraction.
/// The original reservation remains last through selection and plan cleanup.
#[must_use = "keep the original startup reservation until runtime retirement"]
pub(crate) struct PendingRuntime {
    selection: Option<core::Selection>,
    plan: core::StartupPlan,
    limits: Limits,
    reservation: Reservation,
}

#[must_use = "hold this borrow through the idle backend admission phase"]
pub(crate) struct PendingRuntimeGuard<'a> {
    _pending: &'a PendingRuntime,
}
impl PendingRuntimeGuard<'_> {
    /// Borrow the original startup claim while the successful idle preflight
    /// remains retained. This does not extract, split, or clone the owner.
    pub(crate) fn reservation(&self) -> &Reservation {
        &self._pending.reservation
    }
}
impl Drop for PendingRuntimeGuard<'_> {
    fn drop(&mut self) {}
}

impl PendingRuntime {
    /// Pure source planning plus the original ledger admission. This does not
    /// read environment variables, query a driver, or create a context/session.
    pub(crate) fn reserve(ledger: &Ledger, limits: Limits) -> Result<Self, RuntimeError> {
        let plan = core::StartupPlan::new().map_err(|_| RuntimeError::Configuration)?;
        Self::reserve_plan(ledger, limits, plan)
    }

    /// Exact outer-only profile. The original startup reservation owns all
    /// 8 GiB of retained-tree payload before preflight or runtime construction.
    /// Default/raw/native callers continue through the device-only constructor.
    pub(crate) fn reserve_outer_host_v1(
        ledger: &Ledger,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        let plan = core::StartupPlan::outer_host_v1().map_err(|_| RuntimeError::Configuration)?;
        Self::reserve_plan(ledger, limits, plan)
    }

    fn reserve_plan(
        ledger: &Ledger,
        limits: Limits,
        plan: core::StartupPlan,
    ) -> Result<Self, RuntimeError> {
        fixed_limits(limits)?;
        if cfg!(debug_assertions) {
            return Err(RuntimeError::Configuration);
        }
        let allowance = ledger.snapshot().allowance;
        if allowance.host == 0
            || allowance.host > limits.host_bytes
            || allowance.device == 0
            || allowance.device > MANAGED_DEVICE
        {
            return Err(RuntimeError::Configuration);
        }
        let reservation = ledger
            .reserve(Category::PhaseScratch, requested(&plan)?)
            .map_err(|_| RuntimeError::Admission)?;
        Ok(Self {
            selection: None,
            plan,
            limits,
            reservation,
        })
    }

    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.reservation.belongs_to(ledger)
    }

    /// Reporting only. An inclusive backend footprint may subtract the exact
    /// overlapping startup bytes only while this same owner remains retained.
    /// The returned numbers do not transfer quota or authorize any operation.
    pub(crate) fn reserved_bytes(&self) -> Bytes {
        self.reservation.requirements().get(Category::PhaseScratch)
    }

    /// Exact tree payload already owned by this non-cloneable pending runtime.
    /// The source-built profile fixes the amount; callers cannot set it. An
    /// inclusive outer claim may subtract it only while this same original
    /// ledger owner remains retained through full backend/session retirement.
    pub(crate) fn reserved_tree_host_bytes(&self) -> u64 {
        self.plan.footprint().retained_tree_host_bytes as u64
    }

    /// Bounded environment and physical-device capture while the Engine stays
    /// idle. Hold this borrow across any later environment/driver inspection
    /// used to derive outer admission. Repeated calls recheck the same capture.
    ///
    /// # Safety
    /// The guarded process must exclude every environment mutation from this
    /// call until Session retirement (or pending-owner destruction), and exclude
    /// all unrelated GPU startup/shutdown/work. Rechecking is not an OS lock.
    pub(crate) unsafe fn preflight(&mut self) -> Result<PendingRuntimeGuard<'_>, RuntimeError> {
        if self.selection.is_none() {
            // SAFETY: caller retains the documented sealed-process contract;
            // the exact source-derived reservation is already owned by self.
            self.selection =
                Some(unsafe { self.plan.inspect() }.map_err(|_| RuntimeError::Selection)?);
        }
        self.selection
            .as_mut()
            .ok_or(RuntimeError::MissingOwner)?
            .recheck_idle()
            .map_err(|_| RuntimeError::Selection)?;
        Ok(PendingRuntimeGuard { _pending: self })
    }

    /// Construct the actual runtime with this original reservation. No dynamic
    /// error can escape: all core errors are destroyed/mapped while it is live.
    ///
    /// # Safety
    /// Same sealed-process contract as preflight, including callers that skip
    /// an explicit preflight. The contract lasts through runtime destruction.
    pub(crate) unsafe fn start(mut self) -> Result<Session, RuntimeError> {
        {
            // SAFETY: this method forwards its caller's process contract.
            let _preflight = unsafe { self.preflight()? };
        }
        let active = ActiveStart::claim()?;
        let runtime = self
            .selection
            .take()
            .ok_or(RuntimeError::MissingOwner)?
            .start()
            .map_err(|_| RuntimeError::Initialization)?;
        let device = runtime.identity().clone();
        let max_work_group_size = runtime.maximum_work_group_size();
        let session = Session {
            limits: self.limits,
            device,
            max_work_group_size,
            context_bytes: CONTEXT_DEVICE,
            closed: false,
            #[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
            workflow_transition: super::workflow_transition::State::new(),
            _thread: PhantomData,
            runtime_lifetime: Some(RuntimeLifetime {
                runtime: RefCell::new(runtime),
                reservation: self.reservation,
            }),
        };
        active.disarm();
        Ok(session)
    }
}

struct ActiveStart(bool);
impl ActiveStart {
    fn claim() -> Result<Self, RuntimeError> {
        ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RuntimeError::ActiveSession)?;
        Ok(Self(true))
    }
    fn disarm(mut self) {
        self.0 = false;
    }
}
impl Drop for ActiveStart {
    fn drop(&mut self) {
        if self.0 {
            ACTIVE.store(false, Ordering::Release);
        }
    }
}

/// Runtime must drop before the real original quota, including during unwind.
pub(super) struct RuntimeLifetime {
    runtime: RefCell<core::Runtime>,
    reservation: Reservation,
}
impl RuntimeLifetime {
    pub(super) fn retire(&mut self) -> core::Retirement {
        self.runtime.get_mut().retire()
    }
}

/// This borrow keeps the Session/runtime and original reservation alive through
/// a fixed operation. It exposes no unrelated admission or dispatch authority.
#[must_use = "hold the runtime borrow until the owned operation completes"]
pub(crate) struct ReservedRuntime<'a> {
    _lifetime: &'a RuntimeLifetime,
}

/// A source-built borrow of the same runtime and original startup token.
/// RefMut keeps runtime selection exclusive and thread-local until all core
/// operations borrowing this handle have finished. Neither value is extracted.
pub(crate) struct OriginalRuntimeBorrow<'a> {
    runtime: RefMut<'a, core::Runtime>,
    reservation: &'a Reservation,
}

impl OriginalRuntimeBorrow<'_> {
    pub(crate) fn runtime(&self) -> &core::Runtime {
        &self.runtime
    }

    pub(crate) fn reservation(&self) -> &Reservation {
        self.reservation
    }
}

impl ReservedRuntime<'_> {
    /// Complete bounded environment/physical/epoch recheck before a core
    /// consumer takes the Engine lock for its own same-lock capacity admission.
    pub(crate) fn borrow_core(&self) -> Result<OriginalRuntimeBorrow<'_>, RuntimeError> {
        let mut runtime = self
            ._lifetime
            .runtime
            .try_borrow_mut()
            .map_err(|_| RuntimeError::Lifecycle)?;
        runtime.recheck().map_err(|_| RuntimeError::Lifecycle)?;
        Ok(OriginalRuntimeBorrow {
            runtime,
            reservation: &self._lifetime.reservation,
        })
    }
}
impl Drop for ReservedRuntime<'_> {
    fn drop(&mut self) {}
}

impl Session {
    /// Check before prepared-state release, Run construction or DeviceSession
    /// acquisition; retain the returned borrow through completion and cleanup.
    pub(crate) fn check_reserved_runtime(
        &self,
        ledger: &Ledger,
    ) -> Result<ReservedRuntime<'_>, RuntimeError> {
        if self.closed {
            return Err(RuntimeError::Lifecycle);
        }
        fixed_limits(self.limits)?;
        let lifetime = self
            .runtime_lifetime
            .as_ref()
            .ok_or(RuntimeError::MissingOwner)?;
        if !lifetime.reservation.belongs_to(ledger) {
            return Err(RuntimeError::WrongLedger);
        }
        lifetime
            .runtime
            .try_borrow_mut()
            .map_err(|_| RuntimeError::Lifecycle)?
            .recheck()
            .map_err(|_| RuntimeError::Lifecycle)?;
        Ok(ReservedRuntime {
            _lifetime: lifetime,
        })
    }

    /// The reserved path has an inline cleanup receipt. Legacy JSON completion
    /// rejects these sessions because its payload would outlive this token.
    pub(crate) fn finish_reserved(mut self) -> Result<core::Retirement, RuntimeError> {
        if self.closed {
            return Err(RuntimeError::Lifecycle);
        }
        let lifetime = self
            .runtime_lifetime
            .as_mut()
            .ok_or(RuntimeError::MissingOwner)?;
        let receipt = lifetime.retire();
        self.closed = true;
        ACTIVE.store(false, Ordering::Release);
        Ok(receipt)
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;

#[cfg(all(feature = "owned-native-shake", not(debug_assertions)))]
mod continuity;

#[cfg(all(feature = "owned-native-shake", not(debug_assertions)))]
mod quota_projection;

#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
mod workflow_originals;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use workflow_originals::{PendingWorkflowRuntime, StartupTiming, WorkflowRuntimePlan};
