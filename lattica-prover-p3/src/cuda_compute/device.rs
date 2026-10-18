use super::{budget::Budget, cleanup, error, Limits, Result, Snapshot};
use crate::gpu_lease::{normalized_uuid, SingleDeviceLease};
use cudarc::driver::{result, sys, CudaContext, CudaStream};
use serde::Serialize;
use std::{
    ffi::CStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Identity {
    pub ordinal: usize,
    pub uuid: String,
    pub pci: String,
    pub name: String,
    pub global_bytes: usize,
    pub compute_capability: u32,
    pub driver_api: i32,
    pub max_threads: u32,
    pub max_grid_x: u32,
    pub shared_bytes: u32,
}

pub(crate) fn inventory() -> Result<Vec<Identity>> {
    // Loading is explicit and precedes cudarc's lazy symbol lookups.
    if !unsafe { sys::is_culib_present() } {
        return Err("CUDA driver library is unavailable".into());
    }
    result::init().map_err(error)?;
    let count = result::device::get_count().map_err(error)?;
    if !(0..=64).contains(&count) {
        return Err("unsupported CUDA device count".into());
    }
    let mut driver_api = 0;
    unsafe {
        sys::cuDriverGetVersion(&mut driver_api)
            .result()
            .map_err(error)?;
    }
    let mut devices = Vec::with_capacity(count as usize);
    for ordinal in 0..count {
        let device = result::device::get(ordinal).map_err(error)?;
        let attribute = |key| unsafe { result::device::get_attribute(device, key).map_err(error) };
        let mut uuid = sys::CUuuid { bytes: [0; 16] };
        let mut pci = [0i8; 32];
        unsafe {
            sys::cuDeviceGetUuid_v2(&mut uuid, device)
                .result()
                .map_err(error)?;
            sys::cuDeviceGetPCIBusId(pci.as_mut_ptr(), pci.len() as i32, device)
                .result()
                .map_err(error)?;
        }
        let mut identity = String::from("GPU-");
        use std::fmt::Write;
        for (i, byte) in uuid.bytes.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                identity.push('-');
            }
            write!(identity, "{:02x}", *byte as u8).map_err(error)?;
        }
        let major =
            attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR)?;
        let minor =
            attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR)?;
        devices.push(Identity {
            ordinal: ordinal as usize,
            uuid: identity,
            pci: unsafe { CStr::from_ptr(pci.as_ptr()) }
                .to_str()
                .map_err(error)?
                .to_owned(),
            name: result::device::get_name(device).map_err(error)?,
            global_bytes: unsafe { result::device::total_mem(device).map_err(error)? },
            compute_capability: (major * 10 + minor) as u32,
            driver_api,
            max_threads: attribute(
                sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
            )? as u32,
            max_grid_x: attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X)?
                as u32,
            shared_bytes: attribute(
                sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK,
            )? as u32,
        });
    }
    Ok(devices)
}

#[derive(Clone)]
pub(crate) struct Runtime {
    pub(super) state: Arc<State>,
}

pub(super) struct State {
    pub context: Arc<CudaContext>,
    pub stream: Arc<CudaStream>,
    pub identity: Identity,
    pub budget: Arc<Budget>,
    queue: Mutex<()>,
    failed: AtomicBool,
    // Last field: the driver context is retired before releasing device leases.
    _lease: SingleDeviceLease,
}

impl Runtime {
    pub(crate) fn new(uuid: &str, limits: Limits) -> Result<Self> {
        let required = limits.validate()?;
        let normalized = normalized_uuid(uuid)?;
        let identity = inventory()?
            .into_iter()
            .find(|d| normalized_uuid(&d.uuid).is_ok_and(|value| value == normalized))
            .ok_or("assigned CUDA GPU UUID is not visible")?;
        if identity.compute_capability < 70 || identity.driver_api < 12090 {
            return Err("CUDA prover requires SM 7+ and a CUDA 12.9-compatible driver".into());
        }
        if required > identity.global_bytes {
            return Err("CUDA budgets exceed device memory".into());
        }
        let lease = SingleDeviceLease::acquire(&identity.uuid)?;
        let context = CudaContext::new(identity.ordinal).map_err(error)?;
        // Measured after context creation; retain the full opaque reserve for
        // subsequent modules, JIT backing, and driver allocations.
        if context.mem_get_info().map_err(error)?.0 < required {
            return Err(
                "insufficient free CUDA memory for managed budget, context reserve and headroom"
                    .into(),
            );
        }
        let stream = context.new_stream().map_err(error)?;
        let budget = Budget::new(limits)?;
        eprintln!(
            "bounded_cuda_identity {}",
            serde_json::to_string(&identity).map_err(error)?
        );
        Ok(Self {
            state: Arc::new(State {
                context,
                stream,
                identity,
                budget,
                queue: Mutex::new(()),
                failed: AtomicBool::new(false),
                _lease: lease,
            }),
        })
    }

    pub(crate) fn identity(&self) -> &Identity {
        &self.state.identity
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.state.budget.snapshot()
    }
    pub(crate) fn finish(&self) -> Result<()> {
        let _guard = self.state.enter()?;
        self.state.stream.synchronize().map_err(|e| {
            self.state.fail();
            error(e)
        })?;
        self.state.context.check_err().map_err(error)
    }
}

impl State {
    pub fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }

    pub fn cleanup_lock(&self) -> MutexGuard<'_, ()> {
        self.queue.lock().unwrap_or_else(|poisoned| {
            self.fail();
            poisoned.into_inner()
        })
    }

    pub fn enter(&self) -> Result<MutexGuard<'_, ()>> {
        let guard = self.cleanup_lock();
        if self.failed.load(Ordering::Acquire) {
            return Err("CUDA runtime has a failed or abandoned command".into());
        }
        self.context.bind_to_thread().map_err(error)?;
        self.context.check_err().map_err(error)?;
        Ok(guard)
    }

    pub fn drain(&self) -> Result<()> {
        self.context.bind_to_thread().map_err(error)?;
        self.stream.synchronize().map_err(error)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        cleanup(self.drain(), "context drain");
        cleanup(self.context.check_err().map_err(error), "context status");
        debug_assert_eq!(self.budget.snapshot().live_bytes, 0);
    }
}
