use super::{
    budget::Reservation, cleanup, compiler, device::State, error, Buffer, Result, Runtime,
};
use cudarc::driver::{result, sys};
use std::{
    ffi::{c_void, CString},
    sync::Arc,
};

#[derive(Clone)]
pub(crate) struct Module {
    inner: Arc<NativeModule>,
}

struct NativeModule {
    raw: sys::CUmodule,
    _reservation: Reservation,
    state: Arc<State>,
}

/// Local-memory backing comes from the separately reserved context allowance.
/// Keep every native primitive within the same per-thread and occupancy bound.
pub(super) fn private_memory_fits(identity: &super::Identity, bytes: usize) -> Result<bool> {
    let backing = bytes
        .div_ceil(256)
        .checked_mul(256)
        .and_then(|n| n.checked_mul(identity.multiprocessors as usize))
        .and_then(|n| n.checked_mul(identity.max_threads_per_multiprocessor as usize))
        .ok_or("CUDA private memory size overflow")?;
    Ok(bytes <= 512
        && backing <= 128 << 20
        && identity.multiprocessors > 0
        && identity.max_threads_per_multiprocessor > 0)
}

// Calls bind the owning context and serialize on its stream. The raw module
// remains alive through every Kernel and drains outstanding work on retirement.
unsafe impl Send for NativeModule {}
unsafe impl Sync for NativeModule {}

impl Runtime {
    pub(crate) fn compile(&self, source: &str) -> Result<Module> {
        let reservation = self.state.budget.module()?;
        let image = compiler::compile(source, self.identity().compute_capability)?;
        let _guard = self.state.enter()?;
        let raw = unsafe { result::module::load_data(image.as_ptr().cast()).map_err(error)? };
        Ok(Module {
            inner: Arc::new(NativeModule {
                raw,
                _reservation: reservation,
                state: self.state.clone(),
            }),
        })
    }
}

impl Module {
    pub(crate) fn kernel(&self, name: &str) -> Result<Kernel> {
        if name.is_empty() || name.len() > 128 {
            return Err("invalid CUDA kernel name".into());
        }
        let name = CString::new(name).map_err(error)?;
        let _guard = self.inner.state.enter()?;
        let raw = unsafe { result::module::get_function(self.inner.raw, name).map_err(error)? };
        Ok(Kernel {
            raw,
            module: self.clone(),
            stage: None,
        })
    }

    pub(super) fn kernel_for_stage(
        &self,
        name: &str,
        stage: crate::proving::Stage,
    ) -> Result<Kernel> {
        Ok(self.kernel(name)?.with_stage(stage))
    }
}

impl Drop for NativeModule {
    fn drop(&mut self) {
        let _guard = self.state.cleanup_lock();
        cleanup(self.state.drain(), "module drain");
        cleanup(
            unsafe { result::module::unload(self.raw).map_err(error) },
            "module unload",
        );
    }
}

#[derive(Clone)]
pub(crate) struct Kernel {
    raw: sys::CUfunction,
    module: Module,
    stage: Option<crate::proving::Stage>,
}
unsafe impl Send for Kernel {}
unsafe impl Sync for Kernel {}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Launch {
    pub blocks: u32,
    pub threads: u32,
    pub shared_bytes: u32,
}

pub(crate) enum Argument<'a> {
    U32(u32),
    U64(u64),
    Buffer(&'a Buffer),
}
enum Slot {
    U32(u32),
    U64(u64),
}

impl Kernel {
    pub(super) fn with_stage(mut self, stage: crate::proving::Stage) -> Self {
        self.stage = Some(stage);
        self
    }

    /// Static per-thread local memory reported by the CUDA driver. Used to
    /// bound public specialization spills within the reserved context memory.
    pub(crate) fn local_bytes(&self) -> Result<usize> {
        let _guard = self.module.inner.state.enter()?;
        let bytes = unsafe {
            result::function::get_function_attribute(
                self.raw,
                sys::CUfunction_attribute::CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES,
            )
            .map_err(error)?
        };
        usize::try_from(bytes).map_err(|_| "negative CUDA kernel local-memory size".into())
    }

    /// Enqueue on the owning runtime's in-order stream.
    ///
    /// # Safety
    /// Arguments must match the compiled kernel's ABI. The caller must prove
    /// all device indexing is within the retained buffers and all thread/block
    /// dependencies, shared-memory extents, and aliasing obey the kernel contract.
    pub(crate) unsafe fn launch(
        &self,
        launch: Launch,
        arguments: &[Argument<'_>],
    ) -> Result<Completion> {
        let state = &self.module.inner.state;
        if launch.blocks == 0
            || launch.blocks > state.identity.max_grid_x
            || launch.threads == 0
            || launch.threads > state.identity.max_threads
            || launch.shared_bytes > state.identity.shared_bytes
            || arguments.len() > 64
        {
            return Err("CUDA launch exceeds bounded geometry or argument capacity".into());
        }
        let mut slots: [Slot; 64] = std::array::from_fn(|_| Slot::U64(0));
        for (slot, argument) in slots.iter_mut().zip(arguments) {
            *slot = match argument {
                Argument::U32(value) => Slot::U32(*value),
                Argument::U64(value) => Slot::U64(*value),
                Argument::Buffer(buffer) => {
                    if !Arc::ptr_eq(state, buffer.owner()) {
                        return Err("CUDA kernel buffer belongs to another runtime".into());
                    }
                    Slot::U64(buffer.pointer())
                }
            };
        }
        let mut pointers = [std::ptr::null_mut::<c_void>(); 64];
        for (pointer, slot) in pointers.iter_mut().zip(&mut slots).take(arguments.len()) {
            *pointer = match slot {
                Slot::U32(value) => (value as *mut u32).cast(),
                Slot::U64(value) => (value as *mut u64).cast(),
            };
        }
        let guard = state.enter()?;
        let reporting = state.reporting_ticket(self.stage)?;
        let reservation = state.budget.command()?;
        let start = result::event::create(sys::CUevent_flags::CU_EVENT_DEFAULT).map_err(error)?;
        let end = match result::event::create(sys::CUevent_flags::CU_EVENT_DEFAULT) {
            Ok(event) => event,
            Err(e) => {
                cleanup(
                    result::event::destroy(start).map_err(error),
                    "partial event creation",
                );
                return Err(error(e));
            }
        };
        let receipt = Completion {
            start,
            end,
            completed: false,
            _reservation: reservation,
            state: state.clone(),
            reporting,
        };
        let queued = (|| -> Result<()> {
            result::event::record(start, state.stream.cu_stream()).map_err(error)?;
            result::launch_kernel(
                self.raw,
                (launch.blocks, 1, 1),
                (launch.threads, 1, 1),
                launch.shared_bytes,
                state.stream.cu_stream(),
                &mut pointers[..arguments.len()],
            )
            .map_err(error)?;
            result::event::record(end, state.stream.cu_stream()).map_err(error)?;
            Ok(())
        })();
        drop(guard);
        if let Err(e) = queued {
            state.fail();
            return Err(e);
        }
        Ok(receipt)
    }
}

#[must_use = "CUDA completion must be observed; abandoning it invalidates this runtime"]
pub(crate) struct Completion {
    start: sys::CUevent,
    end: sys::CUevent,
    completed: bool,
    _reservation: Reservation,
    state: Arc<State>,
    reporting: Option<super::reporting::Ticket>,
}

impl Completion {
    pub(super) fn is_reported(&self) -> bool {
        self.reporting.is_some()
    }

    pub(crate) fn finish(mut self) -> Result<u64> {
        {
            let _guard = self.state.enter()?;
            unsafe {
                result::event::synchronize(self.end).map_err(error)?;
            }
            let milliseconds =
                unsafe { result::event::elapsed(self.start, self.end).map_err(error)? };
            if !milliseconds.is_finite()
                || milliseconds < 0.0
                || milliseconds as f64 * 1e6 >= u64::MAX as f64
            {
                return Err("invalid CUDA profiling duration".into());
            }
            let ns = (milliseconds as f64 * 1e6).round() as u64;
            self.state.budget.completed(ns)?;
            if let Some(ticket) = &mut self.reporting {
                ticket.complete(ns)?;
            }
            self.completed = true;
            Ok(ns)
        }
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        let _guard = self.state.cleanup_lock();
        if !self.completed {
            self.state.fail();
            cleanup(self.state.drain(), "abandoned command drain");
        }
        cleanup(
            unsafe { result::event::destroy(self.start).map_err(error) },
            "start event destroy",
        );
        cleanup(
            unsafe { result::event::destroy(self.end).map_err(error) },
            "end event destroy",
        );
    }
}
