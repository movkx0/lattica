//! Fixed-size FFI and one synchronous lifetime. No ocl info/error formatter is
//! called: even set-argument/enqueue failures retain only the original i32 code.
use super::*;
use core::{ffi::CStr, ptr};

#[derive(Clone, Copy)]
pub(super) struct Handles {
    pub(super) program: ffi::cl_program,
    pub(super) compute: ffi::cl_command_queue,
    pub(super) copy: ffi::cl_command_queue,
}
#[derive(Clone, Copy)]
pub(super) enum Argument {
    Memory(ffi::cl_mem),
    Uint(u32),
    Ulong(u64),
}

// Private injection boundary is solely for CPU failure-path tests. No caller
// outside this module tree can supply a driver or obtain a raw launch scope.
pub(super) trait Api {
    fn queue_properties(&mut self, queue: ffi::cl_command_queue) -> (u64, usize, i32);
    fn create(&mut self, program: ffi::cl_program, name: &CStr) -> (ffi::cl_kernel, i32);
    fn argument_count(&mut self, kernel: ffi::cl_kernel) -> (u32, usize, i32);
    fn upload(
        &mut self,
        queue: ffi::cl_command_queue,
        buffer: ffi::cl_mem,
        offset: usize,
        words: &[u64],
    ) -> i32;
    fn clear(&mut self, queue: ffi::cl_command_queue, buffer: ffi::cl_mem, bytes: usize) -> i32;
    fn argument(&mut self, kernel: ffi::cl_kernel, index: u32, argument: Argument) -> i32;
    fn enqueue(
        &mut self,
        queue: ffi::cl_command_queue,
        kernel: ffi::cl_kernel,
        work: usize,
    ) -> (ffi::cl_event, i32);
    fn finish(&mut self, queue: ffi::cl_command_queue) -> i32;
    fn event_status(&mut self, event: ffi::cl_event) -> (i32, usize, i32);
    fn timestamp(&mut self, event: ffi::cl_event, end: bool) -> (u64, usize, i32);
    fn release_event(&mut self, event: ffi::cl_event) -> i32;
    fn release_kernel(&mut self, kernel: ffi::cl_kernel) -> i32;
}

pub(super) struct OpenCl;
impl Api for OpenCl {
    fn queue_properties(&mut self, queue: ffi::cl_command_queue) -> (u64, usize, i32) {
        let mut value: ffi::cl_command_queue_properties = 0;
        let mut bytes = 0;
        // SAFETY: handles borrow the live Engine. Every info call supplies a
        // fixed-size stack result; driver-returned lengths never allocate.
        let status = unsafe {
            ffi::clGetCommandQueueInfo(
                queue,
                ffi::CL_QUEUE_PROPERTIES,
                size_of::<ffi::cl_command_queue_properties>(),
                (&mut value as *mut ffi::cl_command_queue_properties).cast(),
                &mut bytes,
            )
        };
        (value, bytes, status)
    }
    fn create(&mut self, program: ffi::cl_program, name: &CStr) -> (ffi::cl_kernel, i32) {
        let mut status = 0;
        // SAFETY: actual engine Program and one of seven static CStr names.
        let kernel = unsafe { ffi::clCreateKernel(program, name.as_ptr(), &mut status) };
        (kernel, status)
    }
    fn argument_count(&mut self, kernel: ffi::cl_kernel) -> (u32, usize, i32) {
        let mut value: u32 = 0;
        let mut bytes = 0;
        // SAFETY: kernel is owned by Scope; destination size is one cl_uint.
        let status = unsafe {
            ffi::clGetKernelInfo(
                kernel,
                ffi::CL_KERNEL_NUM_ARGS,
                size_of::<u32>(),
                (&mut value as *mut u32).cast(),
                &mut bytes,
            )
        };
        (value, bytes, status)
    }
    fn upload(
        &mut self,
        queue: ffi::cl_command_queue,
        buffer: ffi::cl_mem,
        offset: usize,
        words: &[u64],
    ) -> i32 {
        // SAFETY: checked buffer geometry covers this range. CL_TRUE makes the
        // host-slice borrow synchronous; Scope drains on every subsequent error.
        unsafe {
            ffi::clEnqueueWriteBuffer(
                queue,
                buffer,
                ffi::CL_TRUE,
                offset,
                core::mem::size_of_val(words),
                words.as_ptr().cast(),
                0,
                ptr::null(),
                ptr::null_mut(),
            )
        }
    }
    fn clear(&mut self, queue: ffi::cl_command_queue, buffer: ffi::cl_mem, bytes: usize) -> i32 {
        let zero = 0u64;
        // SAFETY: source pattern is copied by OpenCL before this call returns.
        // The actual destination allocation is borrowed through queue drain.
        unsafe {
            ffi::clEnqueueFillBuffer(
                queue,
                buffer,
                (&zero as *const u64).cast(),
                size_of::<u64>(),
                0,
                bytes,
                0,
                ptr::null(),
                ptr::null_mut(),
            )
        }
    }
    fn argument(&mut self, kernel: ffi::cl_kernel, index: u32, argument: Argument) -> i32 {
        // SAFETY: private source-linked variants choose exact argument index,
        // scalar width and memory-handle type. OpenCL copies the argument value.
        unsafe {
            match argument {
                Argument::Memory(value) => ffi::clSetKernelArg(
                    kernel,
                    index,
                    size_of::<ffi::cl_mem>(),
                    (&value as *const ffi::cl_mem).cast(),
                ),
                Argument::Uint(value) => ffi::clSetKernelArg(
                    kernel,
                    index,
                    size_of::<u32>(),
                    (&value as *const u32).cast(),
                ),
                Argument::Ulong(value) => ffi::clSetKernelArg(
                    kernel,
                    index,
                    size_of::<u64>(),
                    (&value as *const u64).cast(),
                ),
            }
        }
    }
    fn enqueue(
        &mut self,
        queue: ffi::cl_command_queue,
        kernel: ffi::cl_kernel,
        work: usize,
    ) -> (ffi::cl_event, i32) {
        let mut event = ptr::null_mut();
        // SAFETY: source-checked geometry and arguments, one in-order queue.
        // Kernel, event and all argument owners remain live through completion.
        let status = unsafe {
            ffi::clEnqueueNDRangeKernel(
                queue,
                kernel,
                1,
                ptr::null(),
                &work,
                ptr::null(),
                0,
                ptr::null(),
                &mut event,
            )
        };
        (event, status)
    }
    fn finish(&mut self, queue: ffi::cl_command_queue) -> i32 {
        // SAFETY: actual Engine queue remains borrowed until Scope is destroyed.
        unsafe { ffi::clFinish(queue) }
    }
    fn event_status(&mut self, event: ffi::cl_event) -> (i32, usize, i32) {
        let mut value: i32 = 0;
        let mut bytes = 0;
        // SAFETY: Scope owns this event; supplied destination is exactly cl_int.
        let status = unsafe {
            ffi::clGetEventInfo(
                event,
                ffi::CL_EVENT_COMMAND_EXECUTION_STATUS,
                size_of::<i32>(),
                (&mut value as *mut i32).cast(),
                &mut bytes,
            )
        };
        (value, bytes, status)
    }
    fn timestamp(&mut self, event: ffi::cl_event, end: bool) -> (u64, usize, i32) {
        let mut value: u64 = 0;
        let mut bytes = 0;
        let field = if end {
            ffi::CL_PROFILING_COMMAND_END
        } else {
            ffi::CL_PROFILING_COMMAND_START
        };
        // SAFETY: retained completed event, fixed cl_ulong destination.
        let status = unsafe {
            ffi::clGetEventProfilingInfo(
                event,
                field,
                size_of::<u64>(),
                (&mut value as *mut u64).cast(),
                &mut bytes,
            )
        };
        (value, bytes, status)
    }
    fn release_event(&mut self, event: ffi::cl_event) -> i32 {
        // SAFETY: exactly one owned event reference; cleared only after success.
        unsafe { ffi::clReleaseEvent(event) }
    }
    fn release_kernel(&mut self, kernel: ffi::cl_kernel) -> i32 {
        // SAFETY: exactly one owned kernel reference; queues have drained.
        unsafe { ffi::clReleaseKernel(kernel) }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    kind: Kernel,
    kernel: ffi::cl_kernel,
    event: ffi::cl_event,
}
impl Slot {
    fn empty() -> Self {
        Self {
            kind: Kernel::Arithmetic,
            kernel: ptr::null_mut(),
            event: ptr::null_mut(),
        }
    }
}

pub(super) struct Scope<'a, A: Api, O> {
    _owners: &'a O,
    handles: Handles,
    api: &'a mut A,
    primary: Kernel,
    slots: [Slot; 2],
    count: usize,
    closed: bool,
}
impl<'a, A: Api, O> Scope<'a, A, O> {
    pub(super) fn new(
        owners: &'a O,
        handles: Handles,
        api: &'a mut A,
        primary: Kernel,
    ) -> Result<Self, Failure> {
        if handles.program.is_null() || handles.compute.is_null() || handles.copy.is_null() {
            return Err(Failure::at(primary, Phase::Queue, 0, 0));
        }
        let scope = Self {
            _owners: owners,
            handles,
            api,
            primary,
            slots: [Slot::empty(); 2],
            count: 0,
            closed: false,
        };
        for (index, queue) in [handles.compute, handles.copy].into_iter().enumerate() {
            let (flags, bytes, status) = scope.api.queue_properties(queue);
            if status != 0
                || bytes != size_of::<ffi::cl_command_queue_properties>()
                || flags & ffi::CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE != 0
                || (index == 0 && flags & ffi::CL_QUEUE_PROFILING_ENABLE == 0)
            {
                return Err(Failure::at(primary, Phase::Queue, index as u8, status));
            }
        }
        Ok(scope)
    }
    pub(super) fn upload(
        &mut self,
        kernel: Kernel,
        buffer: ffi::cl_mem,
        words: &[u64],
    ) -> Result<(), Failure> {
        self.upload_at(kernel, buffer, 0, words)
    }
    pub(super) fn upload_at(
        &mut self,
        kernel: Kernel,
        buffer: ffi::cl_mem,
        offset_words: usize,
        words: &[u64],
    ) -> Result<(), Failure> {
        let offset = offset_words
            .checked_mul(size_of::<u64>())
            .ok_or(Failure::shape(kernel))?;
        if words.is_empty() {
            return Ok(());
        }
        let status = self.api.upload(self.handles.compute, buffer, offset, words);
        if status != 0 {
            return Err(Failure::at(kernel, Phase::Upload, 0, status));
        }
        Ok(())
    }
    pub(super) fn clear(
        &mut self,
        kernel: Kernel,
        buffer: ffi::cl_mem,
        words: usize,
    ) -> Result<(), Failure> {
        let bytes = words
            .checked_mul(size_of::<u64>())
            .ok_or(Failure::shape(kernel))?;
        let status = self.api.clear(self.handles.compute, buffer, bytes);
        if status != 0 {
            return Err(Failure::at(kernel, Phase::Clear, 0, status));
        }
        Ok(())
    }
    pub(super) fn launch(
        &mut self,
        kind: Kernel,
        args: &[Argument],
        work: usize,
    ) -> Result<(), Failure> {
        if self.count == 2 || work == 0 || args.len() != kind.arguments() as usize {
            return Err(Failure::shape(kind));
        }
        for (index, argument) in args.iter().enumerate() {
            let valid = match (kind, index, argument) {
                (Kernel::Node, 1, Argument::Uint(_)) | (Kernel::Node, 2, Argument::Ulong(_)) => {
                    true
                }
                (Kernel::Node, 1 | 2, _) => false,
                (_, _, Argument::Memory(handle)) => !handle.is_null(),
                _ => false,
            };
            if !valid {
                return Err(Failure::at(kind, Phase::Argument, index as u8, 0));
            }
        }
        let slot = &mut self.slots[self.count];
        slot.kind = kind;
        let (kernel, status) = self.api.create(self.handles.program, kind.name());
        slot.kernel = kernel;
        self.count += 1;
        if status != 0 || kernel.is_null() {
            return Err(Failure::at(kind, Phase::Create, 0, status));
        }
        let (count, bytes, status) = self.api.argument_count(kernel);
        if status != 0 || bytes != size_of::<u32>() || count != kind.arguments() {
            return Err(Failure::at(kind, Phase::Signature, 0, status));
        }
        for (index, &argument) in args.iter().enumerate() {
            let status = self.api.argument(kernel, index as u32, argument);
            if status != 0 {
                return Err(Failure::at(kind, Phase::Argument, index as u8, status));
            }
        }
        let (event, status) = self.api.enqueue(self.handles.compute, kernel, work);
        slot.event = event;
        if status != 0 || event.is_null() {
            return Err(Failure::at(kind, Phase::Enqueue, 0, status));
        }
        Ok(())
    }
    fn drain(&mut self) -> Result<(), Failure> {
        // Always attempt both queues. No allocation owner may retire if either
        // queue's completion is uncertain, including asynchronous launch failure.
        let copy = self.api.finish(self.handles.copy);
        let compute = self.api.finish(self.handles.compute);
        if copy != 0 {
            return Err(Failure::at(self.primary, Phase::FinishCopy, 0, copy));
        }
        if compute != 0 {
            return Err(Failure::at(self.primary, Phase::FinishCompute, 0, compute));
        }
        Ok(())
    }
    fn retire(&mut self) -> Result<(), Failure> {
        for slot in &mut self.slots[..self.count] {
            if !slot.event.is_null() {
                let status = self.api.release_event(slot.event);
                if status != 0 {
                    return Err(Failure::at(slot.kind, Phase::ReleaseEvent, 0, status));
                }
                slot.event = ptr::null_mut();
            }
            if !slot.kernel.is_null() {
                let status = self.api.release_kernel(slot.kernel);
                if status != 0 {
                    return Err(Failure::at(slot.kind, Phase::ReleaseKernel, 0, status));
                }
                slot.kernel = ptr::null_mut();
            }
        }
        self.closed = true;
        Ok(())
    }
    pub(super) fn complete(mut self) -> Result<Completion, Failure> {
        self.drain()?;
        let mut kernels = [None; 2];
        for (index, slot) in self.slots[..self.count].iter().enumerate() {
            let (state, bytes, status) = self.api.event_status(slot.event);
            if status != 0 || bytes != size_of::<i32>() || state != ffi::CL_COMPLETE {
                return Err(Failure::at(
                    slot.kind,
                    Phase::EventStatus,
                    0,
                    if status != 0 { status } else { state },
                ));
            }
            let (start, bytes, status) = self.api.timestamp(slot.event, false);
            if status != 0 || bytes != size_of::<u64>() {
                return Err(Failure::at(slot.kind, Phase::ProfileStart, 0, status));
            }
            let (end, bytes, status) = self.api.timestamp(slot.event, true);
            if status != 0 || bytes != size_of::<u64>() || end < start {
                return Err(Failure::at(slot.kind, Phase::ProfileEnd, 0, status));
            }
            kernels[index] = Some(Timing {
                label: slot.kind.label(),
                nanoseconds: end - start,
            });
        }
        if let Err(error) = self.retire() {
            // A failed reference release leaves its ownership uncertain. Do
            // not retry that release or let allocation accounting retire.
            fatal(error);
        }
        Ok(Completion { kernels })
    }
}
impl<A: Api, O> Drop for Scope<'_, A, O> {
    fn drop(&mut self) {
        if !self.closed {
            if let Err(error) = self.drain().and_then(|()| self.retire()) {
                fatal(error);
            }
        }
    }
}

fn fatal(error: Failure) -> ! {
    let diagnostic = error.diagnostic();
    unsafe extern "C" {
        fn write(fd: i32, buffer: *const core::ffi::c_void, bytes: usize) -> isize;
    }
    // SAFETY: a fixed stack diagnostic; Linux write consumes it synchronously.
    // Avoid an allocating error formatter or stderr initialization on this path.
    unsafe {
        let _ = write(2, diagnostic.bytes.as_ptr().cast(), diagnostic.len);
    }
    std::process::abort()
}
