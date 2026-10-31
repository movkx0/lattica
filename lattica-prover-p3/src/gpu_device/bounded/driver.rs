use super::{ffi, Field};
use core::ptr;

// Private seam: only Driver touches OpenCL, and tests supply fixed fake handles.
pub(super) trait Api {
    fn platforms(&mut self, output: &mut [ffi::cl_platform_id]) -> (usize, i32);
    fn devices(
        &mut self,
        platform: ffi::cl_platform_id,
        output: &mut [ffi::cl_device_id],
    ) -> (usize, i32);
    fn info(&mut self, device: ffi::cl_device_id, field: Field, output: &mut [u8]) -> (usize, i32);
}
pub(super) struct Driver;
impl Api for Driver {
    fn platforms(&mut self, output: &mut [ffi::cl_platform_id]) -> (usize, i32) {
        let mut count = 0;
        // SAFETY: nonempty output contains exactly the supplied number of
        // writable slots; an empty query passes null. No driver count sizes it.
        let status = unsafe {
            ffi::clGetPlatformIDs(
                output.len() as u32,
                if output.is_empty() {
                    ptr::null_mut()
                } else {
                    output.as_mut_ptr()
                },
                &mut count,
            )
        };
        (count as usize, status)
    }
    fn devices(
        &mut self,
        platform: ffi::cl_platform_id,
        output: &mut [ffi::cl_device_id],
    ) -> (usize, i32) {
        let mut count = 0;
        // SAFETY: platform came from bounded successful enumeration; output
        // capacity is fixed and checked before this fill call by its caller.
        let status = unsafe {
            ffi::clGetDeviceIDs(
                platform,
                ffi::CL_DEVICE_TYPE_GPU,
                output.len() as u32,
                if output.is_empty() {
                    ptr::null_mut()
                } else {
                    output.as_mut_ptr()
                },
                &mut count,
            )
        };
        (count as usize, status)
    }
    fn info(&mut self, device: ffi::cl_device_id, field: Field, output: &mut [u8]) -> (usize, i32) {
        let mut size = 0;
        // SAFETY: device came from enumeration. The fixed, aligned output has
        // exactly the advertised capacity; null is used only for size queries.
        let status = unsafe {
            ffi::clGetDeviceInfo(
                device,
                field.code(),
                output.len(),
                if output.is_empty() {
                    ptr::null_mut()
                } else {
                    output.as_mut_ptr().cast()
                },
                &mut size,
            )
        };
        (size, status)
    }
}
