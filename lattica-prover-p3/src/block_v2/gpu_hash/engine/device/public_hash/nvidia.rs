//! Optional device instructions for one eight-lane public sponge.
//! Other OpenCL devices compile the portable local-memory implementation.
pub(crate) fn source_prefix(device: ocl::Device) -> &'static str {
    use ocl::core::{DeviceInfo, DeviceInfoResult};
    if !matches!(
        device.info(DeviceInfo::VendorId),
        Ok(DeviceInfoResult::VendorId(0x10de))
    ) {
        return "";
    }
    let word = |parameter| {
        ocl::core::get_device_info_raw(device, parameter)
            .ok()
            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
            .map(u32::from_ne_bytes)
    };
    // CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV and CL_DEVICE_WARP_SIZE_NV.
    // shfl.sync requires Volta (SM 7) or newer. Missing capabilities keep the
    // portable kernel; the UUID/driver and native image bind timing admission.
    if word(0x4000).is_some_and(|major| major >= 7) && word(0x4003) == Some(32) {
        "#define LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE 1\n"
    } else {
        ""
    }
}
