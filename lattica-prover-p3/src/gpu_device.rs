//! Shared OpenCL identity selection. NVIDIA and OpenCL enumeration orders differ.
use ocl::{
    core::{DeviceInfo, DeviceInfoResult},
    Device, Platform,
};
#[derive(Clone, Debug, serde::Serialize)]
pub struct Identity {
    pub opencl_index: usize,
    pub uuid: Option<String>,
    pub name: String,
    pub pci: Option<String>,
    pub global_bytes: u64,
    pub max_allocation_bytes: u64,
    pub driver: String,
}
fn uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 16 {
        return None;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "GPU-{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
pub fn devices() -> Result<Vec<(Platform, Device, Identity)>, String> {
    let mut result = Vec::new();
    for platform in Platform::list() {
        for device in
            Device::list(platform, Some(ocl::flags::DEVICE_TYPE_GPU)).map_err(|e| e.to_string())?
        {
            let info = |kind| device.info(kind).map_err(|e| e.to_string());
            let global_bytes = match info(DeviceInfo::GlobalMemSize)? {
                DeviceInfoResult::GlobalMemSize(n) => n,
                _ => return Err("missing global memory".into()),
            };
            let max_allocation_bytes = match info(DeviceInfo::MaxMemAllocSize)? {
                DeviceInfoResult::MaxMemAllocSize(n) => n,
                _ => return Err("missing max allocation".into()),
            };
            let uuid = ocl::core::get_device_info_raw(device, 0x106A)
                .ok()
                .and_then(|v| uuid(&v));
            let pci = ocl::core::get_device_info_raw(device, 0x410F)
                .ok()
                .filter(|v| v.len() == 16)
                .map(|v| {
                    let words: Vec<_> = v
                        .chunks_exact(4)
                        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
                        .collect();
                    format!(
                        "{:04x}:{:02x}:{:02x}.{}",
                        words[0], words[1], words[2], words[3]
                    )
                });
            let identity = Identity {
                opencl_index: result.len(),
                uuid,
                pci,
                global_bytes,
                max_allocation_bytes,
                name: device.name().map_err(|e| e.to_string())?,
                driver: info(DeviceInfo::DriverVersion)?.to_string(),
            };
            result.push((platform, device, identity));
        }
    }
    Ok(result)
}
pub fn select() -> Result<(Platform, Device, Identity), String> {
    let entries = devices()?;
    let index = std::env::var("LATTICA_V2_GPU_DEVICE")
        .ok()
        .map(|s| s.parse::<usize>().map_err(|_| "invalid OpenCL GPU index"))
        .transpose()?;
    let requested = std::env::var("LATTICA_GPU_DEVICE_UUID").ok();
    let selected = match requested {
        Some(ref id) => entries
            .iter()
            .position(|(_, _, d)| d.uuid.as_ref().is_some_and(|u| u.eq_ignore_ascii_case(id)))
            .ok_or("requested GPU UUID unavailable to OpenCL")?,
        None => index.unwrap_or(0),
    };
    if index.is_some_and(|i| i != selected) {
        return Err("GPU UUID and OpenCL index selectors disagree".into());
    }
    entries
        .into_iter()
        .nth(selected)
        .ok_or("selected OpenCL GPU unavailable".into())
}
