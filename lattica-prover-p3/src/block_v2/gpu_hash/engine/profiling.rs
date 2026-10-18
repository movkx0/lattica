//! Diagnostic-only OpenCL resource metadata. No proof inputs are inspected.
use super::*;

pub(super) fn program(program: &compute::Program, device: compute::Device) -> Result<(), String> {
    use compute::enums::{
        KernelWorkGroupInfo as K, ProgramBuildInfo, ProgramInfo, ProgramInfoResult,
    };
    if !switch("LATTICA_PROFILE_TIMELINE")? {
        return Ok(());
    }
    let names = match program
        .info(ProgramInfo::KernelNames)
        .map_err(|e| e.to_string())?
    {
        ProgramInfoResult::KernelNames(names) => names,
        _ => return Err("missing OpenCL kernel names".into()),
    };
    for name in names.split(';') {
        let kernel =
            compute::core::create_kernel(program.as_core(), name).map_err(|e| e.to_string())?;
        let info = |kind| {
            compute::core::get_kernel_work_group_info(&kernel, device, kind)
                .map_err(|e| e.to_string())
        };
        eprintln!(
            "gpu_kernel_resources {}",
            serde_json::json!({
                "kernel": name, "max_workgroup": format!("{}", info(K::WorkGroupSize)?),
                "preferred_multiple": format!("{}", info(K::PreferredWorkGroupSizeMultiple)?),
                "static_local_bytes": format!("{}", info(K::LocalMemSize)?),
                "private_bytes": format!("{}", info(K::PrivateMemSize)?),
            })
        );
    }
    eprintln!(
        "gpu_program_build_log {}",
        serde_json::json!({
            "log": format!("{}", program.build_info(device, ProgramBuildInfo::BuildLog).map_err(|e| e.to_string())?),
        })
    );
    Ok(())
}

impl DeviceTimeline {
    pub(super) fn launch(&self, kernel: &str, global: usize, local: Option<usize>, bytes: usize) {
        if self.enabled {
            eprintln!(
                "gpu_launch {}",
                serde_json::json!({
                    "kernel": kernel, "global_items": global, "local_items": local,
                    "payload_bytes": bytes, "scope": "next_recorded_event",
                })
            );
        }
    }
}
