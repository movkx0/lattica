//! One explicitly admitted OpenCL lifetime for serial recursive merges.
use super::*;
use lattica_prover_p3::gpu_device::Identity;
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

static ACTIVE: AtomicBool = AtomicBool::new(false);

fn check_device_envelope(
    managed: u64,
    context: u64,
    global: u64,
    max_allocation: u64,
) -> Result<(), String> {
    require(max_allocation > 0, "device reports no allocation capacity")?;
    require(
        context >= 512 << 20,
        "GPU context allowance below engine minimum",
    )?;
    require(
        managed
            .checked_add(context)
            .is_some_and(|bytes| bytes <= global),
        "managed GPU budget plus driver reserve exceeds device memory",
    )
}

/// Process-exclusive OpenCL owner. Dropping it releases the GPU even on errors.
/// Call `finish` to propagate shutdown errors and capture allocation telemetry.
/// Host allowances and managed VRAM are separate; the external runner must also
/// enforce a whole-process RAM cap. GPU-required worker contexts dispatch native
/// component proofs and private spend creation through this OpenCL session.
pub struct Session {
    limits: Limits,
    device: Identity,
    max_work_group_size: usize,
    context_bytes: u64,
    closed: bool,
    _thread: PhantomData<Rc<()>>,
}

impl Session {
    pub fn start(limits: Limits) -> Result<Self, String> {
        check_environment(limits)?;
        require(
            gpu_hash::report("recursive session admission").is_none(),
            "OpenCL session requires a fresh engine; one is already initialized",
        )?;
        let (_, device, identity) = lattica_prover_p3::gpu_device::select()?;
        let max_work_group_size = device.max_wg_size().map_err(err)?;
        require(
            max_work_group_size >= REQUIRED_DEVICE_WORK_GROUP_SIZE,
            "selected OpenCL device cannot support the required workgroup size",
        )?;
        let context_bytes = match std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES") {
            Ok(value) => value.parse::<u64>().map_err(err)?,
            Err(std::env::VarError::NotPresent) => 4_u64 << 30,
            Err(error) => return Err(err(error)),
        };
        check_device_envelope(
            limits.device_bytes,
            context_bytes,
            identity.global_bytes,
            identity.max_allocation_bytes,
        )?;
        ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "an OpenCL recursive session is already active".to_owned())?;
        let mut session = Self {
            limits,
            device: identity,
            max_work_group_size,
            context_bytes,
            closed: false,
            _thread: PhantomData,
        };
        if let Err(error) = initialize() {
            let cleanup = session.close();
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; GPU shutdown failed: {cleanup}"),
            });
        }
        Ok(session)
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Public identity only; prepared device allocations remain session-owned.
    pub fn device_identity(&self) -> &Identity {
        &self.device
    }

    /// Reject unsupported geometry before registration or proving allocation.
    pub fn check_rows(&self, rows: usize) -> Result<(), String> {
        self.limits.check_rows(rows)
    }

    fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        // A retained proving allocation can make shutdown fail. Keep ownership
        // claimed in that case; a second session must not attach to that engine.
        gpu_hash::shutdown()?;
        self.closed = true;
        ACTIVE.store(false, Ordering::Release);
        Ok(())
    }

    pub fn finish(mut self) -> Result<Value, String> {
        let result = (|| {
            gpu_hash::drain()?;
            let snapshot = gpu_hash::report("recursive OpenCL session complete")
                .ok_or("missing initialized OpenCL engine observations")?;
            require(
                snapshot.commits > 0 && snapshot.allocations > 0,
                "no completed GPU commitment work observed",
            )?;
            require(
                u64::try_from(snapshot.managed_peak_bytes).map_err(err)?
                    <= self.limits.device_bytes,
                "GPU managed allocation peak exceeded the admitted budget",
            )?;
            Ok(json!({
                "device": self.device,
                "host_allowance_bytes": self.limits.host_bytes,
                "device_allowance_bytes": self.limits.device_bytes,
                "gpu_context_allowance_bytes": self.context_bytes,
                "max_rows": self.limits.max_rows,
                "device_max_work_group_size": self.max_work_group_size,
                "commits": snapshot.commits,
                "allocations": snapshot.allocations,
                "managed_peak_bytes": snapshot.managed_peak_bytes,
                "uploaded_bytes": snapshot.uploaded_bytes,
                "downloaded_bytes": snapshot.downloaded_bytes,
                "telemetry_scope": "Observed OpenCL allocations and commitments; proof acceptance and strict stage coverage are checked separately"
            }))
        })();
        match (result, self.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(format!("GPU shutdown failed: {error}")),
            (Err(error), Err(cleanup)) => Err(format!("{error}; GPU shutdown failed: {cleanup}")),
        }
    }

    /// The worker supplies only its count of fully validated native-spend
    /// receipts. This path does not claim STARK or commitment completion.
    pub(crate) fn finish_native_spend(self, validated_reports: u64) -> Result<Value, String> {
        self.finish_native_operation_or_cleanup(Some(validated_reports))
    }

    /// Explicit teardown for admission failures or incomplete work. No success
    /// receipt is inferred from allocations, kernels or a clean shutdown.
    pub(crate) fn cleanup_only(self) -> Result<Value, String> {
        self.finish_native_operation_or_cleanup(None)
    }

    fn finish_native_operation_or_cleanup(
        mut self,
        validated_reports: Option<u64>,
    ) -> Result<Value, String> {
        let result = (|| {
            gpu_hash::drain()?;
            let snapshot = gpu_hash::report("native operation session teardown")
                .ok_or("missing initialized OpenCL engine observations")?;
            if let Some(reports) = validated_reports {
                require(reports > 0, "native spend shutdown requires a validated receipt")?;
                require(
                    snapshot.allocations > 0,
                    "native spend receipt lacks observed GPU allocations",
                )?;
            }
            require(
                u64::try_from(snapshot.managed_peak_bytes).map_err(err)?
                    <= self.limits.device_bytes,
                "GPU managed allocation peak exceeded the admitted budget",
            )?;
            Ok(json!({
                "device": self.device,
                "host_allowance_bytes": self.limits.host_bytes,
                "device_allowance_bytes": self.limits.device_bytes,
                "gpu_context_allowance_bytes": self.context_bytes,
                "max_rows": self.limits.max_rows,
                "device_max_work_group_size": self.max_work_group_size,
                "commits": snapshot.commits,
                "allocations": snapshot.allocations,
                "managed_peak_bytes": snapshot.managed_peak_bytes,
                "uploaded_bytes": snapshot.uploaded_bytes,
                "downloaded_bytes": snapshot.downloaded_bytes,
                "queue_drained": true,
                "completion_claimed": validated_reports.is_some(),
                "completion_scope": if validated_reports.is_some() {
                    "native_matrict_spend"
                } else {
                    "cleanup_only"
                },
                "validated_native_spend_reports": validated_reports.unwrap_or(0),
                "stark_completion_claimed": false,
                "telemetry_scope": "Observed GPU resources and verified teardown; successful native operation requires separate validated worker receipts"
            }))
        })();
        // shutdown() checks retained leases, drains queues and verifies that no
        // managed allocation survives context destruction before returning Ok.
        match (result, self.close()) {
            (Ok(mut value), Ok(())) => {
                value["context_closed"] = json!(true);
                Ok(value)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(format!("GPU shutdown failed: {error}")),
            (Err(error), Err(cleanup)) => Err(format!("{error}; GPU shutdown failed: {cleanup}")),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("opencl_session_cleanup_failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::check_device_envelope;
    #[test]
    fn admission_distinguishes_managed_total_and_single_allocation() {
        let gib = 1_u64 << 30;
        let actual_device = 16303_u64 << 20;
        assert!(check_device_envelope(8 * gib, 4 * gib, actual_device, gib).is_ok());
        assert!(check_device_envelope(12 * gib, 4 * gib, actual_device, gib).is_err());
        assert!(check_device_envelope(8 * gib, 4 * gib, 12 * gib, gib).is_ok());
        assert!(check_device_envelope(u64::MAX, gib, u64::MAX, gib).is_err());
        assert!(check_device_envelope(gib, (512 << 20) - 1, actual_device, gib).is_err());
        assert!(check_device_envelope(gib, gib, actual_device, 0).is_err());
    }
}
