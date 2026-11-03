//! Bounded raw graph witness preparation, separate from native STARK proving.
//!
//! The caller may retain raw node values and commitment roots in its graph.
//! No operation accepts, constructs on the host, or downloads an AIR trace.
use crate::block_v2::gpu_hash::device::DeviceSession;
use crate::proving::{
    Backend, Capabilities, CoverageScope, Policy, Profile, Report, Request, Run, Stage,
};
use std::cell::Cell;

pub const WITNESS_PREPARATION_ENTRY: &str = "pq_graph_witness_preparation";

/// An operation borrows the serial preparation session. This is not a prover,
/// and its report cannot substitute for any source or component proof.
pub struct OperationContext<'a> {
    pub(crate) session: &'a DeviceSession,
    pub(crate) run: &'a Run,
    pub(crate) host_allowance: usize,
    failed: Cell<bool>,
    #[cfg(feature = "gpu")]
    pub(super) workspace: std::cell::RefCell<Option<crate::block_v2::gpu_hash::engine::device::preparation_storage::Workspace>>,
}
/// Additional storage that a caller must fund before opting into scope reuse.
#[derive(Clone, Copy, Debug)]
pub struct RawPreparationWorkspaceStorage { pub host_bytes: usize, pub device_bytes: usize }
impl RawPreparationWorkspaceStorage {
    pub const fn fixed() -> Self {
        #[cfg(feature = "gpu")]
        { use crate::block_v2::gpu_hash::engine::device::preparation_storage as storage;
          Self { host_bytes: storage::HOST_BYTES, device_bytes: storage::DEVICE_BYTES } }
        #[cfg(not(feature = "gpu"))]
        { Self { host_bytes: 0, device_bytes: 0 } }
    }
}

struct PoisonOnDrop<'a> {
    failed: &'a Cell<bool>,
    complete: bool,
}
impl Drop for PoisonOnDrop<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.failed.set(true);
        }
    }
}
fn checked_operation<T>(
    failed: &Cell<bool>,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    if failed.get() {
        return Err("GPU witness preparation is unusable after an operation failure".into());
    }
    let mut guard = PoisonOnDrop {
        failed,
        complete: false,
    };
    let value = operation()?;
    if failed.get() {
        return Err("GPU witness preparation suppressed an operation failure".into());
    }
    guard.complete = true;
    Ok(value)
}

/// Run graph preparation under an existing initialized OpenCL engine. The
/// worker must release its prepared program and serialize access before entry.
/// The capacity lease remains live until every operation and readback ends.
/// `host_bytes` bounds operation inputs, packing and readback; the caller must
/// separately account for its retained graph and fixture storage.
pub fn with_operations<T>(
    host_bytes: usize,
    request: Request,
    operation: impl FnOnce(&OperationContext<'_>) -> Result<T, String>,
) -> Result<(T, Report), String> {
    if request.policy != Policy::GpuRequired {
        return Err("raw witness preparation requires an explicit GPU-required request".into());
    }
    if host_bytes == 0 || host_bytes as u64 > 32u64 << 30 {
        return Err("raw witness operation host allowance must be in 1..=32 GiB".into());
    }
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, false, false)
        .scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    let run =
        Run::new(WITNESS_PREPARATION_ENTRY, request, capabilities).map_err(|e| e.to_string())?;
    let session = DeviceSession::new()?;
    let _capacity = session.reserve_proof_capacity()?;
    let profile = crate::proving::preparation_profile::Scope::begin();
    let context = OperationContext {
        session: &session,
        run: &run,
        host_allowance: host_bytes,
        failed: Cell::new(false),
        #[cfg(feature = "gpu")]
        workspace: std::cell::RefCell::new(None),
    };
    let value = context.execute(|| operation(&context))?;
    drop(context);
    let report = run.finish(true).map_err(|e| e.to_string())?;
    profile.complete();
    Ok((value, report))
}

struct RawNode([u64; 256]);
impl Drop for RawNode {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: every word is exclusively owned live temporary storage.
            unsafe { std::ptr::write_volatile(word, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl OperationContext<'_> {
    pub fn enable_reusable_storage(&self) -> Result<(), String> {
        self.enable_reusable_storage_with(true)
    }
    /// GPU scalar reference for source-bound research qualification only.
    #[cfg(feature = "ringct-research-quota")]
    pub fn enable_scalar_field_storage_for_qualification(&self) -> Result<(), String> {
        self.enable_reusable_storage_with(false)
    }
    fn enable_reusable_storage_with(&self, cooperative_fields: bool) -> Result<(), String> {
        #[cfg(not(feature = "gpu"))]
        let _ = cooperative_fields;
        self.execute(|| {
            #[cfg(feature = "gpu")]
            {
                if self.workspace.try_borrow().map_err(|_| "reentrant preparation workspace")?.is_some() { return Ok(()); }
                self.admit_host_bytes(RawPreparationWorkspaceStorage::fixed().host_bytes)?;
                let workspace = self.session.preparation_workspace(cooperative_fields)?;
                *self.workspace.try_borrow_mut().map_err(|_| "reentrant preparation workspace")? = Some(workspace);
                Ok(())
            }
            #[cfg(not(feature = "gpu"))]
            { Err("raw preparation workspace requires OpenCL".into()) }
        })
    }
    /// All public operations use this boundary, including their admission and
    /// conversions. A caught error or panic cannot yield a successful report.
    pub(crate) fn execute<T>(
        &self,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        checked_operation(&self.failed, operation)
    }

    pub(crate) fn admit_host_bytes(&self, bytes: usize) -> Result<(), String> {
        #[cfg(feature = "gpu")]
        let retained = if self.workspace.try_borrow().map_err(|_| "reentrant preparation workspace")?.is_some() {
            RawPreparationWorkspaceStorage::fixed().host_bytes
        } else { 0 };
        #[cfg(not(feature = "gpu"))]
        let retained = 0;
        if bytes.checked_add(retained).is_none_or(|total| total > self.host_allowance) {
            return Err("raw witness operation exceeds host allowance".into());
        }
        Ok(())
    }

    /// The existing canonical polynomial root, including modulus and length.
    /// Residue validity and every Poseidon permutation execute on the device.
    pub fn commit_canonical_node(
        &self,
        values: &[u64; 256],
        modulus: u64,
    ) -> Result<[u64; 4], String> {
        self.execute(|| {
            self.admit_host_bytes((256 + 9) * 8)?;
            #[cfg(feature = "gpu")]
            if let Some(result) = self.session.prepared_commit_node(&self.workspace, 0, values, modulus, self.run) { return result; }
            self.session
                .pq_operation_commit_node(0, values, modulus, self.host_allowance, self.run)
        })
    }

    /// Signed coefficients cross the boundary as raw i64 bit patterns. Their
    /// Goldilocks representatives and bound validation are computed on GPU.
    pub fn commit_signed_node(&self, values: &[i64; 256]) -> Result<[u64; 4], String> {
        self.execute(|| {
            self.admit_host_bytes((2 * 256 + 9) * 8)?;
            let mut raw = RawNode([0; 256]);
            for (word, &value) in raw.0.iter_mut().zip(values) {
                *word = value as u64;
            }
            #[cfg(feature = "gpu")]
            if let Some(result) = self.session.prepared_commit_node(&self.workspace, 1, &raw.0, 0, self.run) { return result; }
            self.session
                .pq_operation_commit_node(1, &raw.0, 0, self.host_allowance, self.run)
        })
    }

    /// Existing 32-byte framing and little-endian byte-pair absorption.
    pub fn commit_bytes32_node(&self, values: &[u8; 32]) -> Result<[u64; 4], String> {
        self.execute(|| {
            // RawNode has fixed storage even though only 32 words are used.
            self.admit_host_bytes(32 + (256 + 9) * 8)?;
            let mut raw = RawNode([0; 256]);
            for (word, &value) in raw.0.iter_mut().zip(values) {
                *word = u64::from(value);
            }
            #[cfg(feature = "gpu")]
            if let Some(result) = self.session.prepared_commit_node(&self.workspace, 2, &raw.0[..32], 0, self.run) { return result; }
            self.session
                .pq_operation_commit_node(2, &raw.0[..32], 0, self.host_allowance, self.run)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_preparation_rejects_cpu_policy_before_callback() {
        let result = with_operations(
            8192,
            Request {
                policy: Policy::CpuRequired,
                emit_report: false,
            },
            |_| -> Result<(), String> { panic!("CPU policy reached GPU preparation") },
        );
        assert!(result.is_err());
    }

    #[test]
    fn raw_preparation_rejects_zero_allowance_before_engine_access() {
        let result = with_operations(
            0,
            Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            },
            |_| -> Result<(), String> { panic!("invalid allowance reached GPU preparation") },
        );
        assert!(result.is_err());
    }

    #[test]
    fn ignored_failure_poisoning_survives_outer_success() {
        let failed = Cell::new(false);
        let result = checked_operation(&failed, || {
            let _: Result<(), String> = checked_operation(&failed, || Err("invalid input".into()));
            Ok(())
        });
        assert!(result.is_err());
        assert!(checked_operation(&failed, || Ok(())).is_err());
    }

    #[test]
    fn caught_operation_panic_poisoning_survives() {
        let failed = Cell::new(false);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), String> = checked_operation(&failed, || panic!("operation panic"));
        }));
        assert!(panic.is_err());
        assert!(checked_operation(&failed, || Ok(())).is_err());
    }
}
