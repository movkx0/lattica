//! Allocation-free enclosing census for the fixed, serial full-workflow path.
//! This is neither a reservation nor dispatch authority. The original planner
//! reserves this owner before source work; phase backends reserve their complete
//! managed-device and host-tree allowances separately. Allocator metadata,
//! thread stacks and opaque driver storage remain under the external guards.
use super::{ProvingContext, PUBLIC_METADATA_LIMIT_BYTES};
use core::mem::{align_of, size_of};
use lattica_prover_p3::{
    block_v2::gpu_hash::device::ringct_runtime::StartupPlan,
    gpu_device::Identity as DeviceIdentity,
    proving::Policy,
};
use serde_json::Value;
use std::collections::BTreeMap;

type Error = &'static str;
const WORKER_HOST: u64 = 32 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const CONTEXT_RESERVE: u64 = 4 << 30;
const HOST_TREE: usize = 8 << 30;
const IDENTITY_KEYS: [&str; 7] = [
    "opencl_index", "uuid", "name", "pci", "global_bytes", "max_allocation_bytes", "driver",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkflowContextFootprint {
    /// Excludes the registry's existing shared 64 MiB envelope. The planner adds
    /// it once, alongside native owners and its own original-control storage.
    pub(crate) enclosing_host_bytes: u64,
    /// Actual Session allowance for each phase's complete managed charge,
    /// including startup constants and staging. It is not an enclosing charge:
    /// the caller sets enclosing.device to zero. This is not a VRAM measurement.
    pub(crate) managed_device_bytes: u64,
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or("workflow context host census overflow")
}

pub(super) fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or("workflow context host census overflow")
}

/// Pinned std BTree node bound shared with the source-graph collection model:
/// parent pointer + two u16 fields, eleven K/V slots, per-field alignment and
/// twelve child pointers. JSON objects here are insertion-only; one extra node
/// covers an insertion in progress. String/Value descendants are charged below.
pub(super) fn json_object_backing(entries: usize) -> Result<usize, Error> {
    if size_of::<usize>() != 8
        || align_of::<String>() > 8
        || align_of::<Value>() > 8
        || size_of::<serde_json::Map<String, Value>>() != size_of::<BTreeMap<String, Value>>()
        || size_of::<serde_json::Number>() != 16
    {
        return Err("workflow JSON census requires pinned scalar/BTree layouts");
    }
    if entries == 0 {
        return Ok(0);
    }
    mul(add(entries, 1)?, add(156, mul(11, add(size_of::<String>(), size_of::<Value>())?)?)?)
}

/// Empty/exact vectors and String serialization use the pinned allocator's
/// doubling growth with an eight-element minimum. Four times the logical
/// ceiling covers old/new growth overlap and a simultaneous serialization
/// input. The owned native source census handles arbitrary caller capacities.
pub(super) fn growing<T>(count: usize) -> Result<usize, Error> {
    if count == 0 {
        return Ok(0);
    }
    mul(mul(count.max(8), 4)?, size_of::<T>())
}

pub(super) fn object_keys(keys: &[&str]) -> Result<usize, Error> {
    keys.iter().try_fold(json_object_backing(keys.len())?, |bytes, key| {
        add(bytes, growing::<u8>(key.len())?)
    })
}

fn matches_optional(value: &Value, expected: Option<&str>) -> bool {
    match expected {
        Some(text) => value.as_str() == Some(text),
        None => value.is_null(),
    }
}

/// Exact key/value agreement and actual owned String capacities, without JSON
/// construction, serialization, cloning or a driver query.
pub(super) fn identity_json_bytes(
    value: &Value,
    identity: &DeviceIdentity,
) -> Result<usize, Error> {
    let map = value.as_object().ok_or("workflow device JSON must be an object")?;
    if map.len() != IDENTITY_KEYS.len()
        || IDENTITY_KEYS.iter().any(|key| !map.contains_key(*key))
        || map["opencl_index"].as_u64() != u64::try_from(identity.opencl_index).ok()
        || !matches_optional(&map["uuid"], identity.uuid.as_deref())
        || map["name"].as_str() != Some(identity.name.as_str())
        || !matches_optional(&map["pci"], identity.pci.as_deref())
        || map["global_bytes"].as_u64() != Some(identity.global_bytes)
        || map["max_allocation_bytes"].as_u64() != Some(identity.max_allocation_bytes)
        || map["driver"].as_str() != Some(identity.driver.as_str())
    {
        return Err("workflow device JSON differs from its owning Session");
    }
    map.iter().try_fold(json_object_backing(map.len())?, |bytes, (key, value)| {
        add(add(bytes, key.capacity())?, match value {
            Value::String(text) => text.capacity(),
            Value::Number(_) | Value::Null => 0,
            _ => return Err("workflow device JSON has an unsupported descendant"),
        })
    })
}

/// Failure diagnostics clone the fixed identity. Count both serialization
/// inputs and requested backing growth from source-limited identity lengths.
pub(super) fn cloned_identity_json_bytes(identity: &DeviceIdentity) -> Result<usize, Error> {
    let mut bytes = object_keys(&IDENTITY_KEYS)?;
    for text in [Some(&identity.name), Some(&identity.driver), identity.uuid.as_ref(), identity.pci.as_ref()]
        .into_iter().flatten()
    {
        bytes = add(bytes, growing::<u8>(text.len())?)?;
    }
    Ok(bytes)
}

fn identity_backing(identity: &DeviceIdentity) -> Result<usize, Error> {
    if identity.name.len() > 255 || identity.driver.len() > 255
        || identity.uuid.as_ref().is_some_and(|v| v.len() > 40)
        || identity.pci.as_ref().is_some_and(|v| v.len() > 37)
        || identity.name != "NVIDIA GeForce RTX 5080"
        || identity.global_bytes < MANAGED_DEVICE + CONTEXT_RESERVE
        || identity.max_allocation_bytes < 64 << 20
    {
        return Err("workflow device identity exceeds the fixed source profile");
    }
    [Some(&identity.name), Some(&identity.driver), identity.uuid.as_ref(), identity.pci.as_ref()]
        .into_iter().flatten().try_fold(0, |bytes, text| add(bytes, text.capacity()))
}

impl ProvingContext {
    pub(crate) fn workflow_enclosing_footprint(&self) -> Result<WorkflowContextFootprint, Error> {
        if cfg!(debug_assertions) || self.host_bytes != self.host_profile.worker_bytes()
            || self.request.policy != Policy::GpuRequired || !self.request.emit_report
            || !self.phases.workflow_census_is_unbound()?
            || !self.owned_workflow_observations.pristine()
        {
            return Err("workflow enclosing census requires an unused strict release context");
        }
        let session = self.session.as_ref().ok_or("workflow context requires its OpenCL Session")?;
        let limits = session.limits();
        if limits.host_bytes != self.host_bytes || limits.device_bytes != MANAGED_DEVICE
            || limits.max_rows == 0 || !limits.max_rows.is_power_of_two() || limits.max_rows > 1 << 22
            || session.workflow_context_reserve_bytes()? != CONTEXT_RESERVE
        {
            return Err("workflow Session differs from the fixed resource envelope");
        }
        let registry = self.registry.try_borrow().map_err(|_| "workflow registry busy")?;
        if registry.prepared.is_some() || !registry.metadata.is_empty()
            || !registry.identity_hints.entries.is_empty() || registry.registrations != 0
            || registry.trace.attempted() != 0 || registry.metadata_bytes > PUBLIC_METADATA_LIMIT_BYTES
        {
            return Err("workflow enclosing census requires a pristine registry");
        }
        let startup = StartupPlan::outer_host_v1().map_err(|_| "workflow startup source census")?;
        let core = startup.footprint();
        if core.retained_tree_host_bytes != HOST_TREE
            || core.driver_context_reserve as u64 != CONTEXT_RESERVE
        {
            return Err("workflow startup profile differs from the resource envelope");
        }
        startup.check_current_engine().map_err(|_| "workflow engine is not unused outer-host startup")?;
        let mut host = core.requested_host_bytes.checked_sub(core.retained_tree_host_bytes)
            .ok_or("workflow startup tree census underflow")?;
        let identity = session.device_identity();
        host = add(host, size_of::<Self>())?;
        host = add(host, super::owned_workflow_observation::additional_host_bytes()
            .map_err(|_| "owned workflow observation census overflow")?)?;
        host = add(host, crate::opencl::Session::workflow_transition_additional_host_bytes())?;
        host = add(host, super::phase_lifecycle::workflow_transition::additional_host_bytes())?;
        host = add(host, identity_backing(identity)?)?;
        host = add(host, identity_json_bytes(&self.device, identity)?)?;
        host = add(host, self.diagnostics.workflow_enclosing_bytes(identity, self.session_id, self.request.policy)?)?;
        Ok(WorkflowContextFootprint {
            enclosing_host_bytes: u64::try_from(host).map_err(|_| "workflow host census width")?,
            managed_device_bytes: limits.device_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
