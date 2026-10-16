//! Retained engine ownership. OpenCL wrappers own inline handles; opaque driver
//! allocations, initialization scratch and per-job sessions are separate phases.

use super::*;
use crate::block_v2::gpu_hash::cache_metadata::{add, arc_bytes, capacity};

pub(crate) const METADATA_BYTES: u64 = 8 << 20;
pub(crate) const MAX_MAPPED_BYTES: u64 = crate::host_memory::GPU_MAPPED_HOST_BYTES;
pub(crate) const RETAINED_HOST_BYTES: u64 = METADATA_BYTES + MAX_MAPPED_BYTES;
const SELECTOR_BYTES: usize = 256;
const CONTAINER_SLOTS: usize = 4;

pub(super) fn check_selection(selection: &[Option<std::ffi::OsString>; 2]) -> Result<(), String> {
    if selection
        .iter()
        .flatten()
        .any(|value| value.capacity() > SELECTOR_BYTES)
    {
        return Err("retained GPU selector storage allowance".into());
    }
    Ok(())
}

fn container<T>(count: usize, maximum: usize) -> Result<usize, String> {
    if count > maximum {
        return Err("retained GPU container capacity".into());
    }
    capacity::<T>(count)
}

/// A bounded fallible allocation, reused after reporting drains the log. The
/// metadata envelope also covers old/new backing overlap during this reserve.
pub(super) fn prepare_timeline(events: &mut Vec<DeviceInterval>) -> Result<(), String> {
    container::<DeviceInterval>(events.capacity(), MAX_DEVICE_EVENTS)?;
    if events.capacity() < MAX_DEVICE_EVENTS {
        events
            .try_reserve_exact(MAX_DEVICE_EVENTS - events.len())
            .map_err(|_| "GPU timing log allocation failed")?;
    }
    container::<DeviceInterval>(events.capacity(), MAX_DEVICE_EVENTS)?;
    Ok(())
}

#[cfg(feature = "gpu")]
pub(super) fn check_workspace(workspace: &Workspace, slots: usize) -> Result<usize, String> {
    if workspace.input.len() != slots || !matches!(slots, 1 | 2) {
        return Err("retained GPU workspace shape".into());
    }
    container::<Allocation>(workspace.input.capacity(), CONTAINER_SLOTS)
}

#[cfg(feature = "gpu")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetainedHost {
    metadata: usize,
    mapped: usize,
}

#[cfg(feature = "gpu")]
impl RetainedHost {
    fn total(self) -> Result<usize, String> {
        add(self.metadata, self.mapped)
    }

    fn admit(self, limit: u64) -> Result<(), String> {
        if self.metadata as u64 > METADATA_BYTES
            || self.mapped as u64 > MAX_MAPPED_BYTES
            || self.total()? as u64 > limit
        {
            return Err("retained GPU engine host allowance".into());
        }
        Ok(())
    }
}

#[cfg(feature = "gpu")]
fn census(engine: &Engine) -> Result<RetainedHost, String> {
    check_selection(&engine.device_selection)?;
    // Includes every inline option, buffer/queue/program handle and statistics
    // field, whether populated or not. Charge each shared allocation once.
    let mut metadata = add(
        core::mem::size_of::<OnceLock<Mutex<Option<Engine>>>>(),
        core::mem::size_of::<Mutex<()>>(),
    )?;
    metadata = add(metadata, arc_bytes::<Mutex<Accounting>>())?;
    metadata = add(metadata, arc_bytes::<JobLease>())?;
    for value in engine.device_selection.iter().flatten() {
        metadata = add(metadata, value.capacity())?;
    }
    metadata = add(
        metadata,
        container::<DeviceInterval>(engine.timeline.events.capacity(), MAX_DEVICE_EVENTS)?,
    )?;
    metadata = add(
        metadata,
        container::<Staging>(engine.staging.capacity(), CONTAINER_SLOTS)?,
    )?;
    if engine.staging.len() != engine.mode.slots() {
        return Err("retained GPU staging shape".into());
    }
    let mut mapped = 0;
    for slot in &engine.staging {
        // The synchronous BufferMapCmd path constructs MemMap without a wait
        // list. A future change that owns such a list needs its own census.
        if slot.map.unmap_wait_events().is_some() || slot.map.is_unmapped() {
            return Err("retained GPU mapping ownership".into());
        }
        mapped = add(mapped, capacity::<u64>(slot.map.len())?)?;
    }
    if mapped != engine.limits.staging_bytes {
        return Err("retained GPU mapped storage shape".into());
    }
    if let Some(workspace) = &engine.workspace {
        metadata = add(metadata, check_workspace(workspace, engine.mode.slots())?)?;
    }
    Ok(RetainedHost { metadata, mapped })
}

#[cfg(feature = "gpu")]
pub(super) fn admit(engine: &Engine) -> Result<(), String> {
    let stored = census(engine)?;
    stored.admit(RETAINED_HOST_BYTES)?;
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!("bounded_gpu_engine_host metadata_bytes={} mapped_staging_bytes={} host_bytes={} limit_bytes={} initialization_job_and_driver_separate=true",
            stored.metadata, stored.mapped, stored.total()?, RETAINED_HOST_BYTES);
    }
    Ok(())
}

/// Opening/FRI can grow the workspace and timing log. Keep the established
/// metadata envelope, including reserve overlap, rather than only their current
/// capacities. Mapped staging is fixed for the lifetime of this engine.
pub(super) fn opening_reservation(engine: &Engine) -> Result<usize, String> {
    #[cfg(feature = "gpu")]
    {
        let stored = census(engine)?;
        stored.admit(RETAINED_HOST_BYTES)?;
        add(METADATA_BYTES as usize, stored.mapped)
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = engine;
        Err("opening engine host reservation requires OpenCL".into())
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;

    #[test]
    fn timeline_capacity_survives_drain_without_growth() {
        let mut timeline = DeviceTimeline {
            enabled: true,
            events: Vec::new(),
            dropped: 0,
        };
        for n in 0..MAX_DEVICE_EVENTS + 2 {
            timeline
                .record_interval("test", n as u64, n as u64 + 1)
                .unwrap();
        }
        assert_eq!(timeline.events.len(), MAX_DEVICE_EVENTS);
        assert_eq!(timeline.events.capacity(), MAX_DEVICE_EVENTS);
        assert_eq!(timeline.dropped, 2);
        let pointer = timeline.events.as_ptr();
        drop(timeline.events.drain(..));
        for n in 0..100 {
            timeline.record_interval("test", n, n + 1).unwrap();
        }
        assert_eq!(timeline.events.as_ptr(), pointer);
        let mut excessive = Vec::with_capacity(MAX_DEVICE_EVENTS + 1);
        assert!(prepare_timeline(&mut excessive).is_err());
        assert!(excessive.is_empty());
    }

    #[test]
    fn selector_spare_capacity_is_bounded() {
        let mut value = std::ffi::OsString::with_capacity(SELECTOR_BYTES);
        value.push("0");
        check_selection(&[None, Some(value)]).unwrap();
        let mut value = std::ffi::OsString::with_capacity(SELECTOR_BYTES + 1);
        value.push("0");
        assert!(check_selection(&[None, Some(value)]).is_err());
    }

    #[test]
    fn engine_host_envelope_covers_inline_owners_and_timeline_reallocation() {
        let base = core::mem::size_of::<OnceLock<Mutex<Option<Engine>>>>()
            + core::mem::size_of::<Mutex<()>>()
            + arc_bytes::<Mutex<Accounting>>()
            + arc_bytes::<JobLease>()
            + 2 * SELECTOR_BYTES
            + CONTAINER_SLOTS
                * (core::mem::size_of::<Staging>() + core::mem::size_of::<Allocation>());
        let timeline = capacity::<DeviceInterval>(MAX_DEVICE_EVENTS).unwrap();
        assert!((base + 2 * timeline) as u64 <= METADATA_BYTES);
        assert_eq!(RETAINED_HOST_BYTES, 72 << 20);
        let value = RetainedHost {
            metadata: base + timeline,
            mapped: MAX_MAPPED_BYTES as usize,
        };
        value.admit(value.total().unwrap() as u64).unwrap();
        assert!(value.admit(value.total().unwrap() as u64 - 1).is_err());
        assert!(RetainedHost {
            metadata: METADATA_BYTES as usize + 1,
            mapped: 0
        }
        .admit(u64::MAX)
        .is_err());
        assert!(RetainedHost {
            metadata: 0,
            mapped: MAX_MAPPED_BYTES as usize + 1
        }
        .admit(u64::MAX)
        .is_err());
        eprintln!("engine_host_envelope base_bytes={base} timeline_bytes={timeline} timeline_overlap_bytes={} metadata_limit_bytes={METADATA_BYTES} mapped_limit_bytes={MAX_MAPPED_BYTES} host_limit_bytes={RETAINED_HOST_BYTES}", base + 2 * timeline);
    }

    #[test]
    #[ignore = "requires an explicitly selected GPU and exclusive device lease"]
    fn retained_engine_census_checks_mapped_storage_and_spare_capacity_without_gpu_work() {
        initialize_mode(
            Limits {
                managed_bytes: 64 * MIB,
                tile_bytes: MIB,
                staging_bytes: 32 * 1024,
            },
            TransferMode::Serial,
        )
        .unwrap();
        {
            let mut slot = ENGINE.get().unwrap().lock().unwrap();
            let engine = slot.as_mut().unwrap();
            let plan = plan_slots(64, 4, engine.limits, engine.max_alloc, 1).unwrap();
            engine.workspace(plan).unwrap();
            assert!(engine.timeline.enabled);
            for n in 0..MAX_DEVICE_EVENTS + 2 {
                engine
                    .timeline
                    .record_interval("test", n as u64, n as u64 + 1)
                    .unwrap();
            }
            let before = *engine.accounting.lock().unwrap();
            let uploads = engine.stats.uploaded_bytes;
            let observed = census(engine).unwrap();
            assert_eq!(observed.mapped, 32 * 1024);
            observed.admit(observed.total().unwrap() as u64).unwrap();
            assert!(observed
                .admit(observed.total().unwrap() as u64 - 1)
                .is_err());
            let saved = core::mem::replace(
                &mut engine.timeline.events,
                Vec::with_capacity(MAX_DEVICE_EVENTS + 1),
            );
            assert!(census(engine).is_err());
            engine.timeline.events = saved;
            admit(engine).unwrap();
            let after = *engine.accounting.lock().unwrap();
            assert_eq!(before.allocations, after.allocations);
            assert_eq!(before.live, after.live);
            assert_eq!(uploads, engine.stats.uploaded_bytes);
            eprintln!("engine_host_census_verified metadata_bytes={} mapped_bytes={} allocations_unchanged=true uploads_unchanged=true", observed.metadata, observed.mapped);
        }
        shutdown().unwrap();
    }
}
