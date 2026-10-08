//! Host-wide OpenCL slot reservations, compatible with the exclusive device lease.
//! Every live slot on a device must use the same reservation, so independently
//! launched controllers cannot overbook the device by choosing different caps.
use crate::block_v2::worker_memory::{lock, lock_file, private_directory};
use std::{fs::File, io::{Read, Seek, SeekFrom, Write}, path::Path};

pub(super) fn workers() -> Result<usize, String> {
    match std::env::var("LATTICA_V2_GPU_WORKERS") {
        Err(std::env::VarError::NotPresent) => Ok(1),
        Ok(v) => v.parse().ok().filter(|n| (1..=3).contains(n))
            .ok_or_else(|| "GPU workers must be 1..3".into()),
        Err(_) => Err("invalid GPU worker count".into()),
    }
}

pub(super) fn check_capacity(workers: usize, managed: usize, context: usize, total: usize) -> Result<(), String> {
    let headroom = if workers > 1 { 1 << 30 } else { 0 };
    let required = managed.checked_add(context).and_then(|n| n.checked_mul(workers))
        .and_then(|n| n.checked_add(headroom)).ok_or("shared GPU reservation overflow")?;
    if required > total { return Err("aggregate GPU slots, contexts and device headroom exceed VRAM".into()); }
    Ok(())
}

pub(super) fn acquire(dir: &Path, workers: usize, managed: usize, context: usize) -> Result<File, String> {
    if !(2..=3).contains(&workers) { return Err("shared device slots must be 2..3".into()); }
    private_directory(dir)?;
    let mut manifest = lock_file(&dir.join("reservation.lock"))?;
    lock(&manifest, false)?;
    let mut free = Vec::new();
    let mut busy = false;
    for slot in 0..3 {
        let file = lock_file(&dir.join(format!("slot-{slot}.lock")))?;
        if lock(&file, true)? { free.push((slot, file)); } else { busy = true; }
    }
    let expected = format!("lattica-opencl-slots-v1 {workers} {managed} {context}\n");
    if busy {
        let mut actual = String::new();
        (&mut manifest).take(1024).read_to_string(&mut actual).map_err(|e| e.to_string())?;
        if actual != expected { return Err("live GPU slot reservation differs from requested workers/VRAM/context".into()); }
    } else {
        manifest.set_len(0).map_err(|e| e.to_string())?;
        manifest.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        manifest.write_all(expected.as_bytes()).map_err(|e| e.to_string())?;
    }
    free.into_iter().find(|(i, _)| *i < workers).map(|(_, f)| f)
        .ok_or_else(|| "all reserved GPU slots are occupied".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slots_reject_overbooking_mismatched_reservations_and_recover_on_drop() {
        let dir = std::env::temp_dir().join(format!("lattica-device-slots-{}", std::process::id()));
        let a = acquire(&dir, 2, 100, 10).unwrap();
        assert!(acquire(&dir, 3, 100, 10).is_err());
        assert!(acquire(&dir, 2, 101, 10).is_err());
        let b = acquire(&dir, 2, 100, 10).unwrap();
        assert!(acquire(&dir, 2, 100, 10).is_err());
        drop(a);
        let c = acquire(&dir, 2, 100, 10).unwrap();
        drop((b, c));
        drop(acquire(&dir, 3, 111, 22).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn capacity_includes_each_context_and_device_headroom() {
        let gib = 1 << 30;
        assert!(check_capacity(2, 6*gib, gib/2, 14*gib).is_ok());
        assert!(check_capacity(2, 6*gib, gib/2, 14*gib-1).is_err());
        assert!(check_capacity(2, usize::MAX, 1, usize::MAX).is_err());
    }
}
