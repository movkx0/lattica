//! Linux private writable data admission. RLIMIT_DATA covers the kernel's
//! data_vm class, not all mappings, stacks, resident memory or process RSS.
use super::super::worker_budget;
use crate::block_v2::recursive::Error;
use std::io::{ErrorKind, Read};

const STATUS_BYTES: usize = 16 << 10;
// Do not lend the caller's separate stack reservation to unclassified data.
// If a fixed pthread stack also counts as data_vm, counting it here is
// conservative; the main grow-down stack does not count as data_vm at all.
const COLD_BYTES: u64 = crate::host_memory::RETAINED_SYSTEM_HOST_BYTES;

#[derive(Debug, PartialEq, Eq)]
struct Status {
    data_bytes: u64,
    threads: u32,
}

fn read_status(mut reader: impl Read) -> Result<Status, Error> {
    // Charge this fixed scratch to the already admitted caller stack.
    let mut input = [0u8; STATUS_BYTES + 1];
    let mut used = 0;
    while used < input.len() {
        match reader.read(&mut input[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    if used > STATUS_BYTES {
        return Err("private data status exceeds bounded startup input".into());
    }
    let (mut data, mut threads) = (None, None);
    for line in input[..used].split(|byte| *byte == b'\n') {
        let mut fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        match fields.next() {
            Some(b"VmData:") => {
                if data.is_some() {
                    return Err("duplicate private data observation".into());
                }
                let kib = std::str::from_utf8(fields.next().ok_or("missing private data bytes")?)?
                    .parse::<u64>()?;
                if fields.next() != Some(b"kB".as_slice()) || fields.next().is_some() {
                    return Err("invalid private data units".into());
                }
                data = Some(kib.checked_mul(1024).ok_or("private data bytes overflow")?);
            }
            Some(b"Threads:") => {
                if threads.is_some() {
                    return Err("duplicate startup thread observation".into());
                }
                let count = std::str::from_utf8(fields.next().ok_or("missing startup threads")?)?
                    .parse::<u32>()?;
                if count == 0 || fields.next().is_some() {
                    return Err("invalid startup thread observation".into());
                }
                threads = Some(count);
            }
            _ => {}
        }
    }
    Ok(Status {
        data_bytes: data.ok_or("missing private data observation")?,
        threads: threads.ok_or("missing startup thread observation")?,
    })
}

fn current() -> Result<Status, Error> {
    read_status(std::fs::File::open("/proc/self/status")?)
}

fn admit_observed(bytes: u64) -> Result<(), Error> {
    if bytes > COLD_BYTES {
        return Err("cold private writable data exceeds startup reservation".into());
    }
    Ok(())
}

pub(super) fn admit_cold(boundary: &str) -> Result<(), Error> {
    let observed = current()?;
    let admitted = admit_observed(observed.data_bytes);
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_private_data_startup {}",
            serde_json::json!({
                "schema": "lattica-private-data-startup-v1", "pid": std::process::id(),
                "boundary": boundary, "observed_bytes": observed.data_bytes,
                "observed_threads": observed.threads, "limit_bytes": COLD_BYTES,
                "allowed": admitted.is_ok(), "is_rss_bound": false,
                "is_lifetime_admission": false,
            })
        );
    }
    admitted
}

fn limits() -> Result<libc::rlimit, Error> {
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the valid output pointer on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_DATA, limits.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { limits.assume_init() })
}

fn require_kernel_enforcement(mut reader: impl Read) -> Result<(), Error> {
    let mut bytes = [0u8; 4];
    let mut used = 0;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    if &bytes[..used] != b"N\n" && &bytes[..used] != b"0\n" {
        return Err("kernel private data limit enforcement is disabled or unknown".into());
    }
    Ok(())
}

/// Tighten both limits in this fresh worker; never relax an inherited limit.
/// The native caller must keep startup ownership quiescent while admitting it.
/// The assigned spill cap and mapped GPU staging cannot borrow private data's
/// allowance. Other mappings, grow-down stacks and RSS remain separate.
pub(super) fn install(worker_bytes: u64, threads: u32, spill_bytes: u64) -> Result<(), Error> {
    admit_cold("before_rayon")?;
    require_kernel_enforcement(std::fs::File::open(
        "/sys/module/kernel/parameters/ignore_rlimit_data",
    )?)?;
    let ceiling = worker_budget::private_data_limit_bytes(worker_bytes, threads, spill_bytes)?;
    let old = limits()?;
    let target = libc::rlim_t::try_from(ceiling)?;
    if old.rlim_cur < target || old.rlim_max < target {
        return Err("inherited private data limit is below worker assignment".into());
    }
    let observed = current()?;
    if observed.data_bytes > ceiling {
        return Err("existing private data exceeds worker assignment".into());
    }
    let requested = libc::rlimit {
        rlim_cur: target,
        rlim_max: target,
    };
    // SAFETY: this only tightens the current worker's resource limits. This
    // process is single-use; no caller may expect its old hard limit restored.
    if unsafe { libc::setrlimit(libc::RLIMIT_DATA, &requested) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let applied = limits()?;
    let after = current()?;
    if applied.rlim_cur != target || applied.rlim_max != target || after.data_bytes > ceiling {
        return Err("private data limit changed during worker startup".into());
    }
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_private_data_limit {}",
            serde_json::json!({
                "schema": "lattica-private-data-limit-v1", "pid": std::process::id(),
                "boundary": "before_rayon", "soft_bytes": applied.rlim_cur,
                "hard_bytes": applied.rlim_max, "observed_bytes": after.data_bytes,
                "observed_threads": after.threads, "is_rss_bound": false,
                "worker_bytes": worker_bytes, "spill_reserve_bytes": spill_bytes,
                "mapped_staging_reserve_bytes": crate::host_memory::GPU_MAPPED_HOST_BYTES,
                "stack_reserve_bytes": worker_budget::rayon_stack_host_bytes(threads)?
                    + worker_budget::CALLER_STACK_HOST_BYTES,
                "shared_mappings_and_growdown_stacks_separate": true,
                "startup_quiescence_required": true,
                "kernel_ignore_rlimit_data": false,
            })
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
