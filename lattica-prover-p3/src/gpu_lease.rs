//! Shared process leases for native GPU transports. Device identity, rather
//! than API enumeration order, coordinates OpenCL and CUDA workers.
use std::fs::File;

pub(crate) struct SingleDeviceLease {
    _global: File,
    _device: File,
}

impl SingleDeviceLease {
    pub(crate) fn acquire(uuid: &str) -> Result<Self, String> {
        let uuid = normalized_uuid(uuid)?;
        Ok(Self {
            _global: lease_file("exclusive.lock", true)?,
            _device: lease_file(&format!("{uuid}.lock"), false)?,
        })
    }
}

pub(crate) fn normalized_uuid(uuid: &str) -> Result<String, String> {
    let raw = uuid
        .strip_prefix("GPU-")
        .ok_or("GPU UUID must begin with GPU-")?;
    if raw.len() != 36
        || !raw.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return Err("invalid GPU UUID".into());
    }
    Ok(format!("gpu-{}", raw.to_ascii_lowercase()))
}

pub(crate) fn lease_file(name: &str, shared: bool) -> Result<File, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err("invalid GPU lease filename".into());
    }
    let uid = unsafe { libc::geteuid() };
    let dir = std::path::Path::new("/tmp").join(format!("lattica-v2-gpu-lease-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.to_string()),
    }
    let meta = std::fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
        return Err("GPU lease directory must be private and owned by the current user".into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(name))
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o777 != 0o600 {
        return Err("invalid GPU lease file".into());
    }
    use std::os::fd::AsRawFd;
    let operation = if shared { libc::LOCK_SH } else { libc::LOCK_EX };
    if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "GPU lease busy: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_lease_names_reject_paths_and_malformed_identities() {
        assert_eq!(
            normalized_uuid("GPU-01234567-89AB-CDEF-0123-456789ABCDEF").unwrap(),
            "gpu-01234567-89ab-cdef-0123-456789abcdef"
        );
        for name in [
            "GPU-",
            "GPU-../../bad",
            "GPU-0123456789abcdef0123456789abcdef----",
            "GPU-01234567-89ab-cdef-0123-456789abcdeg",
        ] {
            assert!(normalized_uuid(name).is_err());
        }
        for name in ["", "../exclusive.lock", "/tmp/lock", "a\\b", "a\0b"] {
            assert!(lease_file(name, false).is_err());
        }
    }
}
