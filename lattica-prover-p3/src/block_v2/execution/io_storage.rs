//! Project-owned path/name backing for the Linux descriptor-anchored stores.
//! Directory iteration/libc buffers, file-descriptor kernel state, allocator
//! overhead and caller-owned input paths remain runtime/caller components.
use crate::block_v2::recursive::Error;
use std::{
    ffi::CString,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

pub(super) const PATH_BYTES: usize = 4096;
pub(super) const NAME_BYTES: usize = 255;
pub(super) const ANCHOR_BYTES: usize = 32;
pub(super) const WORK_BYTES: usize = 128 << 10;

pub(super) fn check_path(path: &Path) -> Result<(), Error> {
    if path.as_os_str().as_encoded_bytes().len() > PATH_BYTES {
        return Err("execution directory path length".into());
    }
    Ok(())
}
pub(super) fn check_named_path(path: &Path) -> Result<(), Error> {
    check_path(path)?;
    if path
        .file_name()
        .is_some_and(|s| s.as_encoded_bytes().len() > NAME_BYTES)
    {
        return Err("execution directory name length".into());
    }
    Ok(())
}
pub(super) fn check_name(name: &str) -> Result<(), Error> {
    if name.len() > NAME_BYTES {
        return Err("execution entry name length".into());
    }
    Ok(())
}
pub(super) fn fd_path(file: &File) -> PathBuf {
    use core::fmt::Write;
    let mut path = String::with_capacity(ANCHOR_BYTES);
    // Linux RawFd is an i32; even its signed decimal minimum fits this buffer.
    write!(&mut path, "/proc/self/fd/{}", file.as_raw_fd()).expect("write into String");
    PathBuf::from(path)
}

/// Allow eight simultaneous copies of each bounded path/name representation,
/// above the store/journal create, scan, link, rename and open call chains.
/// Include Vec geometric growth and C terminators; opaque libc directory
/// buffers are a separate runtime component.
pub(super) fn work_bytes() -> Result<usize, Error> {
    let census = 8 * (core::mem::size_of::<PathBuf>() + 2 * (PATH_BYTES + NAME_BYTES + 1))
        + 8 * (core::mem::size_of::<CString>() + PATH_BYTES + NAME_BYTES + 2)
        + 8 * (core::mem::size_of::<String>() + 2 * (NAME_BYTES + 1));
    if census > WORK_BYTES {
        return Err("execution path storage allowance".into());
    }
    Ok(WORK_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_and_name_bounds_precede_io_and_descriptor_paths_are_exact_capacity() {
        let file = File::open("/tmp").unwrap();
        let anchor = fd_path(&file);
        assert_eq!(anchor.capacity(), ANCHOR_BYTES);
        assert_eq!(
            anchor.to_str().unwrap(),
            format!("/proc/self/fd/{}", file.as_raw_fd())
        );
        assert!(check_path(Path::new(&"x".repeat(PATH_BYTES))).is_ok());
        assert!(check_path(Path::new(&"x".repeat(PATH_BYTES + 1))).is_err());
        assert!(check_named_path(Path::new(&format!("/{}", "x".repeat(NAME_BYTES + 1)))).is_err());
        assert!(check_name(&"x".repeat(NAME_BYTES)).is_ok());
        assert!(check_name(&"x".repeat(NAME_BYTES + 1)).is_err());
        assert_eq!(work_bytes().unwrap(), WORK_BYTES);
    }
}
