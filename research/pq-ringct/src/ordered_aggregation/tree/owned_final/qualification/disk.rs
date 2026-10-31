//! Bounded current-directory artifact names. The coordinator selects a fresh
//! working directory before dispatch. A failed write/check is never removed.
use super::*;
use std::{fs::{File, Metadata, OpenOptions}, io::{Read, Write}, os::unix::fs::MetadataExt};

const PREFIX: &[u8] = b"ringct-final-";
const SUFFIX: &[u8] = b".bin";
pub(super) const NAME_BYTES: usize = PREFIX.len() + 64 + SUFFIX.len();

#[derive(Clone, Copy, Default)]
pub(super) struct Provenance {
    pub(super) device: u64,
    pub(super) inode: u64,
}

fn filename(digest: &[u8; 32]) -> [u8; NAME_BYTES] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = [0u8; NAME_BYTES];
    name[..PREFIX.len()].copy_from_slice(PREFIX);
    for (index, &byte) in digest.iter().enumerate() {
        name[PREFIX.len() + 2 * index] = HEX[usize::from(byte >> 4)];
        name[PREFIX.len() + 2 * index + 1] = HEX[usize::from(byte & 15)];
    }
    name[PREFIX.len() + 64..].copy_from_slice(SUFFIX);
    name
}

fn metadata(file: &File, bytes: usize) -> OwnedResult<Metadata> {
    let value = file.metadata().map_err(|_| FinalFailure::Report)?;
    if !value.is_file() || value.nlink() != 1
        || value.len() != u64::try_from(bytes).map_err(|_| FinalFailure::Overflow)?
    { return Err(FinalFailure::Report); }
    Ok(value)
}

pub(super) fn roundtrip(encoded: &[u8], readback: &mut [u8],
    digest: [u8; 32]) -> OwnedResult<Provenance>
{
    if encoded.len() != readback.len() || digest != sha3(encoded) {
        return Err(FinalFailure::Source);
    }
    let name = filename(&digest);
    let path = core::str::from_utf8(&name).map_err(|_| FinalFailure::Source)?;
    // Fixed81-byte ASCII path takes Rust1.96's stack C-string branch (<384).
    // No PathBuf, CString, read_to_end, formatting or path allocation is used.
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|_| FinalFailure::Report)?;
    output.write_all(encoded).map_err(|_| FinalFailure::Report)?;
    output.sync_all().map_err(|_| FinalFailure::Report)?;
    let written = metadata(&output, encoded.len())?;
    let provenance = Provenance { device: written.dev(), inode: written.ino() };
    drop(output);
    let mut input = File::open(path).map_err(|_| FinalFailure::Report)?;
    let before = metadata(&input, encoded.len())?;
    if (before.dev(), before.ino()) != (provenance.device, provenance.inode) {
        return Err(FinalFailure::Report);
    }
    input.read_exact(readback).map_err(|_| FinalFailure::Report)?;
    let mut extra = [0u8; 1];
    if input.read(&mut extra).map_err(|_| FinalFailure::Report)? != 0 {
        return Err(FinalFailure::Report);
    }
    let after = metadata(&input, encoded.len())?;
    if (after.dev(), after.ino(), after.mtime(), after.mtime_nsec(), after.ctime(), after.ctime_nsec())
        != (before.dev(), before.ino(), before.mtime(), before.mtime_nsec(), before.ctime(), before.ctime_nsec())
        || readback != encoded || sha3(readback) != digest
    { return Err(FinalFailure::Report); }
    drop(input);
    Ok(provenance)
}

pub(super) fn frames() -> OwnedResult<usize> {
    let parts = [size_of::<File>(), size_of::<Metadata>(), size_of::<OpenOptions>(),
        size_of::<std::io::Error>(), size_of::<std::io::Result<File>>(),
        size_of::<std::io::Result<Metadata>>(), size_of::<std::io::Result<usize>>(),
        size_of::<std::io::Result<()>>(), size_of::<Provenance>(),
        size_of::<OwnedResult<Provenance>>(), size_of::<[u8; NAME_BYTES]>(),
        // Pinned std::sys::helpers::small_c_string stack path, and Linux's
        // fixed statx result (256 bytes), in addition to exposed Metadata.
        size_of::<[u8; 384]>(), size_of::<[u8; 256]>(),
        // Private/unstable BorrowedBuf/borrowed-cursor fields: initialized slice,
        // filled/initialized counts and cursor reference, bounded by eight words.
        size_of::<[usize; 8]>(),
        size_of::<[u64; 6]>(), size_of::<[usize; 16]>(),
        size_of::<&str>(), size_of::<&[u8]>(), size_of::<&mut [u8]>(),
        size_of::<[u8; 1]>(), size_of::<core::str::Utf8Error>(),
    ];
    // Sequential I/O calls; account all named values and sixteen forwarding
    // copies together, including errors. No kernel/page-cache RSS credit.
    mul(16, parts.into_iter().try_fold(core::mem::size_of_val(&parts), add)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artifact_name_is_fixed_ascii_and_carries_the_entire_digest() {
        let name = filename(&[0xab; 32]);
        assert_eq!(name.len(), 81);
        assert_eq!(&name[..13], b"ringct-final-");
        assert!(name[13..77].chunks_exact(2).all(|pair| pair == b"ab"));
        assert_eq!(&name[77..], b".bin");
        assert!(name.len() < 384);
    }
}
