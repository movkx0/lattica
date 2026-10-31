//! Checked source locks. Parent-hook postimages, not the older preimages,
//! define the authoritative native API/controller hashes.
use super::*;
use sha3::{Digest, Sha3_256};

pub(super) const CONTROLLER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine/device/native_private_spend.rs"));
pub(super) const DISPATCH: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine/device/native_private_spend/dispatch.rs"));
pub(super) const BUNDLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine/device/native_private_spend/bundle.cl"));
pub(super) const LAYOUT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine/device/native_private_spend/layout.rs"));
pub(super) const TYPES: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/native_gpu/private_spend/types.rs"));
pub(super) const ENTRY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/native_gpu/private_spend/mod.rs"));
pub(super) const DEVICE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine/device.rs"));
pub(super) const ENGINE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine.rs"));
pub(super) const MATRIX: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu_matrix.rs"));
pub(super) const SESSION: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block_v2/gpu_hash/engine/device/host_storage.rs"));
pub(super) const BOUNDED_INFO: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/ocl-core/src/bounded_info.rs"));
const LOCK: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"));
const OCL_LOCK_RECORD: &str = "name = \"ocl\"\nversion = \"0.19.7\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"4297afb442d411793e4e24ee5a2977d15b6c95c743418f1c0ce0a2397d7ec8a3\"";
const PINNED: &[(&str, &str, [u8; 32])] = &[
    ("src/block_v2/gpu_hash/engine/device/native_private_spend.rs", CONTROLLER, [111, 225, 234, 142, 134, 38, 77, 195, 252, 96, 254, 59, 174, 17, 144, 166, 6, 157, 57, 85, 80, 181, 11, 147, 159, 128, 200, 199, 58, 69, 210, 93]),
    ("src/block_v2/gpu_hash/engine/device/native_private_spend/dispatch.rs", DISPATCH, [90, 64, 26, 115, 192, 204, 159, 112, 177, 89, 244, 76, 176, 10, 110, 98, 120, 190, 160, 126, 24, 87, 112, 59, 67, 192, 66, 92, 76, 43, 69, 99]),
    ("src/block_v2/gpu_hash/engine/device/native_private_spend/bundle.cl", BUNDLE, [246, 178, 126, 17, 140, 56, 87, 8, 204, 48, 71, 172, 67, 173, 155, 129, 0, 196, 181, 55, 50, 221, 57, 30, 73, 80, 97, 83, 230, 252, 136, 37]),
    ("src/block_v2/gpu_hash/engine/device/native_private_spend/layout.rs", LAYOUT, [213, 24, 194, 14, 67, 231, 169, 26, 241, 52, 226, 215, 107, 190, 229, 96, 83, 152, 53, 226, 89, 164, 46, 212, 32, 209, 71, 90, 1, 18, 82, 84]),
    ("src/block_v2/native_gpu/private_spend/types.rs", TYPES, [171, 247, 68, 74, 7, 177, 69, 20, 213, 220, 31, 154, 30, 117, 133, 29, 10, 235, 234, 59, 100, 30, 220, 218, 26, 197, 214, 171, 34, 96, 5, 79]),
    ("src/block_v2/native_gpu/private_spend/mod.rs", ENTRY, [202, 104, 10, 115, 120, 211, 142, 253, 15, 223, 140, 245, 13, 117, 223, 242, 25, 227, 73, 89, 49, 47, 144, 62, 246, 228, 146, 41, 180, 52, 68, 24]),
    ("src/block_v2/gpu_hash/engine/device.rs", DEVICE, [2, 51, 136, 55, 147, 73, 121, 128, 253, 137, 159, 201, 60, 255, 119, 103, 74, 82, 59, 209, 210, 128, 43, 163, 31, 227, 20, 175, 252, 33, 13, 205]),
    ("src/block_v2/gpu_hash/engine.rs", ENGINE, [234, 59, 178, 48, 27, 246, 152, 119, 26, 51, 95, 123, 178, 119, 229, 220, 22, 241, 2, 6, 121, 236, 226, 217, 178, 17, 5, 93, 243, 186, 191, 231]),
    ("src/gpu_matrix.rs", MATRIX, [206, 150, 198, 43, 204, 134, 145, 131, 133, 216, 213, 3, 174, 196, 194, 198, 36, 135, 8, 15, 157, 45, 57, 13, 244, 172, 250, 97, 203, 110, 98, 14]),
    ("src/block_v2/gpu_hash/engine/device/host_storage.rs", SESSION, [147, 118, 192, 241, 54, 67, 109, 173, 50, 97, 44, 226, 128, 19, 191, 33, 109, 223, 16, 154, 140, 66, 139, 64, 114, 45, 109, 75, 114, 57, 248, 32]),
    ("vendor/ocl-core/src/bounded_info.rs", BOUNDED_INFO, [148, 162, 24, 124, 9, 60, 125, 167, 115, 145, 18, 33, 158, 97, 129, 59, 195, 89, 206, 162, 19, 95, 92, 176, 40, 191, 22, 76, 16, 235, 68, 22]),
];
const CENSUS: &[&str] = &[include_str!("../source.rs"), include_str!("memory.rs"),
    include_str!("ocl_storage.rs"), include_str!("pins.rs"),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/src/block_v2/native_gpu/private_spend/types/source.rs"))];

pub(super) fn check() -> Result<[u8; 32]> {
    if !LOCK.contains(OCL_LOCK_RECORD) { return Err(NativeSpendSourceError::Source); }
    let mut fingerprint = Sha3_256::new();
    fingerprint.update(b"ringct-native-spend-source-census-v1\0");
    for &(name, source, expected) in PINNED {
        let actual: [u8; 32] = Sha3_256::digest(source.as_bytes()).into();
        if actual != expected { return Err(NativeSpendSourceError::Source); }
        fingerprint.update((name.len() as u64).to_le_bytes());
        fingerprint.update(name.as_bytes());
        fingerprint.update(actual);
    }
    fingerprint.update(OCL_LOCK_RECORD.as_bytes());
    for source in CENSUS {
        fingerprint.update((source.len() as u64).to_le_bytes());
        fingerprint.update(source.as_bytes());
    }
    Ok(fingerprint.finalize().into())
}
pub(super) fn static_bytes() -> Result<usize> {
    let pins = PINNED.iter().try_fold(0usize, |bytes, (name, source, _)|
        add(bytes, add(name.len(), source.len())?))?;
    let census = CENSUS.iter().try_fold(0usize, |bytes, source| add(bytes, source.len()))?;
    sum([pins, census, LOCK.len(), OCL_LOCK_RECORD.len(),
        core::mem::size_of_val(PINNED), core::mem::size_of_val(CENSUS)])
}
