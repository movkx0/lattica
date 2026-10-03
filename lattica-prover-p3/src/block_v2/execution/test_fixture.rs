//! Independently pinned public research fixtures. Test-only; never key approval.
use super::job::{Job, RegistryPin, VerifiedWallet};
use crate::block_v2::{
    commitment,
    machine::program::Val,
    profile,
    recursive::{Error, Registry, WrapperConstruction},
};
use p3_field::PrimeCharacteristicRing;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub struct Fixture {
    pub registry: Registry,
    pub pin: RegistryPin,
    pub wallets: Vec<VerifiedWallet>,
    pub bytes: Vec<Vec<u8>>,
    pub root: Job,
    pub root_bytes: Vec<u8>,
}
pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.len() > limit as u64 {
        return Err("fixture type/size".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(super::artifact_store::safe_file_flags())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("fixture type/size".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("fixture grew".into());
    }
    Ok(bytes)
}
fn hex(value: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}
pub fn load() -> Result<Fixture, Error> {
    let inputs = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_INPUTS")?);
    let bundle = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_ROOT")?);
    let expected_profile = hex("8ec1bbde8ade9c60a90398a6a30f3bb095d5adc1f1fed881e7b72ea051bab3cb");
    let expected_root = hex("23ccda6b5581d09e8d0107be85d09c2795f3f767bfc844a9b5168e7f4a9c20e8");
    let registry = read_registry(&inputs)?;
    let pin = RegistryPin::new(
        &registry,
        expected_profile,
        WrapperConstruction::GroupedPair,
    )?;
    let mut wallets = Vec::new();
    let mut bytes = Vec::new();
    for i in 0..8 {
        let proof = read(
            &inputs.join(format!("wallet.{i}")),
            profile::MAX_PROOF_BYTES,
        )?;
        wallets.push(VerifiedWallet::verify(pin, &registry, [0x5a; 32], &proof)?);
        bytes.push(proof);
    }
    let pairs: Vec<_> = (0..4)
        .map(|i| Job::wrap_pair((2 * i) as u8, wallets[2 * i], wallets[2 * i + 1]))
        .collect::<Result<_, _>>()?;
    let root = Job::merge(
        &Job::merge(&pairs[0], &pairs[1])?,
        &Job::merge(&pairs[2], &pairs[3])?,
    )?;
    if commitment::digest_bytes(root.expected().root)? != expected_root {
        return Err("fixture root statement".into());
    }
    let root_bytes = read(&bundle.join("node.3.0"), profile::MAX_PROOF_BYTES)?;
    super::job::VerifiedNode::verify(&root, &registry, &root_bytes)?;
    Ok(Fixture {
        registry,
        pin,
        wallets,
        bytes,
        root,
        root_bytes,
    })
}

fn read_registry(inputs: &Path) -> Result<Registry, Error> {
    let height =
        u32::from_le_bytes(read(&inputs.join("height"), 4)?.as_slice().try_into()?) as usize;
    if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
        return Err("fixture geometry".into());
    }
    let mut caps = core::array::from_fn(|_| Vec::new());
    let size = (1 << profile::CAP_HEIGHT) * 32;
    for (i, cap) in caps.iter_mut().enumerate() {
        let bytes = read(&inputs.join(format!("key.{}", i + 1)), size)?;
        if bytes.len() != size {
            return Err("fixture cap size".into());
        }
        for digest in bytes.chunks_exact(32) {
            let mut values = [Val::ZERO; 4];
            for (value, word) in values.iter_mut().zip(digest.chunks_exact(8)) {
                let decoded = u64::from_le_bytes(word.try_into()?);
                if decoded >= commitment::MODULUS {
                    return Err("fixture noncanonical cap".into());
                }
                *value = Val::from_u64(decoded);
            }
            cap.push(values);
        }
    }
    Ok(Registry { height, caps })
}

/// Independently reproduced current-layout research registry; not approval.
pub const SINGLE_PROFILE_HEX: &str =
    "8e837436dd8f897a40cef05a6ea0b8cbcf319427a3132fae88585fd5bffef5d2";

pub struct PublicFixture {
    pub registry: Registry,
    pub pin: RegistryPin,
    pub wallets: Vec<VerifiedWallet>,
    pub bytes: Vec<Vec<u8>>,
}

pub fn load_single_registry() -> Result<(Registry, RegistryPin), Error> {
    let inputs = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_SINGLE")?);
    let registry = read_registry(&inputs)?;
    let pin = RegistryPin::new(
        &registry,
        hex(SINGLE_PROFILE_HEX),
        WrapperConstruction::SingleWallet,
    )?;
    Ok((registry, pin))
}

pub fn load_single_public() -> Result<PublicFixture, Error> {
    let inputs = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_SINGLE")?);
    let (registry, pin) = load_single_registry()?;
    let mut wallets = Vec::new();
    let mut bytes = Vec::new();
    for i in 0..8 {
        let proof = read(
            &inputs.join(format!("wallet.{i}")),
            profile::MAX_PROOF_BYTES,
        )?;
        wallets.push(VerifiedWallet::verify(pin, &registry, [0x5a; 32], &proof)?);
        bytes.push(proof);
    }
    Ok(PublicFixture {
        registry,
        pin,
        wallets,
        bytes,
    })
}
