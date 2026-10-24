//! Shared storage for actual outer proofs, never for verification keys.
//!
//! The JSON representation is a bounded diagnostic cache format, not a network
//! protocol codec. Only trusted component/graph adapters supply cache identities
//! and mandatory full-verifier callbacks. No cache operation manufactures a
//! source cap, registered program, coverage flag or acceptance receipt.
use crate::proof_cache_policy::{Control, Family, ProofCachePolicy};
use lattica_prover_p3::block_v2::{machine::program::Val, profile::Config};
use p3_batch_stark::BatchProof;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn err(error: impl std::fmt::Debug) -> Error {
    Error(format!("{error:?}"))
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}
const SCHEMA: u64 = 1;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Only construction/path inspection are public. Actual cache access remains
/// inside the trusted typed node adapters and requires native verification.
pub struct ProofCache {
    directory: PathBuf,
    max_entry_bytes: u64,
    control: Control,
}
impl ProofCache {
    pub(crate) fn policy(&self) -> ProofCachePolicy {
        self.control.policy()
    }
    pub(crate) fn proof_attempt(&self) {
        self.control.attempt(Family::Outer);
    }
    pub(crate) fn fresh_proof(&self) {
        self.control.fresh(Family::Outer);
    }
    pub fn new(directory: impl Into<PathBuf>, max_entry_bytes: u64) -> Result<Self> {
        Self::new_with_policy(directory, max_entry_bytes, ProofCachePolicy::default())
    }
    pub fn new_with_policy(
        directory: impl Into<PathBuf>,
        max_entry_bytes: u64,
        policy: ProofCachePolicy,
    ) -> Result<Self> {
        Self::new_with_control(directory, max_entry_bytes, Control::new(policy))
    }
    pub(crate) fn new_with_control(
        directory: impl Into<PathBuf>,
        max_entry_bytes: u64,
        control: Control,
    ) -> Result<Self> {
        require(
            (1..=64 << 20).contains(&max_entry_bytes),
            "outer cache entry limit must be in 1..=64 MiB",
        )?;
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(err)?;
        Ok(Self {
            directory,
            max_entry_bytes,
            control,
        })
    }
    pub fn entry_path(&self, identity: &[u8; 32]) -> PathBuf {
        let name: String = identity.iter().map(|byte| format!("{byte:02x}")).collect();
        self.directory.join(format!("{name}.json"))
    }
    pub(crate) fn load_verified(
        &self,
        identity: &[u8; 32],
        expected_public: &[Val],
        verify: impl FnOnce(&[Val], &BatchProof<Config>) -> std::result::Result<(), String>,
    ) -> Result<Option<(Vec<Val>, BatchProof<Config>)>> {
        if !self.control.read(Family::Outer) {
            return Ok(None);
        }
        let file = match File::open(self.entry_path(identity)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        require(
            file.metadata().map_err(err)?.len() <= self.max_entry_bytes,
            "outer cache entry exceeds byte limit",
        )?;
        let mut bytes = Vec::new();
        file.take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(
            bytes.len() as u64 <= self.max_entry_bytes,
            "outer cache entry exceeds byte limit",
        )?;
        let (schema, source, stored_identity, public, proof): (
            u64,
            [u8; 32],
            [u8; 32],
            Vec<Val>,
            BatchProof<Config>,
        ) = serde_json::from_slice(&bytes).map_err(err)?;
        require(
            schema == SCHEMA
                && source == crate::graph_proofs::compiled_source_fingerprint()
                && stored_identity == *identity,
            "outer cache schema/source/identity mismatch",
        )?;
        require(
            public == expected_public,
            "outer cache expected public mismatch",
        )?;
        verify(&public, &proof).map_err(Error)?;
        self.control.hit(Family::Outer);
        Ok(Some((public, proof)))
    }
    pub(crate) fn store_verified(
        &self,
        identity: &[u8; 32],
        public: &[Val],
        proof: &BatchProof<Config>,
        verify: impl FnOnce(&[Val], &BatchProof<Config>) -> std::result::Result<(), String>,
    ) -> Result<()> {
        verify(public, proof).map_err(Error)?;
        struct Bounded {
            bytes: Vec<u8>,
            limit: u64,
        }
        impl Write for Bounded {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() as u64 > self.limit.saturating_sub(self.bytes.len() as u64) {
                    return Err(std::io::Error::other(
                        "outer cache entry exceeds byte limit",
                    ));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = Bounded {
            bytes: Vec::new(),
            limit: self.max_entry_bytes,
        };
        serde_json::to_writer(
            &mut output,
            &(
                SCHEMA,
                crate::graph_proofs::compiled_source_fingerprint(),
                identity,
                public,
                proof,
            ),
        )
        .map_err(err)?;
        let temporary = self.directory.join(format!(
            ".outer-{}-{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = self.write_atomic(&temporary, &self.entry_path(identity), &output.bytes);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    fn write_atomic(&self, temporary: &Path, destination: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary)
            .map_err(err)?;
        file.write_all(bytes).map_err(err)?;
        file.sync_all().map_err(err)?;
        drop(file);
        fs::rename(temporary, destination).map_err(err)?;
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_only_skips_existing_proof_files_on_every_read() {
        let directory = std::env::temp_dir().join(format!(
            "lattica-outer-fresh-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let control = Control::new(ProofCachePolicy::FreshOnly);
        let cache = ProofCache::new_with_control(&directory, 8, control.clone()).unwrap();
        let identity = [17; 32];
        for payload in [b"invalid".as_slice(), &[0u8; 32], b"invalid"] {
            fs::write(cache.entry_path(&identity), payload).unwrap();
            assert!(cache
                .load_verified(&identity, &[], |_, _| panic!("FreshOnly invoked verifier"))
                .unwrap()
                .is_none());
        }
        let counts = control.snapshot();
        assert_eq!(counts.families["outer"].reads, 0);
        assert_eq!(counts.families["outer"].hits, 0);
        assert_eq!(counts.families["outer"].bypasses, 3);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_malformed_and_oversized_outer_entries_fail_before_verification() {
        let directory = std::env::temp_dir().join(format!(
            "lattica-outer-cache-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(ProofCache::new(&directory, 0).is_err());
        assert!(ProofCache::new(&directory, (64 << 20) + 1).is_err());
        let cache = ProofCache::new(&directory, 128).unwrap();
        let identity = [1; 32];
        let unreachable_verifier =
            |_: &[Val], _: &BatchProof<Config>| -> std::result::Result<(), String> {
                panic!("malformed input reached native verification")
            };
        assert!(cache
            .load_verified(&identity, &[], unreachable_verifier)
            .unwrap()
            .is_none());
        fs::write(cache.entry_path(&identity), b"[1,null]").unwrap();
        assert!(cache
            .load_verified(&identity, &[], unreachable_verifier)
            .is_err());
        fs::write(cache.entry_path(&identity), [0; 129]).unwrap();
        assert!(cache
            .load_verified(&identity, &[], unreachable_verifier)
            .is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
