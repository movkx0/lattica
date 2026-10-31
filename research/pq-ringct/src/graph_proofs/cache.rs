//! Bounded persistent storage of real child STARKs. Metadata is a cache lookup
//! aid only; loaded proofs are always checked against the trusted plan and AIR.
use super::*;
use crate::proof_cache_policy::{Control, Family, ProofCachePolicy};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
const SCHEMA: u64 = 1;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

pub struct ProofCache {
    directory: PathBuf,
    max_entry_bytes: u64,
    control: Control,
}
pub struct CacheOutcome {
    pub artifact: ComponentArtifact,
    pub cache_hit: bool,
    pub key: [u8; 32],
}
/// Explicit archival import: the proof was verified anew under the current
/// registered relation. It is not a hit in the current source-version cache.
pub struct ArchivedReverification {
    pub artifact: ComponentArtifact,
    pub archived_key: String,
    pub current_key: [u8; 32],
}
impl ProofCache {
    /// Use a persistent worktree directory. A size cap is required before any
    /// untrusted entry is read; the default recommendation is 64 MiB per child.
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
        if max_entry_bytes == 0 || max_entry_bytes > 1 << 30 {
            return Err(error("cache entry limit must be in 1..=1 GiB"));
        }
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(io_error)?;
        Ok(Self {
            directory,
            max_entry_bytes,
            control,
        })
    }
    pub fn entry_path(&self, key: &[u8; 32]) -> PathBuf {
        self.directory.join(format!("{}.json", hex(key)))
    }
    /// Invalid existing files fail closed instead of becoming native acceptance
    /// hints or being silently overwritten. Missing files produce real proofs.
    pub fn load_or_prove(
        &self,
        plan: &GraphProofPlan<'_>,
        batch_index: usize,
    ) -> Result<CacheOutcome> {
        self.load_or_prove_with_context(plan, batch_index, None)
    }
    pub fn load_or_prove_with_context(
        &self,
        plan: &GraphProofPlan<'_>,
        batch_index: usize,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<CacheOutcome> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && self.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(error("native GPU algebra coverage requires FreshOnly"));
        }
        let key = plan.cache_key(batch_index)?;
        if let Some(artifact) = self.load(plan, batch_index)? {
            return Ok(CacheOutcome {
                artifact,
                cache_hit: true,
                key,
            });
        }
        self.control.attempt(Family::Algebra);
        let artifact = plan.prove_batch_with_context(batch_index, execution)?;
        self.control.fresh(Family::Algebra);
        self.store(plan, batch_index, &artifact)?;
        Ok(CacheOutcome {
            artifact,
            cache_hit: false,
            key,
        })
    }
    pub fn load(
        &self,
        plan: &GraphProofPlan<'_>,
        batch_index: usize,
    ) -> Result<Option<ComponentArtifact>> {
        if !self.control.read(Family::Algebra) {
            return Ok(None);
        }
        let key = plan.cache_key(batch_index)?;
        let path = self.entry_path(&key);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(e)),
        };
        let artifact = self
            .decode_and_verify(plan, batch_index, file, Some(&hex(&key)))?
            .artifact;
        self.control.hit(Family::Algebra);
        Ok(Some(artifact))
    }
    /// Reverify an explicitly selected archived proof against the current
    /// exact AIR, degree and ordered roots. Its old key is diagnostic only.
    /// This does not claim a cache hit or write/relabel the entry; callers may
    /// explicitly `store` the reverified artifact under the current key.
    pub fn reverify_archived_entry(
        &self,
        plan: &GraphProofPlan<'_>,
        batch_index: usize,
        path: impl AsRef<Path>,
    ) -> Result<ArchivedReverification> {
        if !self.control.allows_import() {
            return Err(error("FreshOnly disallows archived proof import"));
        }
        self.control.read(Family::Algebra);
        let file = File::open(path).map_err(io_error)?;
        self.decode_and_verify(plan, batch_index, file, None)
    }
    fn decode_and_verify(
        &self,
        plan: &GraphProofPlan<'_>,
        batch_index: usize,
        mut file: File,
        expected_key: Option<&str>,
    ) -> Result<ArchivedReverification> {
        if file.metadata().map_err(io_error)?.len() > self.max_entry_bytes {
            return Err(error("cached proof exceeds byte limit"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 > self.max_entry_bytes {
            return Err(error("cached proof exceeds byte limit"));
        }
        let (schema, encoded_key, public, proof): (
            u64,
            String,
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        ) = serde_json::from_slice(&bytes)
            .map_err(|e| error(format!("invalid cached proof encoding: {e}")))?;
        if schema != SCHEMA
            || encoded_key.len() != 64
            || !encoded_key.bytes().all(|byte| byte.is_ascii_hexdigit())
            || expected_key.is_some_and(|key| encoded_key != key)
        {
            return Err(error("cached proof key/version mismatch"));
        }
        let artifact = match plan.batch(batch_index)?.kind {
            ComponentKind::Affine { .. } => ComponentArtifact::Affine(AffineBatchProof {
                public_values: public
                    .try_into()
                    .map_err(|_| error("affine cache public width"))?,
                proof,
            }),
            ComponentKind::Ntt { .. } => ComponentArtifact::Ntt(NttBatchProof {
                public_values: public,
                proof,
            }),
            ComponentKind::Mul { .. } => ComponentArtifact::Mul(MulBatchProof {
                public_values: public,
                proof,
            }),
            ComponentKind::GBound { .. } => ComponentArtifact::GBound(GBoundArtifact {
                public_values: public
                    .try_into()
                    .map_err(|_| error("GBound cache public width"))?,
                proof,
            }),
            ComponentKind::Permutation { .. } => ComponentArtifact::Permutation(PermutationProof {
                public_values: public
                    .try_into()
                    .map_err(|_| error("permutation cache public width"))?,
                proof,
            }),
            ComponentKind::LinearMap { .. } => ComponentArtifact::LinearMap(LinearMapProof {
                public_values: public,
                proof,
            }),
            ComponentKind::External => {
                return Err(error("external operation has no algebra proof"))
            }
        };
        plan.verify_batch(batch_index, &artifact)?;
        Ok(ArchivedReverification {
            artifact,
            archived_key: encoded_key,
            current_key: plan.cache_key(batch_index)?,
        })
    }
    pub fn store(
        &self,
        plan: &GraphProofPlan<'_>,
        batch_index: usize,
        artifact: &ComponentArtifact,
    ) -> Result<()> {
        plan.verify_batch(batch_index, artifact)?;
        let key = plan.cache_key(batch_index)?;
        let path = self.entry_path(&key);
        let temp = self.directory.join(format!(
            ".{}-{}-{}.tmp",
            hex(&key),
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = self
            .write_entry(&temp, &key, artifact)
            .and_then(|()| fs::rename(&temp, &path).map_err(io_error))
            .and_then(|()| {
                File::open(&self.directory)
                    .and_then(|f| f.sync_all())
                    .map_err(io_error)
            });
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
    fn write_entry(&self, path: &Path, key: &[u8; 32], artifact: &ComponentArtifact) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io_error)?;
        let mut writer = BufWriter::new(BoundedWriter {
            file,
            remaining: self.max_entry_bytes,
        });
        serde_json::to_writer(
            &mut writer,
            &(SCHEMA, hex(key), artifact.public_values(), artifact.proof()),
        )
        .map_err(|e| error(format!("cache serialization/size limit: {e}")))?;
        writer.flush().map_err(io_error)?;
        writer.get_ref().file.sync_all().map_err(io_error)
    }
}
struct BoundedWriter {
    file: File,
    remaining: u64,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::other("proof cache byte limit"));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
fn io_error(e: std::io::Error) -> Error {
    error(format!("proof cache I/O: {e}"))
}
pub(super) fn hex(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}
