use super::*;
use crate::proof_cache_policy::{Control, Family, ProofCachePolicy};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const SCHEMA: u64 = 1;
static NONCE: AtomicU64 = AtomicU64::new(0);
pub struct AuxiliaryCache {
    directory: PathBuf,
    max_entry_bytes: u64,
    control: Control,
}
pub struct CacheOutcome {
    pub artifact: AuxiliaryArtifact,
    pub cache_hit: bool,
    pub key: [u8; 32],
}
pub struct ArchivedReverification {
    pub artifact: AuxiliaryArtifact,
    pub archived_key: String,
    pub current_key: [u8; 32],
}
pub(super) fn hex(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}
impl AuxiliaryCache {
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
            max_entry_bytes > 0 && max_entry_bytes <= 64 << 20,
            "auxiliary cache byte limit must be in1..=64MiB",
        )?;
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(err)?;
        Ok(Self {
            directory,
            max_entry_bytes,
            control,
        })
    }
    pub fn entry_path(&self, key: &[u8; 32]) -> PathBuf {
        self.directory.join(format!("{}.json", hex(key)))
    }
    pub fn load(&self, request: &AuxiliaryRequest) -> Result<Option<AuxiliaryArtifact>> {
        if !self.control.read(Family::Auxiliary) {
            return Ok(None);
        }
        let key = request.cache_key();
        let file = match File::open(self.entry_path(&key)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(err(error)),
        };
        let artifact = self.decode(request, file, Some(&hex(&key)))?.artifact;
        self.control.hit(Family::Auxiliary);
        Ok(Some(artifact))
    }
    /// Explicit source-version archival import. Verifies the current exact
    /// AIR, degree, role and public roots; never silently relabels or writes.
    pub fn reverify_archived_entry(
        &self,
        request: &AuxiliaryRequest,
        path: impl AsRef<Path>,
    ) -> Result<ArchivedReverification> {
        if !self.control.allows_import() {
            return Err(Error("FreshOnly disallows archived proof import".into()));
        }
        self.control.read(Family::Auxiliary);
        self.decode(request, File::open(path).map_err(err)?, None)
    }
    fn decode(
        &self,
        request: &AuxiliaryRequest,
        file: File,
        expected_key: Option<&str>,
    ) -> Result<ArchivedReverification> {
        require(
            file.metadata().map_err(err)?.len() <= self.max_entry_bytes,
            "auxiliary cache entry too large",
        )?;
        let mut bytes = Vec::new();
        file.take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(
            bytes.len() as u64 <= self.max_entry_bytes,
            "auxiliary cache entry too large",
        )?;
        let (schema, archived_key, public, proof): (
            u64,
            String,
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        ) = serde_json::from_slice(&bytes).map_err(err)?;
        require(
            schema == SCHEMA
                && archived_key.len() == 64
                && archived_key.bytes().all(|b| b.is_ascii_hexdigit())
                && expected_key.is_none_or(|key| key == archived_key),
            "auxiliary cache schema/key",
        )?;
        let public_values: [Val; 8] = public
            .try_into()
            .map_err(|_| Error("auxiliary cache public width".into()))?;
        let artifact = match request.kind() {
            Kind::Uniform(_) => AuxiliaryArtifact::Uniform(UniformArtifact {
                public_values,
                proof,
            }),
            Kind::Sparse(_) => AuxiliaryArtifact::Sparse(SparseArtifact {
                public_values,
                proof,
            }),
            Kind::Transcript => AuxiliaryArtifact::Transcript(TranscriptArtifact {
                public_values,
                proof,
            }),
        };
        request.verify(&artifact)?;
        Ok(ArchivedReverification {
            artifact,
            archived_key,
            current_key: request.cache_key(),
        })
    }
    pub fn store(&self, request: &AuxiliaryRequest, artifact: &AuxiliaryArtifact) -> Result<()> {
        request.verify(artifact)?;
        let key = request.cache_key();
        let path = self.entry_path(&key);
        let temporary = self.directory.join(format!(
            ".{}-{}-{}.tmp",
            hex(&key),
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> Result<()> {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(err)?;
            let mut writer = BufWriter::new(BoundedWriter {
                file,
                remaining: self.max_entry_bytes,
            });
            serde_json::to_writer(
                &mut writer,
                &(
                    SCHEMA,
                    hex(&key),
                    artifact.public_values(),
                    artifact.proof(),
                ),
            )
            .map_err(err)?;
            writer.flush().map_err(err)?;
            writer.get_ref().file.sync_all().map_err(err)?;
            fs::rename(&temporary, path).map_err(err)?;
            File::open(&self.directory)
                .and_then(|dir| dir.sync_all())
                .map_err(err)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn load_or_prove(&self, request: &AuxiliaryRequest) -> Result<CacheOutcome> {
        self.load_or_prove_with_context(request, None)
    }
    pub fn load_or_prove_with_context(
        &self,
        request: &AuxiliaryRequest,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<CacheOutcome> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && self.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(Error(
                "native GPU auxiliary coverage requires FreshOnly".into(),
            ));
        }
        if let Some(artifact) = self.load(request)? {
            return Ok(CacheOutcome {
                artifact,
                cache_hit: true,
                key: request.cache_key(),
            });
        }
        self.control.attempt(Family::Auxiliary);
        let artifact = request.prove_with_context(execution)?;
        self.control.fresh(Family::Auxiliary);
        self.store(request, &artifact)?;
        Ok(CacheOutcome {
            artifact,
            cache_hit: false,
            key: request.cache_key(),
        })
    }
}
struct BoundedWriter {
    file: File,
    remaining: u64,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::other("auxiliary cache byte limit"));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
