//! Bounded storage of actual AES/SHAKE child proofs. Cache metadata never
//! bypasses native verification or the consuming recursive component verifier.
use super::*;
use crate::crypto_join::ShakeSegmentProof;
use crate::proof_cache_policy::{Control, Family, ProofCachePolicy};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const SCHEMA: u64 = 1;
const WIDE_SCHEMA: u64 = 2;
mod wide_aes;
pub use wide_aes::{WideAesArchiveImport, WideAesCacheOutcome};
mod serial_archive;
pub use serial_archive::SerialArchiveImport;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub struct ProofCache {
    directory: PathBuf,
    max_entry_bytes: u64,
    control: Control,
}
pub struct CacheOutcome {
    pub artifact: SegmentArtifact,
    pub cache_hit: bool,
    pub key: [u8; 32],
}
pub struct WideCacheOutcome {
    pub artifact: ShakeSegmentProof,
    pub cache_hit: bool,
    pub key: [u8; 32],
}
/// Explicit revalidation, never an automatic current-source cache hit. Archive
/// metadata is reported as stored, not authenticated build provenance. No file
/// is rewritten or published under the current key by this operation.
pub struct WideArchiveImport {
    pub artifact: ShakeSegmentProof,
    pub archived_schema: u64,
    pub archived_key: [u8; 32],
    pub archived_source_fingerprint: Option<[u8; 32]>,
    pub archive_sha3_256: [u8; 32],
    pub current_key: [u8; 32],
    pub current_source_fingerprint: [u8; 32],
}
struct WideEntry {
    schema: u64,
    key: [u8; 32],
    source: Option<[u8; 32]>,
    archive_sha3_256: [u8; 32],
    artifact: ShakeSegmentProof,
}
fn decode_hex_key(key: &str) -> Result<[u8; 32]> {
    require(
        key.len() == 64 && key.as_bytes().iter().all(u8::is_ascii_hexdigit),
        "wide SHAKE archive key encoding",
    )?;
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key[2 * i..2 * i + 2], 16).map_err(err)?;
    }
    Ok(bytes)
}
impl ProofCache {
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
            (1..=1 << 30).contains(&max_entry_bytes),
            "crypto cache size limit must be in1..=1GiB",
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
    pub fn load(&self, request: &Request, index: usize) -> Result<Option<SegmentArtifact>> {
        if !self.control.read(Family::Crypto) {
            return Ok(None);
        }
        let key = request.cache_key(index)?;
        let mut file = match File::open(self.entry_path(&key)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        require(
            file.metadata().map_err(err)?.len() <= self.max_entry_bytes,
            "crypto cached proof exceeds byte limit",
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(
            bytes.len() as u64 <= self.max_entry_bytes,
            "crypto cached proof exceeds byte limit",
        )?;
        let (schema, encoded_key, public, proof): (
            u64,
            String,
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        ) = serde_json::from_slice(&bytes).map_err(err)?;
        require(
            schema == SCHEMA && encoded_key == hex(&key),
            "crypto cache key/version mismatch",
        )?;
        let artifact = match request.descriptor {
            RequestDescriptor::Aes(_) => SegmentArtifact::Aes(AesLaneSegmentProof {
                public_values: public
                    .try_into()
                    .map_err(|_| Error("AES cache public width".into()))?,
                proof,
            }),
            RequestDescriptor::Shake(_) => SegmentArtifact::Shake(LaneShakeProof {
                public_values: public
                    .try_into()
                    .map_err(|_| Error("SHAKE cache public width".into()))?,
                proof,
            }),
        };
        request.verify_segment(index, &artifact)?;
        self.control.hit(Family::Crypto);
        Ok(Some(artifact))
    }
    pub fn store(&self, request: &Request, index: usize, artifact: &SegmentArtifact) -> Result<()> {
        request.verify_segment(index, artifact)?;
        let key = request.cache_key(index)?;
        let path = self.entry_path(&key);
        if self.load(request, index)?.is_some() {
            return Ok(());
        }
        let encoded = serde_json::to_vec(&(
            SCHEMA,
            hex(&key),
            artifact.public_values(),
            artifact.proof(),
        ))
        .map_err(err)?;
        require(
            encoded.len() as u64 <= self.max_entry_bytes,
            "encoded crypto proof exceeds byte limit",
        )?;
        let temporary = self.directory.join(format!(
            ".{}-{}-{}.tmp",
            hex(&key),
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = write_atomic(&temporary, &path, &encoded);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn load_or_prove(&self, request: &Request, index: usize) -> Result<CacheOutcome> {
        self.load_or_prove_with_context(request, index, None)
    }
    pub fn load_or_prove_with_context(
        &self,
        request: &Request,
        index: usize,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<CacheOutcome> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && self.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(Error(
                "native GPU crypto coverage requires FreshOnly".into(),
            ));
        }
        let key = request.cache_key(index)?;
        if let Some(artifact) = self.load(request, index)? {
            return Ok(CacheOutcome {
                artifact,
                cache_hit: true,
                key,
            });
        }
        self.control.attempt(Family::Crypto);
        let artifact = request.prove_segment_with_context(index, execution)?;
        self.control.fresh(Family::Crypto);
        self.store(request, index, &artifact)?;
        Ok(CacheOutcome {
            artifact,
            cache_hit: false,
            key,
        })
    }

    /// Fresh native source for bounded retention. The caller reserves the
    /// public shape's retained_bytes for this output AND every sibling before
    /// passing the remaining native operation allowance. This path never
    /// decodes or serializes cache data; the ordinary cache API is unchanged.
    pub fn prove_fresh_retained_with_context(
        &self,
        request: &Request,
        index: usize,
        execution: &crate::execution::ProvingContext,
        remaining_host_bytes: u64,
    ) -> Result<RetainedNativeChild> {
        require(
            execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired
                && self.control.policy() == ProofCachePolicy::FreshOnly,
            "bounded native retention requires GpuRequired and FreshOnly",
        )?;
        let shape = request.segment_retention_shape(index)?;
        require(
            remaining_host_bytes != 0
                && remaining_host_bytes <= execution.host_bytes()
                && u64::try_from(shape.retained_bytes())
                    .ok()
                    .and_then(|retained| retained.checked_add(remaining_host_bytes))
                    .is_some_and(|sum| sum <= execution.host_bytes()),
            "bounded native retention output reservation",
        )?;
        let key = request.cache_key(index)?;
        self.control.attempt(Family::Crypto);
        let artifact = request.prove_segment_with_context_and_host_allowance(
            index,
            execution,
            remaining_host_bytes,
        )?;
        self.control.fresh(Family::Crypto);
        // The factory independently verifies the actual proof. Capacity
        // failure propagates; it must never select a different group layout.
        RetainedNativeChild::from_fresh(index, key, shape, artifact)
    }

    /// Wide and serial keys have distinct domains. Exact native public values,
    /// height and real proof verification are required even for a cache hit.
    pub fn load_wide(
        &self,
        factory: &WideShakeFactory<'_>,
        index: usize,
    ) -> Result<Option<ShakeSegmentProof>> {
        if !self.control.read(Family::Crypto) {
            return Ok(None);
        }
        let key = factory.cache_key(index)?;
        let Some(entry) = self.read_wide_entry(&self.entry_path(&key))? else {
            return Ok(None);
        };
        require(
            entry.schema == WIDE_SCHEMA
                && entry.key == key
                && entry.source == Some(crate::graph_proofs::compiled_source_fingerprint()),
            "wide SHAKE cache key/source/version mismatch; legacy archives require explicit import",
        )?;
        factory.verify_segment(index, &entry.artifact)?;
        self.control.hit(Family::Crypto);
        Ok(Some(entry.artifact))
    }
    fn read_wide_entry(&self, path: &Path) -> Result<Option<WideEntry>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        require(
            file.metadata().map_err(err)?.len() <= self.max_entry_bytes,
            "wide SHAKE cached proof exceeds byte limit",
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(
            bytes.len() as u64 <= self.max_entry_bytes,
            "wide SHAKE cached proof exceeds byte limit",
        )?;
        type Current = (
            u64,
            String,
            [u8; 32],
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        );
        type Legacy = (u64, String, Vec<Val>, p3_uni_stark::Proof<profile::Config>);
        let (schema, encoded_key, source, public, proof) =
            match serde_json::from_slice::<Current>(&bytes) {
                Ok((schema, key, source, public, proof)) => {
                    require(schema == WIDE_SCHEMA, "wide SHAKE archive schema")?;
                    (schema, key, Some(source), public, proof)
                }
                Err(_) => {
                    let (schema, key, public, proof): Legacy =
                        serde_json::from_slice(&bytes).map_err(err)?;
                    require(schema == SCHEMA, "legacy wide SHAKE archive schema")?;
                    (schema, key, None, public, proof)
                }
            };
        let key = decode_hex_key(&encoded_key)?;
        let artifact = ShakeSegmentProof {
            public_values: public
                .try_into()
                .map_err(|_| Error("wide SHAKE cache public width".into()))?,
            proof,
        };
        Ok(Some(WideEntry {
            schema,
            key,
            source,
            archive_sha3_256: Sha3_256::digest(&bytes).into(),
            artifact,
        }))
    }
    /// Import an explicitly selected archive under the current exact request.
    /// Legacy entries have no separately recorded source fingerprint. Their
    /// original key is still preserved and never presented as a current hit.
    pub fn import_wide(
        &self,
        factory: &WideShakeFactory<'_>,
        index: usize,
        path: impl AsRef<Path>,
    ) -> Result<WideArchiveImport> {
        if !self.control.allows_import() {
            return Err(Error("FreshOnly disallows archived proof import".into()));
        }
        self.control.read(Family::Crypto);
        let entry = self
            .read_wide_entry(path.as_ref())?
            .ok_or_else(|| Error("wide SHAKE archive does not exist".into()))?;
        factory.verify_segment(index, &entry.artifact)?;
        Ok(WideArchiveImport {
            artifact: entry.artifact,
            archived_schema: entry.schema,
            archived_key: entry.key,
            archived_source_fingerprint: entry.source,
            archive_sha3_256: entry.archive_sha3_256,
            current_key: factory.cache_key(index)?,
            current_source_fingerprint: crate::graph_proofs::compiled_source_fingerprint(),
        })
    }
    pub fn store_wide(
        &self,
        factory: &WideShakeFactory<'_>,
        index: usize,
        artifact: &ShakeSegmentProof,
    ) -> Result<()> {
        factory.verify_segment(index, artifact)?;
        let key = factory.cache_key(index)?;
        if self.load_wide(factory, index)?.is_some() {
            return Ok(());
        }
        let encoded = serde_json::to_vec(&(
            WIDE_SCHEMA,
            hex(&key),
            crate::graph_proofs::compiled_source_fingerprint(),
            artifact.public_values.as_slice(),
            &artifact.proof,
        ))
        .map_err(err)?;
        require(
            encoded.len() as u64 <= self.max_entry_bytes,
            "encoded wide SHAKE proof exceeds byte limit",
        )?;
        let temporary = self.directory.join(format!(
            ".{}-{}-{}.tmp",
            hex(&key),
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = write_atomic(&temporary, &self.entry_path(&key), &encoded);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn load_or_prove_wide(
        &self,
        factory: &WideShakeFactory<'_>,
        index: usize,
    ) -> Result<WideCacheOutcome> {
        self.load_or_prove_wide_with_context(factory, index, None)
    }
    pub fn load_or_prove_wide_with_context(
        &self,
        factory: &WideShakeFactory<'_>,
        index: usize,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<WideCacheOutcome> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && self.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(Error(
                "native GPU crypto coverage requires FreshOnly".into(),
            ));
        }
        let key = factory.cache_key(index)?;
        if let Some(artifact) = self.load_wide(factory, index)? {
            return Ok(WideCacheOutcome {
                artifact,
                cache_hit: true,
                key,
            });
        }
        self.control.attempt(Family::Crypto);
        let artifact = factory.prove_segment_with_context(index, execution)?;
        self.control.fresh(Family::Crypto);
        self.store_wide(factory, index, &artifact)?;
        Ok(WideCacheOutcome {
            artifact,
            cache_hit: false,
            key,
        })
    }
}
fn write_atomic(temporary: &Path, destination: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    drop(file);
    fs::rename(temporary, destination).map_err(err)
}
