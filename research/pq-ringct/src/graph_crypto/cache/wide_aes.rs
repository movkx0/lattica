//! Bounded cache and explicit archival revalidation for complete wide AES.
use super::*;

const WIDE_AES_SCHEMA: u64 = 3;

pub struct WideAesCacheOutcome {
    pub artifact: WideAesProof,
    pub cache_hit: bool,
    pub key: [u8; 32],
}

/// Archival metadata is reported as stored, not authenticated build provenance.
/// Import verifies the actual native proof under the current trusted request;
/// it never rewrites the archive or promotes it to a current-source cache hit.
pub struct WideAesArchiveImport {
    pub artifact: WideAesProof,
    pub archived_schema: u64,
    pub archived_key: [u8; 32],
    pub archived_source_fingerprint: [u8; 32],
    pub archive_sha3_256: [u8; 32],
    pub current_key: [u8; 32],
    pub current_source_fingerprint: [u8; 32],
}

struct Entry {
    schema: u64,
    key: [u8; 32],
    source: [u8; 32],
    digest: [u8; 32],
    artifact: WideAesProof,
}

impl ProofCache {
    fn read_wide_aes_entry(&self, path: &Path) -> Result<Option<Entry>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        require(
            file.metadata().map_err(err)?.len() <= self.max_entry_bytes,
            "wide AES cached proof exceeds byte limit",
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(
            bytes.len() as u64 <= self.max_entry_bytes,
            "wide AES cached proof exceeds byte limit",
        )?;
        let (schema, encoded_key, source, public, proof): (
            u64,
            String,
            [u8; 32],
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        ) = serde_json::from_slice(&bytes).map_err(err)?;
        require(schema == WIDE_AES_SCHEMA, "wide AES archive schema")?;
        require(
            encoded_key.len() == 64 && encoded_key.as_bytes().iter().all(u8::is_ascii_hexdigit),
            "wide AES archive key encoding",
        )?;
        let mut key = [0; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded_key[2 * i..2 * i + 2], 16).map_err(err)?;
        }
        let public_values = public
            .try_into()
            .map_err(|_| Error("wide AES cache public width".into()))?;
        Ok(Some(Entry {
            schema,
            key,
            source,
            digest: Sha3_256::digest(&bytes).into(),
            artifact: WideAesProof {
                public_values,
                proof,
            },
        }))
    }

    pub fn load_wide_aes(&self, factory: &WideAesFactory<'_>) -> Result<Option<WideAesProof>> {
        if !self.control.read(Family::Crypto) {
            return Ok(None);
        }
        let key = factory.cache_key()?;
        let Some(entry) = self.read_wide_aes_entry(&self.entry_path(&key))? else {
            return Ok(None);
        };
        require(
            entry.key == key && entry.source == crate::graph_proofs::compiled_source_fingerprint(),
            "wide AES cache key/source mismatch; archives require explicit import",
        )?;
        factory.verify(&entry.artifact)?;
        self.control.hit(Family::Crypto);
        Ok(Some(entry.artifact))
    }

    pub fn import_wide_aes(
        &self,
        factory: &WideAesFactory<'_>,
        path: impl AsRef<Path>,
    ) -> Result<WideAesArchiveImport> {
        if !self.control.allows_import() {
            return Err(Error("FreshOnly disallows archived proof import".into()));
        }
        self.control.read(Family::Crypto);
        let entry = self
            .read_wide_aes_entry(path.as_ref())?
            .ok_or_else(|| Error("wide AES archive does not exist".into()))?;
        factory.verify(&entry.artifact)?;
        Ok(WideAesArchiveImport {
            artifact: entry.artifact,
            archived_schema: entry.schema,
            archived_key: entry.key,
            archived_source_fingerprint: entry.source,
            archive_sha3_256: entry.digest,
            current_key: factory.cache_key()?,
            current_source_fingerprint: crate::graph_proofs::compiled_source_fingerprint(),
        })
    }

    pub fn store_wide_aes(
        &self,
        factory: &WideAesFactory<'_>,
        artifact: &WideAesProof,
    ) -> Result<()> {
        factory.verify(artifact)?;
        let key = factory.cache_key()?;
        if self.load_wide_aes(factory)?.is_some() {
            return Ok(());
        }
        let encoded = serde_json::to_vec(&(
            WIDE_AES_SCHEMA,
            hex(&key),
            crate::graph_proofs::compiled_source_fingerprint(),
            artifact.public_values.as_slice(),
            &artifact.proof,
        ))
        .map_err(err)?;
        require(
            encoded.len() as u64 <= self.max_entry_bytes,
            "encoded wide AES proof exceeds byte limit",
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

    pub fn load_or_prove_wide_aes(
        &self,
        factory: &WideAesFactory<'_>,
    ) -> Result<WideAesCacheOutcome> {
        self.load_or_prove_wide_aes_with_context(factory, None)
    }
    pub fn load_or_prove_wide_aes_with_context(
        &self,
        factory: &WideAesFactory<'_>,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<WideAesCacheOutcome> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && self.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(Error(
                "native GPU crypto coverage requires FreshOnly".into(),
            ));
        }
        let key = factory.cache_key()?;
        if let Some(artifact) = self.load_wide_aes(factory)? {
            return Ok(WideAesCacheOutcome {
                artifact,
                cache_hit: true,
                key,
            });
        }
        self.control.attempt(Family::Crypto);
        let artifact = factory.prove_with_context(execution)?;
        self.control.fresh(Family::Crypto);
        self.store_wide_aes(factory, &artifact)?;
        Ok(WideAesCacheOutcome {
            artifact,
            cache_hit: false,
            key,
        })
    }
}
