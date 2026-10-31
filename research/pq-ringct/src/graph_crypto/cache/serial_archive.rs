//! Explicit bounded serial archive revalidation. Stored keys/provenance are
//! reported metadata; the current exact request and native verifier authenticate
//! the proof. Import never rewrites an archive or creates a current cache entry.
use super::*;

pub struct SerialArchiveImport {
    pub artifact: SegmentArtifact,
    pub archived_schema: u64,
    pub archived_key: [u8; 32],
    /// Serial schema1 predates an explicit source-fingerprint field. Its opaque
    /// cache key is not reversible and cannot authenticate build provenance.
    pub archived_source_fingerprint: Option<[u8; 32]>,
    pub archive_sha3_256: [u8; 32],
    pub current_key: [u8; 32],
    pub current_source_fingerprint: [u8; 32],
}

impl ProofCache {
    pub fn import_segment(
        &self,
        request: &Request,
        index: usize,
        path: &Path,
    ) -> Result<SerialArchiveImport> {
        if !self.control.allows_import() {
            return Err(Error("FreshOnly disallows archived proof import".into()));
        }
        self.control.read(Family::Crypto);
        let current_key = request.cache_key(index)?;
        let mut file = File::open(path).map_err(err)?;
        require(
            file.metadata().map_err(err)?.len() <= self.max_entry_bytes,
            "serial archive exceeds byte limit",
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(
            bytes.len() as u64 <= self.max_entry_bytes,
            "serial archive exceeds byte limit",
        )?;
        let (schema, encoded_key, public, proof): (
            u64,
            String,
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        ) = serde_json::from_slice(&bytes).map_err(err)?;
        require(schema == SCHEMA, "unsupported serial archive schema")?;
        require(
            encoded_key.len() == 64 && encoded_key.as_bytes().iter().all(u8::is_ascii_hexdigit),
            "serial archive key encoding",
        )?;
        let mut archived_key = [0; 32];
        for (i, byte) in archived_key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded_key[2 * i..2 * i + 2], 16).map_err(err)?;
        }
        let artifact = match request.descriptor() {
            RequestDescriptor::Aes(_) => SegmentArtifact::Aes(AesLaneSegmentProof {
                public_values: public
                    .try_into()
                    .map_err(|_| Error("AES archive public width".into()))?,
                proof,
            }),
            RequestDescriptor::Shake(_) => SegmentArtifact::Shake(LaneShakeProof {
                public_values: public
                    .try_into()
                    .map_err(|_| Error("SHAKE archive public width".into()))?,
                proof,
            }),
        };
        request.verify_segment(index, &artifact)?;
        Ok(SerialArchiveImport {
            artifact,
            archived_schema: schema,
            archived_key,
            archived_source_fingerprint: None,
            archive_sha3_256: Sha3_256::digest(&bytes).into(),
            current_key,
            current_source_fingerprint: crate::graph_proofs::compiled_source_fingerprint(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_malformed_and_oversized_serial_archives_do_not_write_or_prove() {
        let request = Request::new(
            [7; 32],
            0,
            0,
            RequestDescriptor::Aes(aes_lane_air::Descriptor {
                domain: 1,
                start_counter: 0,
                output_len: 16,
            }),
            Payload::Aes([9; 32]),
            Policy::default(),
        )
        .unwrap();
        let directory = std::env::temp_dir().join(format!(
            "lattica-serial-archive-boundary-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        ));
        assert!(!directory.exists());
        let cache = ProofCache::new(directory.join("cache"), 4).unwrap();
        let archive = directory.join("archive.json");
        assert!(cache.import_segment(&request, 0, &archive).is_err());
        fs::write(&archive, b"12345").unwrap();
        let error = cache.import_segment(&request, 0, &archive).err().unwrap();
        assert!(error.0.contains("exceeds byte limit"));
        assert_eq!(fs::read(&archive).unwrap(), b"12345");
        fs::write(&archive, b"null").unwrap();
        assert!(cache.import_segment(&request, 0, &archive).is_err());
        assert!(cache.import_segment(&request, 1, &archive).is_err());
        assert_eq!(fs::read(&archive).unwrap(), b"null");
        assert_eq!(fs::read_dir(directory.join("cache")).unwrap().count(), 0);
        fs::remove_dir_all(directory).unwrap();
    }
}
