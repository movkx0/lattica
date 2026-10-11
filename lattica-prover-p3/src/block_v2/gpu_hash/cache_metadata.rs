//! Host backing owned by cached device-only preprocessing. Device payloads and
//! shared engine/context/driver storage have separate reservations.
use super::*;

/// Per registered AIR: inline prover data, common/cap/receipt arrays and the
/// Rust wrappers owning device prefixes, salts and their allocation handles.
/// The completed cache value is checked against this ceiling before publication.
pub(crate) const METADATA_BYTES: u64 = 1 << 20;

pub(crate) fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "cached PCS metadata overflow".into())
}
pub(crate) fn capacity<T>(count: usize) -> Result<usize, String> {
    count
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| "cached PCS capacity overflow".into())
}
pub(crate) fn arc_bytes<T>() -> usize {
    // Pinned ArcInner layout: two atomic counters followed by the aligned value.
    std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<T>())
        .unwrap()
        .0
        .pad_to_align()
        .size()
}
pub(crate) fn bound(rows: u64, device_salts: bool) -> Result<u64, String> {
    if !(8..=1 << 24).contains(&rows) || !rows.is_power_of_two() {
        return Err("cached PCS trace height".into());
    }
    // Hiding preprocessing doubles the domain, then applies LOG_BLOWUP.
    // The compatible host-salt path retains four base fields per LDE row.
    let host_salts = if device_salts {
        0
    } else {
        rows.checked_mul(2 << super::super::profile::LOG_BLOWUP)
            .and_then(|n| n.checked_mul(4 * core::mem::size_of::<Val>() as u64))
            .ok_or("cached PCS salt storage overflow")?
    };
    METADATA_BYTES
        .checked_add(host_salts)
        .ok_or_else(|| "cached PCS bound overflow".into())
}

impl<M> ProverData<M> {
    /// Excludes inline ProverData (charged by its caller), lookup graphs, and
    /// device payloads. Shared allocation Arcs may be counted more than once;
    /// no deduplication workspace or field arithmetic is needed.
    pub(crate) fn cached_preprocessing_backing(
        &self,
        rows: usize,
        matrices: usize,
    ) -> Result<(usize, bool), String> {
        let Self::DeviceOnly { owned, salts, tree } = self else {
            return Err("cached PCS metadata requires device-only preprocessing".into());
        };
        if !(1..=256).contains(&matrices) {
            return Err("cached PCS matrix count".into());
        }
        bound(rows as u64, false)?;
        let height = rows
            .checked_mul(2 << super::super::profile::LOG_BLOWUP)
            .ok_or("cached PCS LDE height overflow")?;
        let prefixes = owned.cached_public_backing(height, matrices)?;
        let (salts, device_salts) = salts.cached_public_backing(height, matrices)?;
        Ok((
            add(add(prefixes, salts)?, tree.cached_host_backing()?)?,
            device_salts,
        ))
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn cached_allocation_arc_layout_matches_requested_storage_and_alignment() {
        #[repr(align(64))]
        struct Aligned([u8; 17]);
        let (owned, measured) = measure(|| std::sync::Arc::new(Aligned([7; 17])));
        assert_eq!(measured.calls, 1);
        assert_eq!(measured.bytes, arc_bytes::<Aligned>());
        assert_eq!(owned.0[0], 7);
        eprintln!(
            "cached_pcs_arc aligned_payload=true requested_bytes={}",
            measured.bytes
        );
    }

    #[test]
    fn public_device_handles_and_host_salts_have_distinct_cache_bounds() {
        for rows in [8, 16, 262144, 1 << 24] {
            let (device, allocations) = measure(|| bound(rows, true).unwrap());
            assert_eq!(allocations.calls, 0);
            assert_eq!(device, METADATA_BYTES);
            assert_eq!(bound(rows, false).unwrap() - device, rows * 1024);
        }
        for rows in [0, 7, 9, (1 << 24) + 1, u64::MAX] {
            assert!(bound(rows, false).is_err());
            assert!(bound(rows, true).is_err());
        }
        eprintln!("cached_pcs_modes metadata_bytes={} host_salt_bytes_per_trace_row=1024 planning_allocation_free=true", METADATA_BYTES);
    }

    #[test]
    fn retained_host_salt_census_counts_spare_capacity_without_field_work() {
        let mut fields = Vec::with_capacity(64);
        fields.resize(32, Val::ONE);
        let mut matrices = Vec::with_capacity(3);
        let expected = matrices.capacity() * core::mem::size_of::<RowMajorMatrix<Val>>()
            + fields.capacity() * core::mem::size_of::<Val>();
        matrices.push(RowMajorMatrix::new(fields, 4));
        let salts = SaltStore::Host(matrices);
        let (storage, allocations) = measure(|| salts.cached_public_backing(8, 1).unwrap());
        assert_eq!(storage, (expected, false));
        assert_eq!(allocations.calls, 0);
        assert!(salts.cached_public_backing(16, 1).is_err());
        assert!(salts.cached_public_backing(8, 2).is_err());
        let mut partial = RowMajorMatrix::new(vec![Val::ONE; 32], 4);
        partial.values.push(Val::ONE);
        let partial = SaltStore::Host(vec![partial]);
        assert!(partial.cached_public_backing(8, 1).is_err());
        assert!(SaltStore::Device(vec![])
            .cached_public_backing(8, 1)
            .is_err());
        assert!(SaltStore::Replay(vec![])
            .cached_public_backing(8, 1)
            .is_err());
        eprintln!("cached_pcs_host_salts retained_bytes={expected} spare_capacity_counted=true private_salts_rejected=true census_allocation_free=true");
    }
}
