//! Retained device-only commitment backing coexists with opening construction,
//! FRI and hiding output. Shared wrappers may be overcounted; engine/session,
//! transcript, driver, device payload and allocator overhead stay separate.
use super::ProverData;

#[derive(Debug)]
pub(super) struct Partition {
    pub retained_bytes: usize,
    pub opening_allowance: usize,
    pub operation_allowance: usize,
}

impl Partition {
    fn from_backings(
        backings: impl IntoIterator<Item = Result<Option<usize>, String>>,
        allowance: usize,
    ) -> Result<Option<Self>, String> {
        let mut retained_bytes = 0usize;
        for backing in backings {
            let Some(bytes) = backing? else {
                return Ok(None);
            };
            retained_bytes = retained_bytes
                .checked_add(bytes)
                .ok_or("retained commitment storage overflow")?;
        }
        let opening_allowance = allowance
            .checked_sub(retained_bytes)
            .filter(|bytes| *bytes > 0)
            .ok_or("retained commitments exceed opening allowance")?;
        Ok(Some(Self {
            retained_bytes,
            opening_allowance,
            operation_allowance: allowance,
        }))
    }

    pub(super) fn new<F>(
        rounds: &[(&ProverData, Vec<Vec<F>>)],
        allowance: usize,
    ) -> Result<Option<Self>, String> {
        Self::from_backings(
            rounds.iter().map(|(data, _)| data.opening_host_backing()),
            allowance,
        )
    }

    pub(super) fn report(&self) {
        eprintln!("bounded_opening_commitment_partition retained_bytes={} opening_allowance_bytes={} operation_allowance_bytes={} device_only=true whole_proof=false",
            self.retained_bytes, self.opening_allowance, self.operation_allowance);
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
