//! Host-approved timing evidence. Never decode this from a worker result.
//! These estimates confer no proof, device, resource or deadline admission.

use super::*;

/// Immutable qualification inputs approved by the host. Each field is a
/// nonzero fingerprint of the corresponding exact configuration. `settings`
/// includes geometry, cache policy, GPU switches and host/device budgets.
/// The local adapter additionally binds its actual immutable descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimingIdentity {
    fingerprints: [[u8; 32]; 6],
}

impl TimingIdentity {
    pub fn new(
        backend: [u8; 32],
        kernels: [u8; 32],
        executable: [u8; 32],
        device: [u8; 32],
        driver: [u8; 32],
        settings: [u8; 32],
    ) -> Result<Self, Error> {
        let fingerprints = [backend, kernels, executable, device, driver, settings];
        if fingerprints.contains(&[0; 32]) {
            return Err("scheduler timing identity has an empty fingerprint".into());
        }
        Ok(Self { fingerprints })
    }

    pub(crate) fn bind_configuration(
        mut self,
        executable: [u8; 32],
        configuration: [u8; 32],
    ) -> Result<Self, Error> {
        if self.fingerprints[2] != executable {
            return Err("scheduler timing identity executable mismatch".into());
        }
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.fingerprints[5]);
        bytes[32..].copy_from_slice(&configuration);
        self.fingerprints[5] =
            crate::block_v2::execution::launch::digest(0x4c545443464731, &bytes)?;
        Ok(self)
    }
}

/// Provenance of the selected service estimate, not of the entire DAG path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EstimateSource {
    Bootstrap,
    Live,
    ColdLive,
    Calibration([u8; 32]),
    ColdCalibration([u8; 32]),
}

/// A fixed-size, bounded copy of exact live observations. Re-exporting imported
/// observations is forbidden. The host must approve the evidence and verify its
/// fingerprint before decoding/importing; this format is not authentication.
#[derive(Clone, Debug)]
pub struct TimingCalibration {
    identity: TimingIdentity,
    profile: [u8; 32],
    resources: Resources,
    mode: u64,
    level: u8,
    input_count: u8,
    warm: bool,
    count: u8,
    samples: [u64; MAX_SAMPLES],
}

impl TimingCalibration {
    pub const ENCODED_BYTES: usize = 8 + 6 * 32 + 32 + 3 * 8 + 4 + 8 + 4 + 8 * MAX_SAMPLES;
    const MAGIC: &'static [u8; 8] = b"LTTCAL01";

    pub fn encode(&self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        let mut offset = 0;
        let mut write = |value: &[u8]| {
            bytes[offset..offset + value.len()].copy_from_slice(value);
            offset += value.len();
        };
        write(Self::MAGIC);
        for field in self.identity.fingerprints {
            write(&field);
        }
        write(&self.profile);
        for value in [
            self.resources.ram_bytes,
            self.resources.vram_bytes,
            self.resources.scratch_bytes,
        ] {
            write(&value.to_le_bytes());
        }
        write(&self.resources.threads.to_le_bytes());
        write(&self.mode.to_le_bytes());
        write(&[
            self.level,
            self.input_count,
            u8::from(self.warm),
            self.count,
        ]);
        for value in self.samples {
            write(&value.to_le_bytes());
        }
        debug_assert_eq!(offset, Self::ENCODED_BYTES);
        bytes
    }

    pub fn decode_host(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::ENCODED_BYTES || &bytes[..8] != Self::MAGIC {
            return Err("scheduler calibration encoding".into());
        }
        fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
            let value = bytes[*offset..*offset + N].try_into().unwrap();
            *offset += N;
            value
        }
        let mut offset = 8;
        let mut fingerprints = [[0; 32]; 6];
        for field in &mut fingerprints {
            *field = take(bytes, &mut offset);
        }
        let identity = TimingIdentity::new(
            fingerprints[0],
            fingerprints[1],
            fingerprints[2],
            fingerprints[3],
            fingerprints[4],
            fingerprints[5],
        )?;
        let profile = take(bytes, &mut offset);
        let resources = Resources {
            ram_bytes: u64::from_le_bytes(take(bytes, &mut offset)),
            vram_bytes: u64::from_le_bytes(take(bytes, &mut offset)),
            scratch_bytes: u64::from_le_bytes(take(bytes, &mut offset)),
            threads: u32::from_le_bytes(take(bytes, &mut offset)),
        };
        let mode = u64::from_le_bytes(take(bytes, &mut offset));
        let [level, input_count, warm, count] = take(bytes, &mut offset);
        if warm > 1 {
            return Err("scheduler calibration warm flag".into());
        }
        let mut samples = [0; MAX_SAMPLES];
        for sample in &mut samples {
            *sample = u64::from_le_bytes(take(bytes, &mut offset));
        }
        debug_assert_eq!(offset, bytes.len());
        let record = Self {
            identity,
            profile,
            resources,
            mode,
            level,
            input_count,
            warm: warm == 1,
            count,
            samples,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), Error> {
        self.resources.validate_capacity()?;
        if self.profile == [0; 32]
            || !(1..=crate::block_v2::machine::typed_pairs::FINALIZE).contains(&self.mode)
            || self.level > crate::block_v2::commitment::DEPTH
            || usize::from(self.input_count) > crate::block_v2::commitment::CAPACITY
            || !(1..=MAX_SAMPLES).contains(&usize::from(self.count))
        {
            return Err("scheduler calibration class/count".into());
        }
        let (used, unused) = self.samples.split_at(usize::from(self.count));
        if used.iter().any(|ms| !(1..=7_200_000).contains(ms)) || unused.iter().any(|ms| *ms != 0) {
            return Err("scheduler calibration sample bounds/padding".into());
        }
        Ok(())
    }
}

impl CostModel {
    pub fn export_calibration(
        &self,
        worker: &WorkerCapabilities,
        job: &Job,
        warm: bool,
    ) -> Result<TimingCalibration, Error> {
        let key = Self::key(worker, job, warm)?;
        let history = self
            .samples
            .get(&key)
            .ok_or("scheduler calibration requires exact live history")?;
        if history.evidence.is_some() {
            return Err("scheduler cannot re-export imported calibration".into());
        }
        let mut record = TimingCalibration {
            identity: worker
                .timing_identity
                .ok_or("scheduler calibration requires a timing identity")?,
            profile: worker.profile,
            resources: worker.resources,
            mode: key.mode,
            level: key.level,
            input_count: key.count,
            warm,
            count: u8::try_from(history.samples.len())?,
            samples: [0; MAX_SAMPLES],
        };
        for (out, sample) in record.samples.iter_mut().zip(&history.samples) {
            *out = *sample;
        }
        record.validate()?;
        Ok(record)
    }

    /// Import only host-approved evidence for an idle worker's exact class.
    /// Explicit imports never overwrite live or previously imported history.
    pub fn import_calibration(
        &mut self,
        worker: &WorkerCapabilities,
        record: &TimingCalibration,
        evidence: [u8; 32],
    ) -> Result<(), Error> {
        record.validate()?;
        if worker.worker.0 == 0
            || evidence == [0; 32]
            || worker.timing_identity != Some(record.identity)
            || worker.profile != record.profile
            || worker.resources != record.resources
        {
            return Err("scheduler calibration identity/resources mismatch".into());
        }
        let key = CostKey {
            worker: worker.worker.0,
            profile: worker.profile,
            identity: worker.timing_identity,
            mode: record.mode,
            level: record.level,
            count: record.input_count,
            ram_bytes: worker.resources.ram_bytes,
            vram_bytes: worker.resources.vram_bytes,
            scratch_bytes: worker.resources.scratch_bytes,
            threads: worker.resources.threads,
            warm: record.warm,
        };
        if self.samples.contains_key(&key) {
            return Err("scheduler calibration would replace existing history".into());
        }
        self.admit_class(key)?;
        let mut samples = VecDeque::with_capacity(MAX_SAMPLES);
        samples.extend(record.samples[..usize::from(record.count)].iter().copied());
        self.samples.insert(
            key,
            History {
                samples,
                evidence: Some(evidence),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
