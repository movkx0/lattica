//! Caller-owned completion metadata for one sequential pool request. The
//! service does not replace endpoints during a request, so each can fail once.

use super::*;
use lattica_prover_p3::block_v2::execution::pool::{AcceptedJob, PoolOutputStorage};
use std::mem::size_of;

const JOB_LIMIT: usize = 2 * commitment::CAPACITY - 1;

#[derive(serde::Serialize)]
pub(super) struct JobRecord {
    #[serde(serialize_with = "job_hex")]
    job: [u8; 32],
    worker: u64,
    elapsed_ms: u64,
    proof_bytes: usize,
}

fn job_hex<S: serde::Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = [0; 64];
    for (i, byte) in bytes.iter().enumerate() {
        text[2 * i] = HEX[(byte >> 4) as usize];
        text[2 * i + 1] = HEX[(byte & 15) as usize];
    }
    serializer.serialize_str(std::str::from_utf8(&text).map_err(serde::ser::Error::custom)?)
}

#[derive(serde::Serialize)]
pub(super) struct FailureRecord {
    worker: u64,
    reason: String,
}

pub(super) struct Report {
    jobs: Vec<JobRecord>,
    failures: Vec<FailureRecord>,
    job_limit: usize,
    worker_limit: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Storage {
    pub retained_bytes: usize,
    pub json_bytes: usize,
    pub output: PoolOutputStorage,
}

impl Storage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        self.retained_bytes
            .checked_add(self.json_bytes)
            .and_then(|n| n.checked_add(self.output.total_bytes().ok()?))
            .ok_or_else(|| "pool report storage overflow".into())
    }
}

impl Report {
    pub fn storage_plan(jobs: usize, workers: usize) -> Result<Storage, Error> {
        if !(1..=JOB_LIMIT).contains(&jobs)
            || !(1..=PoolOutputStorage::ACCEPTED_LIMIT).contains(&workers)
        {
            return Err("pool report cardinality".into());
        }
        Ok(Storage {
            retained_bytes: size_of::<Self>()
                + jobs * size_of::<JobRecord>()
                + workers * (size_of::<FailureRecord>() + PoolOutputStorage::FAILURE_BYTES),
            json_bytes: JSON_LIMIT + size_of::<Vec<u8>>(),
            output: PoolOutputStorage::new()?,
        })
    }

    pub fn new(jobs: usize, workers: usize) -> Result<Self, Error> {
        Self::storage_plan(jobs, workers)?.total_bytes()?;
        let mut result = Self {
            jobs: Vec::new(),
            failures: Vec::new(),
            job_limit: jobs,
            worker_limit: workers,
        };
        result.jobs.try_reserve_exact(jobs)?;
        result.failures.try_reserve_exact(workers)?;
        if result.jobs.capacity() != jobs || result.failures.capacity() != workers {
            return Err("pool report capacity rounding".into());
        }
        Ok(result)
    }

    fn push_job(&mut self, job: JobRecord) -> Result<(), Error> {
        if self.jobs.len() >= self.job_limit {
            return Err("pool report accepted-job limit".into());
        }
        self.jobs.push(job);
        Ok(())
    }

    pub fn accepted(&mut self, job: AcceptedJob) -> Result<(), Error> {
        self.push_job(JobRecord {
            job: job.job.to_bytes(),
            worker: job.worker.0,
            elapsed_ms: job.elapsed_ms,
            proof_bytes: job.proof_bytes,
        })
    }

    pub fn failed(&mut self, worker: WorkerId, reason: String) -> Result<(), Error> {
        if self.failures.len() >= self.worker_limit {
            return Err("pool report failed-worker limit".into());
        }
        if reason.capacity() > PoolOutputStorage::FAILURE_BYTES {
            return Err("pool report failure backing".into());
        }
        self.failures.push(FailureRecord {
            worker: worker.0,
            reason,
        });
        Ok(())
    }

    pub fn jobs(&self) -> &[JobRecord] {
        &self.jobs
    }
    pub fn failures(&self) -> &[FailureRecord] {
        &self.failures
    }

    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let bytes = size_of::<Self>()
            + self.jobs.capacity() * size_of::<JobRecord>()
            + self.failures.capacity() * size_of::<FailureRecord>()
            + self
                .failures
                .iter()
                .map(|value| value.reason.capacity())
                .sum::<usize>();
        if bytes > Self::storage_plan(self.job_limit, self.worker_limit)?.retained_bytes {
            return Err("pool report retained storage invariant".into());
        }
        Ok(bytes)
    }
}

/// Keep the previous 128 KiB output limit, rejecting before a write can grow
/// the buffer. This preserves JSON values without building a serde_json::Value
/// tree or an unbounded serialization Vec. Serializer/runtime stacks are separate.
pub(super) fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, Error> {
    struct Buffer(Vec<u8>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > JSON_LIMIT - self.0.len() {
                return Err(std::io::Error::other("pool JSON output limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut buffer = Buffer(Vec::new());
    buffer.0.try_reserve_exact(JSON_LIMIT)?;
    if buffer.0.capacity() != JSON_LIMIT {
        return Err("pool JSON capacity rounding".into());
    }
    serde_json::to_writer_pretty(&mut buffer, value)?;
    Ok(buffer.0)
}

#[derive(serde::Serialize)]
pub(super) struct Completion<'a> {
    pub schema_version: u32,
    pub status: &'a str,
    pub root_file: &'a str,
    pub fresh_proofs: usize,
    pub reused_proofs: usize,
    pub started_ms: u64,
    pub completed_ms: u64,
    pub worker_failures: &'a [FailureRecord],
    pub native_host: &'a native::Binding,
    pub native_applied: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(n: u8) -> JobRecord {
        JobRecord {
            job: [n; 32],
            worker: u64::MAX,
            elapsed_ms: u64::MAX,
            proof_bytes: PoolOutputStorage::ROOT_LIMIT,
        }
    }

    #[test]
    fn report_counts_full_capacity_and_rejects_extra_records_without_growth() {
        for workers in 1..=16 {
            let mut report = Report::new(JOB_LIMIT, workers).unwrap();
            let plan = Report::storage_plan(JOB_LIMIT, workers).unwrap();
            for i in 0..JOB_LIMIT {
                report.push_job(job(i as u8)).unwrap();
            }
            for i in 0..workers {
                let reason = "\u{1f680}".repeat(PoolOutputStorage::FAILURE_BYTES / 4);
                report.failed(WorkerId(i as u64), reason).unwrap();
            }
            assert_eq!(
                report.retained_storage_bytes().unwrap(),
                plan.retained_bytes
            );
            assert!(report.push_job(job(255)).is_err());
            assert!(report.failed(WorkerId(99), String::new()).is_err());
            assert_eq!(
                report.retained_storage_bytes().unwrap(),
                plan.retained_bytes
            );
            if workers == 1 || workers == 16 {
                eprintln!("bounded_pool_report workers={workers} jobs={JOB_LIMIT} retained_bytes={} json_bytes={} output_bytes={} total_bytes={}", plan.retained_bytes, plan.json_bytes, plan.output.total_bytes().unwrap(), plan.total_bytes().unwrap());
            }
        }
        for (jobs, workers) in [(0, 1), (JOB_LIMIT + 1, 1), (1, 0), (1, 17)] {
            assert!(Report::new(jobs, workers).is_err());
        }
        let mut report = Report::new(1, 1).unwrap();
        assert!(report
            .failed(
                WorkerId(1),
                String::with_capacity(PoolOutputStorage::FAILURE_BYTES + 1)
            )
            .is_err());
        assert!(report.failures().is_empty());
    }

    #[test]
    fn typed_records_preserve_json_values_and_borrow_failure_strings() {
        let mut report = Report::new(1, 1).unwrap();
        report.push_job(job(0xab)).unwrap();
        let reason = "quote \" newline\n rocket \u{1f680}".to_owned();
        let pointer = reason.as_ptr();
        report.failed(WorkerId(42), reason).unwrap();
        assert_eq!(report.failures()[0].reason.as_ptr(), pointer);
        let native_value = json!({"schema_version":1,"head_token":vec![1u8;32],"generation":0,
            "configuration_sha256":vec![2u8;32],"complete_body_sha256":vec![3u8;32],
            "preparation_sha256":vec![4u8;32],"expected":{"schema_version":1,
            "profile":vec![5u8;32],"chain":vec![6u8;32],"root":[7,7,7,7],"count":4,
            "block_height":10,"authorized_issuance":{"3":7}}});
        let native: native::Binding = serde_json::from_value(native_value.clone()).unwrap();
        let completion = Completion {
            schema_version: 1,
            status: "proved_cpu_audit_pending",
            root_file: "node.6.0",
            fresh_proofs: 1,
            reused_proofs: 0,
            started_ms: 10,
            completed_ms: 20,
            worker_failures: report.failures(),
            native_host: &native,
            native_applied: false,
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encode(&completion).unwrap()).unwrap(),
            json!({"schema_version":1,"status":"proved_cpu_audit_pending","root_file":"node.6.0",
                "fresh_proofs":1,"reused_proofs":0,"started_ms":10,"completed_ms":20,
                "worker_failures":[{"worker":42,"reason":"quote \" newline\n rocket \u{1f680}"}],
                "native_host":native_value,"native_applied":false})
        );
        let expected = json!([{"job":"ab".repeat(32),"worker":u64::MAX,
            "elapsed_ms":u64::MAX,"proof_bytes":PoolOutputStorage::ROOT_LIMIT}]);
        let bytes = encode(&report.jobs()).unwrap();
        assert_eq!(bytes.capacity(), JSON_LIMIT);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            expected
        );
        let failures = encode(&report.failures()).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&failures).unwrap(),
            json!([{"worker":42,"reason":"quote \" newline\n rocket \u{1f680}"}])
        );
        assert_eq!(report.failures()[0].reason.as_ptr(), pointer);
    }

    #[test]
    fn json_limit_is_enforced_while_serializing_at_exact_and_escaped_boundaries() {
        let exact = "x".repeat(JSON_LIMIT - 2);
        let bytes = encode(&exact).unwrap();
        assert_eq!(bytes.len(), JSON_LIMIT);
        assert_eq!(bytes, serde_json::to_vec_pretty(&exact).unwrap());
        assert!(encode(&(exact + "x")).is_err());
        let escaped = "\0".repeat((JSON_LIMIT - 2) / 6);
        assert_eq!(encode(&escaped).unwrap().len(), JSON_LIMIT);
        assert!(encode(&(escaped + "\0")).is_err());
        struct Endless;
        impl serde::Serialize for Endless {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;
                let mut values = serializer.serialize_seq(None)?;
                for _ in 0..=JSON_LIMIT {
                    values.serialize_element(&"value")?;
                }
                panic!(
                    "unbounded serializer exhausted instead of being stopped by the output limit"
                );
            }
        }
        assert!(encode(&Endless).is_err());
        eprintln!("bounded_pool_json limit_bytes={JSON_LIMIT} exact_capacity=true overflow_stops_serialization=true");
    }
}
