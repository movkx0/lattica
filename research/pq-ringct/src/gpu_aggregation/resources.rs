//! Conservative simultaneous envelope, held until queues and GPU are retired.
//! Reservations are bounds, not measured RSS. The external zero-swap guard
//! also measures the process and caps opaque driver memory separately.
use super::*;
use lattica_prover_p3::ringct_research_quota::{
    Bytes, Category, Ledger, Reservation, WorkerAllowance,
};

pub(super) struct Envelope {
    max_rows: usize,
    ledger: Ledger,
    owners: Vec<Reservation>,
    weighted: bool,
    workers: usize,
}
impl Envelope {
    pub fn new(options: &Options) -> Result<Self> {
        let host = if options.transactions == 3 { 32 } else { 36 };
        ensure(
            std::env::var("LATTICA_RINGCT_HOST_PROFILE").unwrap_or_default()
                == if host == 32 {
                    "standard"
                } else {
                    "expanded-36"
                },
            "worker/host profile mismatch",
        )?;
        let device = memory::selected(options)?
            .and_then(|v| v["managed_bytes"].as_u64())
            .unwrap_or(8 << 30);
        let ledger = Ledger::new(WorkerAllowance {
            host: host << 30,
            device,
        });
        let mut owners = Vec::new();
        let mut reserve = |category, host, device| -> Result<()> {
            owners.push(
                ledger
                    .reserve(category, Bytes { host, device })
                    .map_err(error)?,
            );
            Ok(())
        };
        // Input graph, bounded native artifacts, compact verifier keys/proofs.
        reserve(Category::CompilerInputs, 2 << 30, 0)?;
        // Each of two compilers: 2 GiB source + 512 MiB auxiliary workspace.
        reserve(
            Category::SymbolicCompiler,
            if matches!(
                options.profile.as_str(),
                "grouped-v3" | "grouped-v4" | "grouped-v5"
            ) {
                policy::current().symbolic_bytes
            } else {
                5 << 30
            },
            0,
        )?;
        // Four admitted jobs, including the currently consumed program.
        reserve(
            Category::RegisteredMetadata,
            (policy::current().program_bytes * policy::current().live_jobs) as u64,
            0,
        )?;
        // Registration/identity/proving are serialized on the sole GPU owner.
        // V3's four permits include building, queued and consuming programs:
        // 4 * 2 GiB source storage + 2 * 512 MiB compiler/identity auxiliaries.
        // Building programs are not four additional retained programs. The
        // resulting 20 GiB backend phase includes the full 8 GiB tree quota.
        reserve(
            Category::PhaseScratch,
            if matches!(
                options.profile.as_str(),
                "grouped-v3" | "grouped-v4" | "grouped-v5"
            ) {
                policy::current().backend_host_bytes
            } else {
                16 << 30
            },
            device,
        )?;
        reserve(Category::Report, 1 << 30, 0)?;
        Ok(Self {
            ledger,
            owners,
            max_rows: options.max_rows(),
            weighted: options.typed_recursion()
                && matches!(options.command.as_str(), "run" | "architecture-request"),
            workers: options.preparation_workers,
        })
    }
    pub fn finish(mut self) -> Result<serde_json::Value> {
        let peak = self.ledger.snapshot();
        self.owners.clear();
        let released = self.ledger.snapshot();
        ensure(
            released.current == Bytes::ZERO,
            "aggregation reservations leaked",
        )?;
        Ok(serde_json::json!({"worker_host_bytes":peak.allowance.host,
            "reserved_host_peak_bytes":peak.peak.host,"reserved_device_peak_bytes":peak.peak.device,
            "current_host_bytes":released.current.host,"current_device_bytes":released.current.device,
            "cpu_compilers":if self.weighted {self.workers} else {2},"maximum_live_jobs":if self.weighted {16} else {policy::current().live_jobs},"single_gpu_consumer":true,
            "preparation_admission":if self.weighted {"weighted-bytes"} else {"fixed-job-count"},
            "maximum_recursive_rows":self.max_rows,
            "reservation_counters_are_not_rss":true}))
    }
}
