//! Conservative simultaneous envelope, held until queues and GPU are retired.
//! Reservations are bounds, not measured RSS. The external zero-swap guard
//! also measures the process and caps opaque driver memory separately.
use super::*;
use lattica_prover_p3::ringct_research_quota::{
    Bytes, Category, Ledger, Reservation, WorkerAllowance,
};

pub(super) struct Envelope {
    ledger: Ledger,
    owners: Vec<Reservation>,
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
        let ledger = Ledger::new(WorkerAllowance {
            host: host << 30,
            device: 8 << 30,
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
        reserve(Category::SymbolicCompiler, 5 << 30, 0)?;
        // Four admitted jobs, including the currently consumed program.
        reserve(Category::RegisteredMetadata, 8 << 30, 0)?;
        // Registration/identity/proving are serialized on the sole GPU owner.
        reserve(Category::PhaseScratch, 16 << 30, 8 << 30)?;
        reserve(Category::Report, 1 << 30, 0)?;
        Ok(Self { ledger, owners })
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
            "cpu_compilers":2,"maximum_live_jobs":4,"single_gpu_consumer":true,
            "maximum_recursive_rows":MAX_RECURSIVE_ROWS,
            "reservation_counters_are_not_rss":true}))
    }
}
