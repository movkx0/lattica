use super::*;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

const MAX_EVENTS: usize = 32;
const MAX_ERROR_CHARS: usize = 2048;
const MAX_ARTIFACT_BYTES: usize = 64 << 20;

#[derive(Clone, Copy, Default)]
struct NativeStageTotals {
    completed_calls: u64,
    device_calls: u64,
    device_ns: u128,
}

#[derive(Default)]
struct NativeGpuTotals {
    calls: u64,
    succeeded: u64,
    seconds: f64,
    reports: u64,
    stages: [NativeStageTotals; 16],
}

#[derive(Default)]
struct WitnessPreparationTotals {
    calls: u64,
    succeeded: u64,
    seconds: f64,
    reports: u64,
    witness: NativeStageTotals,
}

#[derive(Default)]
struct NativeSpendTotals {
    calls: u64,
    succeeded: u64,
    seconds: f64,
    reports: u64,
    peak_managed_bytes: usize,
    witness: NativeStageTotals,
}

#[derive(Default)]
struct State {
    directory: Option<PathBuf>,
    artifact_attempted: bool,
    failures: VecDeque<Value>,
    prove_calls: u64,
    prove_succeeded: u64,
    prove_seconds: f64,
    verify_calls: u64,
    verify_succeeded: u64,
    verify_seconds: f64,
    native_calls: u64,
    native_succeeded: u64,
    native_seconds: f64,
    native_gpu: NativeGpuTotals,
    witness_preparation: WitnessPreparationTotals,
    native_spend: NativeSpendTotals,
    stark_work_attempted: bool,
}

pub(super) struct Diagnostics {
    state: RefCell<State>,
    session_id: u64,
    policy: Policy,
    device: Value,
}

impl Diagnostics {
    pub(super) fn new(session_id: u64, policy: Policy, device: Value) -> Self {
        Self {
            state: RefCell::new(State::default()),
            session_id,
            policy,
            device,
        }
    }
    pub(super) fn set_directory(&self, path: PathBuf) -> Result<(), String> {
        // The owner creates/adopts a bounded diagnostics directory explicitly.
        // Never redirect an existing directory or follow a symlink destination.
        if !path.is_absolute()
            || path.canonicalize().map_err(error)? != path
            || !path.is_dir()
            || path
                .symlink_metadata()
                .map_err(error)?
                .file_type()
                .is_symlink()
        {
            return Err("failure directory must be an existing canonical directory".into());
        }
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| "diagnostics busy")?;
        if state.directory.is_some() || state.artifact_attempted || state.prove_calls != 0 {
            return Err("failure directory must be set once before proving".into());
        }
        state.directory = Some(path);
        Ok(())
    }
    pub(super) fn prove_finished(&self, seconds: f64, succeeded: bool) {
        let mut s = self.state.borrow_mut();
        s.prove_calls += 1;
        s.prove_succeeded += u64::from(succeeded);
        s.prove_seconds += seconds;
    }
    pub(super) fn mark_stark_work_attempted(&self) {
        self.state.borrow_mut().stark_work_attempted = true;
    }
    pub(super) fn verify_finished(&self, seconds: f64, succeeded: bool) {
        let mut s = self.state.borrow_mut();
        s.verify_calls += 1;
        s.verify_succeeded += u64::from(succeeded);
        s.verify_seconds += seconds;
    }
    pub(super) fn native_finished(&self, seconds: f64, succeeded: bool) {
        let mut s = self.state.borrow_mut();
        s.native_calls += 1;
        s.native_succeeded += u64::from(succeeded);
        s.native_seconds += seconds;
    }
    #[cfg(feature = "opencl")]
    pub(super) fn native_gpu_finished(
        &self,
        seconds: f64,
        report: Option<&lattica_prover_p3::proving::Report>,
    ) {
        let mut state = self.state.borrow_mut();
        let totals = &mut state.native_gpu;
        totals.calls += 1;
        totals.seconds += seconds;
        if let Some(report) = report {
            totals.succeeded += 1;
            totals.reports += 1;
            for observation in &report.observations {
                if let Some(index) = lattica_prover_p3::proving::Stage::ARITHMETIC
                    .iter()
                    .position(|&stage| stage == observation.stage)
                {
                    let stage = &mut totals.stages[index];
                    stage.completed_calls = stage
                        .completed_calls
                        .saturating_add(observation.completed_calls);
                    stage.device_calls =
                        stage.device_calls.saturating_add(observation.device_calls);
                    stage.device_ns = stage.device_ns.saturating_add(observation.device_ns);
                }
            }
        }
    }
    #[cfg(feature = "opencl")]
    pub(super) fn witness_preparation_finished(
        &self,
        seconds: f64,
        report: Option<&lattica_prover_p3::proving::Report>,
    ) {
        let mut state = self.state.borrow_mut();
        let totals = &mut state.witness_preparation;
        totals.calls += 1;
        totals.seconds += seconds;
        if let Some(report) = report {
            totals.succeeded += 1;
            totals.reports += 1;
            // The wrapper validates a single WitnessTrace observation before
            // recording. No native proof count or stage total is modified.
            let observation = &report.observations[0];
            totals.witness.completed_calls = totals
                .witness
                .completed_calls
                .saturating_add(observation.completed_calls);
            totals.witness.device_calls = totals
                .witness
                .device_calls
                .saturating_add(observation.device_calls);
            totals.witness.device_ns = totals
                .witness
                .device_ns
                .saturating_add(observation.device_ns);
        }
    }
    #[cfg(feature = "opencl")]
    pub(super) fn native_spend_finished(
        &self,
        seconds: f64,
        receipt: Option<(
            &lattica_prover_p3::proving::Report,
            &lattica_prover_p3::block_v2::native_gpu::private_spend::SpendEvidence,
        )>,
    ) {
        let mut state = self.state.borrow_mut();
        let totals = &mut state.native_spend;
        totals.calls = totals.calls.saturating_add(1);
        totals.seconds += seconds;
        if let Some((report, evidence)) = receipt {
            totals.succeeded = totals.succeeded.saturating_add(1);
            totals.reports = totals.reports.saturating_add(1);
            totals.peak_managed_bytes = totals.peak_managed_bytes.max(evidence.managed_bytes);
            // The private-spend wrapper already validated exactly one complete
            // OpenCL WitnessTrace observation and both exact schedule masks.
            // These totals never contribute to STARK or aggregate proof counts.
            let observation = &report.observations[0];
            totals.witness.completed_calls = totals
                .witness
                .completed_calls
                .saturating_add(observation.completed_calls);
            totals.witness.device_calls = totals
                .witness
                .device_calls
                .saturating_add(observation.device_calls);
            totals.witness.device_ns = totals
                .witness
                .device_ns
                .saturating_add(observation.device_ns);
        }
    }
    #[cfg(feature = "opencl")]
    pub(super) fn native_spend_only_complete_reports(&self) -> u64 {
        let state = self.state.borrow();
        if state.stark_work_attempted
            || state.prove_calls != 0
            || state.verify_calls != 0
            || state.native_gpu.calls != 0
            || state.witness_preparation.calls != 0
            || state.native_calls != 0
        {
            return 0;
        }
        state.native_spend.reports
    }
    pub(super) fn failure(
        &self,
        stage: &str,
        identity: Value,
        message: &str,
        returned: Option<(&[Val], &BatchProof<Config>)>,
    ) {
        let mut state = self.state.borrow_mut();
        let mut event = json!({"stage":stage,"identity":identity,"session_id":self.session_id,
            "policy":self.policy,"device":self.device,"error":message.chars().take(MAX_ERROR_CHARS).collect::<String>(),
            "returned_proof":returned.is_some(),"retry_attempted":false});
        if let (Some((public, proof)), Some(directory)) = (returned, state.directory.as_ref()) {
            if !state.artifact_attempted {
                let path = directory.join(format!("session-{}-failed-proof.json", self.session_id));
                state.artifact_attempted = true;
                let metadata = json!({"schema":"pq-unverified-worker-proof-v1", "failure":event,
                    "canonical_field_encoding":true,"original_raw_memory_representation_preserved":false,
                    "verification_succeeded":false,"contains_witness_or_rng_state":false});
                event["artifact"] = match preserve(&path, &metadata, public, proof) {
                    Ok(bytes) => json!({"path":path,"bytes":bytes,"complete":true}),
                    Err(message) => json!({"path":path,"complete":false,"error":message}),
                };
            }
        }
        if state.failures.len() == MAX_EVENTS {
            state.failures.pop_front();
        }
        state.failures.push_back(event);
    }
    pub(super) fn report(&self) -> Value {
        let s = self.state.borrow();
        let mut report = json!({"prove_calls":s.prove_calls,"prove_succeeded":s.prove_succeeded,"prove_seconds":s.prove_seconds,
            "verify_calls":s.verify_calls,"verify_succeeded":s.verify_succeeded,"verify_seconds":s.verify_seconds,
            "native_cpu_calls":s.native_calls,"native_cpu_succeeded":s.native_succeeded,"native_cpu_seconds":s.native_seconds,
            "native_cpu_contract":"closure uses explicit profile::make_cpu_config; no GPU claim",
            "native_gpu_calls":s.native_gpu.calls,"native_gpu_succeeded":s.native_gpu.succeeded,
            "native_gpu_seconds":s.native_gpu.seconds,"native_gpu_complete_reports":s.native_gpu.reports,
            "native_gpu_receipt_scope":"sum of validated fresh single-AIR native reports; not whole-transaction coverage",
            "witness_preparation_calls":s.witness_preparation.calls,
            "witness_preparation_succeeded":s.witness_preparation.succeeded,
            "witness_preparation_seconds":s.witness_preparation.seconds,
            "witness_preparation_complete_reports":s.witness_preparation.reports,
            "witness_preparation_scope":"raw graph values and node roots; not a proof or full-transaction coverage",
            "witness_preparation_stage":{"stage":"witness_trace",
                "completed_calls":s.witness_preparation.witness.completed_calls,
                "device_calls":s.witness_preparation.witness.device_calls,
                "device_ns":s.witness_preparation.witness.device_ns},
            "native_gpu_stages":s.native_gpu.stages.iter().enumerate().map(|(index, totals)| json!({
                "stage":lattica_prover_p3::proving::Stage::ARITHMETIC[index],
                "completed_calls":totals.completed_calls,"device_calls":totals.device_calls,
                "device_ns":totals.device_ns})).collect::<Vec<_>>(),
            "failures":s.failures,"failure_events_limit":MAX_EVENTS,
            "failure_artifact_limit":1,"failure_artifact_bytes_limit":MAX_ARTIFACT_BYTES,
            "failure_artifact_attempted":s.artifact_attempted});
        report["native_spend_calls"] = json!(s.native_spend.calls);
        report["stark_work_attempted"] = json!(s.stark_work_attempted);
        report["native_spend_succeeded"] = json!(s.native_spend.succeeded);
        report["native_spend_seconds"] = json!(s.native_spend.seconds);
        report["native_spend_complete_reports"] = json!(s.native_spend.reports);
        report["native_spend_peak_managed_bytes"] = json!(s.native_spend.peak_managed_bytes);
        report["native_spend_scope"] =
            json!("native MatRiCT spend creation only; excludes STARK and aggregate proofs");
        report["native_spend_stage"] = json!({
            "stage":"witness_trace",
            "completed_calls":s.native_spend.witness.completed_calls,
            "device_calls":s.native_spend.witness.device_calls,
            "device_ns":s.native_spend.witness.device_ns,
        });
        report
    }
}

#[cfg(all(test, feature = "opencl"))]
mod native_spend_shutdown_tests {
    use super::*;
    use lattica_prover_p3::{
        block_v2::machine::ProgramBuilder,
        proving::Report,
    };

    fn validated_native_diagnostics() -> Diagnostics {
        let diagnostics = Diagnostics::new(1, Policy::GpuRequired, Value::Null);
        // Seed only the trusted aggregate produced after report/evidence
        // validation. These tests exercise shutdown selection, not a proof.
        {
            let mut state = diagnostics.state.borrow_mut();
            state.native_spend.calls = 1;
            state.native_spend.succeeded = 1;
            state.native_spend.reports = 1;
        }
        diagnostics
    }

    #[test]
    fn validated_native_only_success_allows_native_shutdown() {
        let diagnostics = validated_native_diagnostics();
        assert_eq!(diagnostics.native_spend_only_complete_reports(), 1);
        assert!(!diagnostics.state.borrow().stark_work_attempted);
    }

    #[test]
    fn attempted_native_work_without_a_validated_report_cannot_claim_completion() {
        let diagnostics = Diagnostics::new(1, Policy::GpuRequired, Value::Null);
        assert_eq!(diagnostics.native_spend_only_complete_reports(), 0);
        diagnostics.state.borrow_mut().native_spend.calls = 3;
        assert_eq!(diagnostics.native_spend_only_complete_reports(), 0);
        // Even an inconsistent success counter cannot replace the validated
        // receipt counter used by the shutdown decision.
        diagnostics.state.borrow_mut().native_spend.succeeded = 1;
        assert_eq!(diagnostics.native_spend_only_complete_reports(), 0);
    }

    #[test]
    fn failed_registration_attempt_disables_native_only_shutdown() {
        let context = ProvingContext::cpu(1 << 30).unwrap();
        context.diagnostics.state.borrow_mut().native_spend.reports = 1;
        let mut builder = ProgramBuilder::new(1).unwrap();
        let public = builder.public(0).unwrap();
        let input = builder.input();
        builder.assert_equal(public, input);
        let program = builder.finish(None).unwrap();
        let busy = context.registry.borrow_mut();
        let result = context.with_registered(program, |_| -> Result<(), String> {
            panic!("reentrant registration reached the callback")
        });
        assert!(result.is_err());
        assert_eq!(busy.registrations, 0);
        assert!(context.diagnostics.state.borrow().stark_work_attempted);
        assert_eq!(context.diagnostics.native_spend_only_complete_reports(), 0);
    }

    #[test]
    fn refused_stark_prove_attempt_disables_native_only_shutdown_before_counting() {
        let context = ProvingContext::cpu(1 << 30).unwrap();
        context.diagnostics.state.borrow_mut().native_spend.reports = 1;
        let result = context.with_native_gpu(|_| -> Result<((), Report), String> {
            panic!("CPU worker reached the native GPU proof callback")
        });
        assert!(result.is_err());
        assert_eq!(context.diagnostics.state.borrow().native_gpu.calls, 0);
        assert!(context.diagnostics.state.borrow().stark_work_attempted);
        assert_eq!(context.diagnostics.native_spend_only_complete_reports(), 0);
    }

    #[test]
    fn other_worker_work_also_retains_the_strict_shutdown_route() {
        let blockers: [fn(&mut State); 5] = [
            |state| state.prove_calls = 1,
            |state| state.verify_calls = 1,
            |state| state.native_gpu.calls = 1,
            |state| state.witness_preparation.calls = 1,
            |state| state.native_calls = 1,
        ];
        for block in blockers {
            let diagnostics = validated_native_diagnostics();
            block(&mut diagnostics.state.borrow_mut());
            assert_eq!(diagnostics.native_spend_only_complete_reports(), 0);
        }
        let diagnostics = validated_native_diagnostics();
        diagnostics.mark_stark_work_attempted();
        assert_eq!(diagnostics.native_spend_only_complete_reports(), 0);
    }

    #[test]
    fn explicit_cleanup_reports_no_completion_claim() {
        let context = ProvingContext::cpu(1 << 30).unwrap();
        let report = context.close_without_completion().unwrap();
        assert_eq!(report["completion_claimed"], false);
        assert_eq!(report["session_closed"], true);
        assert_eq!(report["operations"]["native_spend_complete_reports"], 0);
        assert!(report.get("session_finish").is_none());
    }
}

struct BoundedWriter<W> {
    inner: W,
    bytes: usize,
}
impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > MAX_ARTIFACT_BYTES.saturating_sub(self.bytes) {
            return Err(io::Error::other("diagnostic proof exceeds 64MiB"));
        }
        let written = self.inner.write(buffer)?;
        self.bytes += written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn preserve(
    path: &Path,
    metadata: &Value,
    public: &[Val],
    proof: &BatchProof<Config>,
) -> Result<usize, String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(error)?;
    let mut writer = BoundedWriter {
        inner: file,
        bytes: 0,
    };
    // Stream references; do not allocate a second proof as a JSON Value.
    let result = serde_json::to_writer(&mut writer, &(metadata, public, proof)).map_err(error);
    writer.flush().map_err(error)?;
    writer.inner.sync_all().map_err(error)?;
    result?;
    Ok(writer.bytes)
}
