#![cfg(feature = "native-spend-oracle")]
//! Explicit, serialized, post-freeze qualification. No timings or throughput.
//! Execute only in the externally admitted exclusive GPU process described in
//! /tmp/pq-matrict-private-fixture/QUALIFICATION.txt. Ignored by normal test runs.
use lattica_pq_ringct_research::{
    execution::ProvingContext,
    native::{
        self,
        private_spend_fixture::{generate_spend_fixture, oracle, NativeSpendFixture},
        FixtureAmounts,
    },
    opencl::Limits,
};
use lattica_prover_p3::{
    block_v2::native_gpu::private_spend::SpendLimits,
    proving::{Backend, CoverageScope, Policy, Profile},
};
use serde_json::Value;
use std::sync::atomic::{compiler_fence, Ordering};

const HOST_BYTES: u64 = 32 << 30;
const NATIVE_HOST_BYTES: usize = 24 << 30;
const CONTEXT: [u8; 32] = [0x4d; 32];
const SETUP_SEED: [u8; 32] = [0xa3; 32];
struct Key([u8; 32]);
impl Drop for Key {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
fn admitted() -> Result<(), &'static str> {
    if std::env::var("LATTICA_NATIVE_SPEND_QUALIFICATION").as_deref() != Ok("1") {
        return Err("explicit post-freeze private-spend qualification admission is missing");
    }
    if !native::available() {
        return Err("reference CPU ISA prerequisites are missing");
    }
    Ok(())
}
fn fixture(index: u64, amounts: FixtureAmounts) -> Result<NativeSpendFixture, &'static str> {
    generate_spend_fixture(CONTEXT, Some(SETUP_SEED), index, amounts)
        .map_err(|_| "fixture input generation failed")
}
fn standard_fixture() -> Result<NativeSpendFixture, &'static str> {
    fixture(
        4,
        FixtureAmounts {
            input: [29, 31],
            output: [23, 37],
        },
    )
}
fn worker() -> Result<ProvingContext, &'static str> {
    ProvingContext::opencl(Limits {
        host_bytes: HOST_BYTES,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    })
    .map_err(|_| "owned OpenCL session admission failed")
}
fn no_cpu_proofs(report: &Value) -> Result<(), &'static str> {
    for field in ["native_cpu_calls", "native_gpu_calls", "prove_calls"] {
        if report["operations"][field].as_u64() != Some(0) {
            return Err("native spend qualification unexpectedly performed other proving work");
        }
    }
    Ok(())
}
fn verify_and_reject_mutations(statement: &[u8], proof: &[u8]) -> Result<(), &'static str> {
    if !native::verify(&CONTEXT, statement, proof).map_err(|_| "public verifier failed")? {
        return Err("GPU output failed independent native verification");
    }
    let mut changed_statement = statement.to_vec();
    // The first ring coefficient is forced noncanonical: exactly Q.
    changed_statement[32..36].copy_from_slice(&167_770_241u32.to_le_bytes());
    if native::verify(&CONTEXT, &changed_statement, proof)
        .map_err(|_| "statement mutation verifier failed")?
    {
        return Err("noncanonical statement mutation was accepted");
    }
    let mut changed_proof = proof.to_vec();
    // The first proof coefficient is a 28-bit Q coefficient; all ones exceeds Q.
    changed_proof[..4].fill(0xff);
    if native::verify(&CONTEXT, statement, &changed_proof)
        .map_err(|_| "proof mutation verifier failed")?
    {
        return Err("noncanonical proof mutation was accepted");
    }
    let mut changed_context = CONTEXT;
    changed_context[0] ^= 1;
    if native::verify(&changed_context, statement, proof)
        .map_err(|_| "context mutation verifier failed")?
    {
        return Err("context mutation was accepted");
    }
    Ok(())
}

fn full_spend_parity() -> Result<(), &'static str> {
    admitted()?;
    let context = worker()?;
    let edge = (1u64 << 52) - 1;
    let cases = [
        (
            0,
            FixtureAmounts {
                input: [0, 0],
                output: [0, 0],
            },
        ),
        (
            4,
            FixtureAmounts {
                input: [29, 31],
                output: [23, 37],
            },
        ),
        (
            9,
            FixtureAmounts {
                input: [edge, 1],
                output: [edge - 1, 2],
            },
        ),
    ];
    for (case, (index, amounts)) in cases.into_iter().enumerate() {
        let key = Key([0x31 + case as u8; 32]);
        let input = fixture(index, amounts)?;
        let reference = oracle::spend(&input, &key.0, 1024)
            .map_err(|_| "deterministic native reference spend failed")?;
        let request = input
            .into_gpu_request()
            .map_err(|_| "GPU witness conversion failed")?;
        let (output, report, evidence) = context
            .create_matrict_spend_on_gpu_for_oracle(
                request,
                SpendLimits::bounded(NATIVE_HOST_BYTES),
                key.0,
            )
            .map_err(|_| "deterministic GPU spend failed")?;
        // Boolean comparisons ensure panic output never prints private material.
        if output.statement != reference.statement || output.proof != reference.proof {
            return Err("GPU native statement/proof bytes differ from the deterministic reference");
        }
        if !reference.output_keys_equal(output.output_keys.polynomials()) {
            return Err("GPU output commitment keys differ from the deterministic reference");
        }
        if report.entry_point != "native_matrict_spend"
            || report.policy != Policy::GpuRequired
            || !report.succeeded
            || !report.stage_coverage_complete
            || report.completion_rejected
            || report.observation_errors != 0
            || !report.components.is_empty()
            || report.capabilities.profile() != Profile::MatrictN10
            || report.capabilities.scope() != CoverageScope::Operation
            || report.observations.len() != 1
            || report.observations.iter().any(|o| {
                o.backend != Backend::OpenCl
                    || o.calls == 0
                    || o.calls != o.completed_calls
                    || o.device_calls != o.completed_calls
            })
            || evidence.prelude_steps != 0x3f
            || evidence.accepted_attempt_steps != 0x03ff_ffc0
        {
            return Err("GPU native spend has incomplete strict execution evidence");
        }
        verify_and_reject_mutations(&output.statement, &output.proof)?;
        // Phase digests and RNG counters remain private in-memory diagnostics.
        // Full output parity is required here; GPU sampler/phase-specific parity
        // needs separate feature-gated kernel probe APIs and is not claimed.
    }
    let report = context
        .finish()
        .map_err(|_| "native spend session shutdown failed")?;
    no_cpu_proofs(&report)?;
    if report["session_finish"]["completion_claimed"] != true
        || report["session_finish"]["completion_scope"] != "native_matrict_spend"
        || report["session_finish"]["validated_native_spend_reports"].as_u64() != Some(3)
        || report["session_finish"]["stark_completion_claimed"] != false
        || report["session_finish"]["queue_drained"] != true
        || report["session_finish"]["context_closed"] != true
    {
        return Err("native-only completion scope or teardown evidence is invalid");
    }
    if report["session_closed"] != true
        || report["operations"]["native_spend_succeeded"].as_u64() != Some(3)
        || report["operations"]["native_spend_complete_reports"].as_u64() != Some(3)
    {
        return Err("native spend terminal session evidence is incomplete");
    }
    Ok(())
}

#[test]
#[ignore = "requires serialized post-freeze resource admission and a qualified FP64 OpenCL device"]
fn native_spend_gpu_matches_reference_and_rejects_public_mutations() {
    if let Err(message) = full_spend_parity() {
        panic!("{message}");
    }
}

fn refusal_checks() -> Result<(), &'static str> {
    admitted()?;
    let cpu = ProvingContext::cpu(HOST_BYTES).map_err(|_| "CPU refusal context failed")?;
    let request = standard_fixture()?
        .into_gpu_request()
        .map_err(|_| "refusal fixture conversion failed")?;
    let key = Key([0x61; 32]);
    if cpu
        .create_matrict_spend_on_gpu_for_oracle(
            request,
            SpendLimits::bounded(NATIVE_HOST_BYTES),
            key.0,
        )
        .is_ok()
    {
        return Err("CPU policy accepted GPU-only spend");
    }
    let report = cpu.finish().map_err(|_| "CPU refusal shutdown failed")?;
    no_cpu_proofs(&report)?;
    if report["operations"]["native_spend_calls"].as_u64() != Some(0) {
        return Err("CPU policy refusal dispatched native spend work");
    }
    // A fresh context for each refusal also checks cleanup permits a new owner.
    for kind in 0..4 {
        let context = worker()?;
        let request = standard_fixture()?
            .into_gpu_request()
            .map_err(|_| "budget fixture conversion failed")?;
        let mut limits = SpendLimits::bounded(NATIVE_HOST_BYTES);
        match kind {
            0 => limits.host_bytes = 1,
            1 => limits.max_attempts = 0,
            2 => limits.random_call_limit = 1,
            _ => limits.proposal_limit = 1,
        }
        let key = Key([0x71 + kind; 32]);
        if context
            .create_matrict_spend_on_gpu_for_oracle(request, limits, key.0)
            .is_ok()
        {
            return Err("bounded native spend exhaustion unexpectedly succeeded");
        }
        let report = context
            .close_without_completion()
            .map_err(|_| "failed native spend did not shut down cleanly")?;
        no_cpu_proofs(&report)?;
        if report["session_cleanup"]["completion_claimed"] != false
            || report["session_cleanup"]["queue_drained"] != true
            || report["session_cleanup"]["context_closed"] != true
            || report["completion_claimed"] != false
        {
            return Err("failed native spend cleanup claimed completion or failed teardown");
        }
        if report["session_closed"] != true
            || report["operations"]["native_spend_succeeded"].as_u64() != Some(0)
            || report["operations"]["native_spend_complete_reports"].as_u64() != Some(0)
        {
            return Err("budget refusal was misreported as accepted proving work");
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires serialized post-freeze resource admission and a qualified FP64 OpenCL device"]
fn native_spend_cpu_policy_and_budgets_fail_without_fallback() {
    if let Err(message) = refusal_checks() {
        panic!("{message}");
    }
}
