//! Explicit diagnostic-only full trace readback. Off in production builds.
use super::{GeneratedTrace, TraceContext};
use crate::block_v2::gpu_hash::device::{DeviceSession, Extension, MatrixSpec, RowOrder};
use crate::config::Val;
use crate::proving::{
    Backend, Capabilities, CoverageScope, Policy, Profile, Report, Request, Run, Stage,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

/// Compare every generated field to an independent CPU oracle under an explicit
/// combined expected/readback host bound. Requires an externally bounded,
/// initialized OpenCL engine. This function neither proves nor uploads a trace.
#[allow(clippy::too_many_arguments)]
pub fn audit_generated_trace(
    entry: &'static str,
    rows: usize,
    width: usize,
    public_count: usize,
    host_bytes: usize,
    expected_trace: &[Val],
    expected_public: &[Val],
    generate: impl FnOnce(&TraceContext<'_>) -> Result<GeneratedTrace, String>,
) -> Result<Report, String> {
    let trace_words = rows
        .checked_mul(width)
        .ok_or("trace audit dimensions overflow")?;
    let total_words = trace_words
        .checked_add(public_count)
        .ok_or("trace audit word count overflow")?;
    let bytes = total_words
        .checked_mul(16)
        .and_then(|n| n.checked_add(64 << 10))
        .ok_or("trace audit host bound overflow")?;
    if !rows.is_power_of_two()
        || width == 0
        || public_count == 0
        || expected_trace.len() != trace_words
        || expected_public.len() != public_count
        || bytes > host_bytes
    {
        return Err("trace audit geometry or combined host allowance rejected".into());
    }
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, false, false).scoped(
        CoverageScope::Operation,
        &[Stage::WitnessTrace, Stage::PublicValues],
    );
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    capabilities.set(Stage::PublicValues, Backend::OpenCl);
    let run = Run::new(
        entry,
        Request {
            policy: Policy::GpuRequired,
            emit_report: true,
        },
        capabilities,
    )
    .map_err(|e| e.to_string())?;
    let session = DeviceSession::new()?;
    let context = TraceContext {
        session: &session,
        run: &run,
        host_allowance: host_bytes - bytes + (64 << 10),
        rows,
        width,
        public_count,
    };
    let generated = generate(&context)?;
    let trace_spec = MatrixSpec::new(rows.ilog2(), width, Extension::Base, RowOrder::Natural, 1)?;
    let public_spec = MatrixSpec::new(0, public_count, Extension::Base, RowOrder::Natural, 1)?;
    if generated.trace.spec() != trace_spec || generated.public.spec() != public_spec {
        return Err("trace audit generated shape differs from oracle".into());
    }
    drop(session.alias_private(&generated.trace)?);
    drop(session.alias_private(&generated.public)?);
    for (name, matrix, expected) in [
        ("trace", &generated.trace, expected_trace),
        ("public", &generated.public, expected_public),
    ] {
        let words = session.read(matrix, total_words * 8)?;
        for (index, (&word, value)) in words.iter().zip(expected).enumerate() {
            if word >= Val::ORDER_U64 || word != value.as_canonical_u64() {
                return Err(format!("native {name} parity mismatch at field {index}"));
            }
        }
    }
    run.finish(true).map_err(|e| e.to_string())
}
