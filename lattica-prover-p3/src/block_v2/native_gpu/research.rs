//! Strict native research proving over GPU-generated trace/public buffers.
//! Proof encoding and the independent CPU verifier remain p3-uni-stark 0.6.1.
use super::super::{
    gpu_hash::device::{DeviceMatrix, DeviceSession, Extension, MatrixSpec, RowOrder},
    gpu_quotient_prover::uni,
    machine::{
        symbolic,
        verifier::{periodic, CompileError},
    },
    profile,
};
use crate::proving::{Backend, Capabilities, Policy, Profile, Report, Request, Run, Stage};
use p3_air::{Air, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::StarkGenericConfig;

pub use super::super::machine::symbolic::Builder as NativeAirBuilder;
type Val = crate::config::Val;

/// Ordinary AIRs that evaluate generically over an AirBuilder satisfy this
/// bound automatically. Debug builds retain the reference constraint-audit
/// bound, but GPU-required admission rejects that CPU audit before proving.
#[cfg(not(debug_assertions))]
pub trait NativeAir: Air<NativeAirBuilder> {}
#[cfg(not(debug_assertions))]
impl<A: Air<NativeAirBuilder>> NativeAir for A {}
#[cfg(debug_assertions)]
pub trait NativeAir:
    Air<NativeAirBuilder> + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>
{
}
#[cfg(debug_assertions)]
impl<A> NativeAir for A where
    A: Air<NativeAirBuilder> + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>
{
}

/// Static public periodic metadata. Geometry methods must not allocate; fill
/// writes exactly one borrowed column and must not build an owned AIR table.
/// Every period must be a positive power of two no greater than trace height.
/// Private witness-dependent data must never be supplied through this trait.
pub trait PeriodicSource {
    fn column_count(&self) -> usize;
    fn column_len(&self, index: usize) -> Option<usize>;
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String>;
}

impl PeriodicSource for () {
    fn column_count(&self) -> usize {
        0
    }
    fn column_len(&self, _: usize) -> Option<usize> {
        None
    }
    fn fill_column(&self, _: usize, _: &mut [Val]) -> Result<(), String> {
        Err("empty native periodic source".into())
    }
}

struct PublicSource<'a, S: ?Sized>(&'a S);
impl<S: PeriodicSource + ?Sized> periodic::Source for PublicSource<'_, S> {
    fn count(&self) -> usize {
        self.0.column_count()
    }
    fn len(&self, index: usize) -> Option<usize> {
        self.0.column_len(index)
    }
    fn fill(&self, index: usize, output: &mut [Val]) -> Result<(), CompileError> {
        self.0
            .fill_column(index, output)
            .map_err(|_| CompileError::Shape("native periodic source rejected fill"))
    }
}

/// Only approved core kernels can create this handle. There is no public
/// constructor accepting a host matrix or an uploaded trace. Both matrices
/// belong to the fresh per-proof session and are consumed once by `prove`.
pub struct GeneratedTrace {
    pub(crate) trace: DeviceMatrix,
    pub(crate) public: DeviceMatrix,
}

/// Borrowed capability for one admitted native trace generation. Extension
/// modules expose typed kernel methods, never raw upload/readback methods.
pub struct TraceContext<'a> {
    pub(crate) session: &'a DeviceSession,
    pub(crate) run: &'a Run,
    pub(crate) host_allowance: usize,
    pub(crate) rows: usize,
    pub(crate) width: usize,
    pub(crate) public_count: usize,
}

pub struct ProvedNative {
    pub proof: p3_uni_stark::Proof<profile::Config>,
    pub public_values: Vec<Val>,
    pub report: Report,
}

fn capabilities() -> Capabilities {
    // Static source lowering/periodic evaluation is preprocessing. Native uni
    // AIRs have no lookup argument; do not invent a lookup stage or receipt.
    let mut result = Capabilities::cpu(Profile::BlockV2Cubic, true, false);
    for stage in Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::Lookup)
    {
        result.set(stage, Backend::OpenCl);
    }
    #[cfg(debug_assertions)]
    let result = result.with_constraint_audit();
    result
}

/// Keep both the public word readback and its field conversion live outside
/// the Prepared compiler/PCS budget. Caller-owned raw inputs and allocator/RSS
/// overhead remain part of the enclosing process admission.
fn public_reservation(count: usize, host_bytes: usize) -> Result<(usize, usize), String> {
    if host_bytes == 0 || host_bytes as u64 > 32u64 << 30 || count == 0 {
        return Err(
            "native GPU proof requires public values and a host allowance up to 32 GiB".into(),
        );
    }
    let bytes = count
        .checked_mul(core::mem::size_of::<Val>())
        .ok_or("native public storage overflow")?;
    let reserve = bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(2 * core::mem::size_of::<Vec<Val>>()))
        .ok_or("native public readback reservation overflow")?;
    let prepared = host_bytes
        .checked_sub(reserve)
        .filter(|&n| n > symbolic::HOST_BYTES as usize)
        .ok_or("native public storage leaves no compiler/prover allowance")?;
    Ok((bytes, prepared))
}

fn checked_public_words(words: Vec<u64>, expected: usize) -> Result<Vec<Val>, String> {
    if words.len() != expected || words.iter().any(|&word| word >= Val::ORDER_U64) {
        return Err("native GPU public output has invalid length or field encoding".into());
    }
    Ok(words.into_iter().map(Val::from_u64).collect())
}

/// Prove one existing native AIR using an initialized owned OpenCL session.
/// The generator runs only after strict policy and resource admission. It
/// receives fresh proof/session state; neither witnesses nor entropy are cached.
/// CPU independent verification is the caller's next step after this returns.
pub fn prove<A: NativeAir, S: PeriodicSource + ?Sized>(
    entry: &'static str,
    air: &A,
    periodic: &S,
    rows: usize,
    host_bytes: usize,
    request: Request,
    generate: impl FnOnce(&TraceContext<'_>) -> Result<GeneratedTrace, String>,
) -> Result<ProvedNative, String> {
    if request.policy != Policy::GpuRequired {
        return Err("native GPU proving requires an explicit GPU-required request".into());
    }
    let run = Run::new(entry, request, capabilities()).map_err(|e| e.to_string())?;
    if air.preprocessed_width() != 0 {
        return Err("native GPU uni proofs do not support preprocessed commitments".into());
    }
    let public_count = air.num_public_values();
    let (public_bytes, preparation_allowance) = public_reservation(public_count, host_bytes)?;
    let trace_spec = MatrixSpec::new(
        rows.checked_ilog2().ok_or("zero native trace height")?,
        air.width(),
        Extension::Base,
        RowOrder::Natural,
        1,
    )?;
    if trace_spec.rows() != rows {
        return Err("native trace height must be a power of two".into());
    }
    let public_spec = MatrixSpec::new(0, public_count, Extension::Base, RowOrder::Natural, 1)?;
    let prepared = uni::Prepared::new_with_source(
        air,
        &PublicSource(periodic),
        rows,
        Extension::Cubic,
        preparation_allowance,
    )?;
    let owner = DeviceSession::new()?;
    // Retain the engine's full exclusive managed-capacity lease through final
    // proof construction. Each kernel must additionally plan its own trace,
    // raw-input, metadata and scratch peak before allocating those buffers.
    let _capacity = owner.reserve_wallet_proof_capacity(prepared.minimum()?)?;
    let config = prepared.config::<profile::Challenge>()?;
    let session = config.pcs().quotient_session()?;
    let context = TraceContext {
        session: &session,
        run: &run,
        host_allowance: config.pcs().host_output_budget(),
        rows,
        width: air.width(),
        public_count,
    };
    let generated = generate(&context)?;
    if generated.trace.spec() != trace_spec || generated.public.spec() != public_spec {
        return Err("native GPU trace/public geometry differs from its AIR".into());
    }
    // Validate trace session provenance without downloading its private data.
    drop(session.alias_private(&generated.trace)?);
    let before = session.stats().downloaded_bytes;
    let words = session.read(&generated.public, public_bytes)?;
    let transferred = session
        .stats()
        .downloaded_bytes
        .checked_sub(before)
        .ok_or("native public transfer counter regressed")?;
    if transferred != public_bytes as u64 {
        return Err("native public handoff transferred unexpected bytes".into());
    }
    let public_values = checked_public_words(words, public_count)?;
    drop(generated.public);
    let proof = uni::prove(
        &config,
        air,
        generated.trace,
        &public_values,
        &run,
        prepared,
    )?;
    let report = run.finish(true).map_err(|e| e.to_string())?;
    Ok(ProvedNative {
        proof,
        public_values,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_output_reserves_conversion_and_rejects_noncanonical_fields() {
        let host = 1 << 30;
        let (readback, prepared) = public_reservation(4, host).unwrap();
        assert_eq!(readback, 32);
        assert_eq!(host - prepared, 64 + 2 * core::mem::size_of::<Vec<Val>>());
        assert!(public_reservation(0, host).is_err());
        assert!(public_reservation(usize::MAX, host).is_err());
        assert!(public_reservation(4, symbolic::HOST_BYTES as usize).is_err());
        assert!(checked_public_words(vec![0, Val::ORDER_U64], 2).is_err());
        assert!(checked_public_words(vec![0], 2).is_err());
        assert_eq!(
            checked_public_words(vec![0, 1], 2).unwrap(),
            vec![Val::ZERO, Val::ONE]
        );
    }
}
