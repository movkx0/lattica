//! Experimental *direct* constrained relation. It creates no MatRiCT proof and
//! calls no MatRiCT verifier. All NTT/product arithmetic is inlined; no deferred
//! child digest is accepted. Public AES preprocessing is recomputed from the
//! public seed/serials and embedded in the program (see README trust boundary).
//!
//! With `gpu-proving`, the research API supports fresh GPU proving, bounded
//! artifacts and independently reconstructed verification. Resource admission
//! must pass before dispatch. Full workflow qualification and cryptographic
//! review remain required before any adoption; production acceptance is unchanged.
use crate::{
    ring::{self, Statement, Witness, D, Q},
    ring_native as native, Context, Error,
};
use lattica_pq_ringct_research::rust_verify::{
    constraints::{ConstraintContext, ResidueValue},
    constraints_crypto::CryptoObligations,
};
use lattica_prover_p3::block_v2::machine::{
    pq_modular,
    program::{Program, ProgramBuilder, Val, Wire},
    MachineAir,
};
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;

const PROGRAM_BYTES: usize = 256 << 20;
const WITNESS_BYTES: usize = 128 << 20;
const MAX_WIRES: usize = 1 << 24;
const MAX_INPUTS: usize = MAX_WIRES - 4;
const MAX_ROWS: usize = 1 << 24;
const AUXILIARY_BYTES: usize = 16 << 20;
pub const REPRESENTATION: &str = "inline-public-montgomery-constants-v2";
pub mod artifact;
#[cfg(feature = "gpu-proving")]
pub(crate) mod identity_reuse;
#[cfg(feature = "gpu-proving")]
pub mod proving;
#[cfg(feature = "gpu-proving")]
pub mod verification;
#[cfg(feature = "ring-recursion-experiment")]
pub mod recursion;
#[cfg(feature = "ring-direct-aggregate-experiment")]
pub mod aggregation;

#[path = "ring_circuit_budget.rs"]
mod budget;
#[path = "ring_circuit_evaluation.rs"]
mod evaluation;
#[path = "ring_circuit_limits.rs"]
mod limits;
#[path = "ring_circuit_linear.rs"]
mod linear;
#[path = "ring_circuit_mont.rs"]
mod montgomery;
#[path = "ring_circuit_ntt.rs"]
mod ntt;
#[path = "ring_circuit_ranges.rs"]
mod ranges;
#[path = "ring_circuit_ternary.rs"]
mod ternary;
pub use evaluation::{EvaluationBackend, EvaluationFootprint, EvaluationPlan};
pub use limits::{
    CompilerCapacityProfile, CompilerLimits, CompilerMemoryProfile, CompilerWireProfile,
};

/// Independent research representation; selecting capacity never changes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum CompilerRepresentation {
    #[default]
    #[serde(rename = "inline-public-montgomery-constants-v2")]
    InlinePublicMontgomeryConstantsV2,
    #[serde(rename = "fused-public-linear-v1")]
    FusedPublicLinearV1,
    #[serde(rename = "fused-public-ntt-v1")]
    FusedPublicNttV1,
    #[serde(rename = "fused-ternary-ntt-v1")]
    FusedTernaryNttV1,
    #[serde(rename = "fused-ternary-ranges-v1")]
    FusedTernaryRangesV1,
}
impl CompilerRepresentation {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InlinePublicMontgomeryConstantsV2 => REPRESENTATION,
            Self::FusedPublicLinearV1 => "fused-public-linear-v1",
            Self::FusedPublicNttV1 => "fused-public-ntt-v1",
            Self::FusedTernaryNttV1 => "fused-ternary-ntt-v1",
            Self::FusedTernaryRangesV1 => "fused-ternary-ranges-v1",
        }
    }
}
impl core::str::FromStr for CompilerRepresentation {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            REPRESENTATION => Ok(Self::InlinePublicMontgomeryConstantsV2),
            "fused-public-linear-v1" => Ok(Self::FusedPublicLinearV1),
            "fused-public-ntt-v1" => Ok(Self::FusedPublicNttV1),
            "fused-ternary-ntt-v1" => Ok(Self::FusedTernaryNttV1),
            "fused-ternary-ranges-v1" => Ok(Self::FusedTernaryRangesV1),
            _ => Err("compiler representation must be inline-public-montgomery-constants-v2, fused-public-linear-v1, fused-public-ntt-v1, fused-ternary-ntt-v1, or fused-ternary-ranges-v1"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub representation: &'static str,
    #[serde(flatten)]
    pub limits: CompilerLimits,
    pub host_allowance_bytes: u64,
    pub active_rows: usize,
    pub padded_rows: usize,
    pub wires: usize,
    pub witness_values: usize,
    /// Snapshot before final packing; retained for report compatibility.
    pub compiler_requested_bytes_peak: usize,
    /// Full admitted builder peak, including final packing and scoped scratch.
    pub compiler_packed_admitted_bytes_peak: usize,
    pub deferred_crypto_obligations: usize,
    pub cryptographic_proof_available: bool,
}

/// Public compiler counts only. Requested heap accounting is distinct from
/// observed cgroup/RSS memory, and neither is a proof-performance measurement.
#[derive(Debug, Serialize)]
pub struct CompilationFailure {
    pub representation: &'static str,
    pub phase: &'static str,
    pub logical_limit: &'static str,
    #[serde(flatten)]
    pub limits: CompilerLimits,
    pub host_allowance_bytes: u64,
    pub requested_program_bytes_peak: Option<usize>,
    pub wires: Option<usize>,
    pub input_values: Option<usize>,
    pub witness_hint_values: Option<usize>,
    pub cryptographic_proof_started: bool,
    #[serde(skip)]
    pub error: Error,
}

impl CompilationFailure {
    fn admission(limits: CompilerLimits, host_allowance_bytes: u64, error: Error) -> Self {
        Self {
            representation: REPRESENTATION,
            phase: "admission_or_finalization",
            logical_limit: "not_observed_at_primitive_boundary",
            limits,
            host_allowance_bytes,
            requested_program_bytes_peak: None,
            wires: None,
            input_values: None,
            witness_hint_values: None,
            cryptographic_proof_started: false,
            error,
        }
    }

    fn primitive(admitted: &limits::AdmittedLimits, failure: budget::Exhausted) -> Self {
        Self {
            phase: failure.phase,
            logical_limit: failure.logical_limit,
            requested_program_bytes_peak: Some(failure.counters.requested_bytes_peak),
            wires: Some(failure.counters.wires),
            input_values: Some(failure.counters.witnesses),
            witness_hint_values: Some(failure.witness_hint_values),
            ..Self::admission(
                admitted.limits,
                admitted.host_allowance_bytes,
                Error::ResourceLimit,
            )
        }
    }
}

/// Only for constants derived from the expected public statement or frozen
/// arithmetic profile. Private values must keep using residue/signed inputs.
/// The existing canonical-from-bits gadget checks Booleanity, reconstruction and
/// strict comparison; known 0/1 bits let the builder fold these checks exactly.
fn public_constant(
    c: &mut ConstraintContext<'_, '_>,
    value: u64,
    modulus: u64,
) -> Result<ResidueValue, Error> {
    public_constant_in_phase(c, value, modulus, "direct_relation_inputs")
}

fn public_constant_in_phase(
    c: &mut ConstraintContext<'_, '_>,
    value: u64,
    modulus: u64,
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    if !matches!(modulus, Q | ring::QHAT) || value >= modulus {
        return Err(Error::NonCanonical);
    }
    budget::guard_phase(c, phase);
    let bits =
        std::array::from_fn::<_, 32, _>(|i| c.builder.constant(Val::from_u64((value >> i) & 1)));
    let modulus = pq_modular::Modulus::new(modulus as u32).map_err(|_| Error::NonCanonical)?;
    let constrained = pq_modular::canonical_from_bits(c.builder, &bits, modulus)
        .map_err(|_| Error::NonCanonical)?;
    let expected = c.builder.constant(Val::from_u64(value));
    c.builder.assert_equal(constrained.wire(), expected);
    budget::guard_phase(c, phase);
    Ok(ResidueValue { value, constrained })
}

pub struct CompiledRelation {
    program: Program,
    witness: Vec<Val>,
    public: [Val; 4],
    summary: Summary,
}
impl CompiledRelation {
    /// Inspect source-derived GPU memory bounds without opening a device.
    /// Incomplete phase bounds are diagnostics and never authorize dispatch.
    #[cfg(feature = "gpu-proving")]
    pub fn into_gpu_memory_diagnostic(
        self,
    ) -> Result<lattica_prover_p3::block_v2::machine::RegisteredGpuFootprint, String> {
        use lattica_prover_p3::block_v2::machine::{RegisteredGpuLimits, RegisteredGpuMemoryPlan};
        let program = std::sync::Arc::new(self.program);
        let limits = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, 1 << 20)?;
        let plan = RegisteredGpuMemoryPlan::new(&program, &self.public, &self.witness, limits)?;
        Ok(plan.footprint())
    }

    pub fn summary(&self) -> &Summary {
        &self.summary
    }
    /// Executes constraints as a host diagnostic. This is not proof verification.
    pub fn evaluate(self) -> Result<Summary, Error> {
        let Self {
            program,
            witness,
            public,
            summary,
        } = self;
        MachineAir::new(program)
            .trace(&public, &witness)
            .map_err(|e| Error::Backend(format!("{e:?}")))?;
        Ok(summary)
    }
}

fn checkpoint(c: &ConstraintContext<'_, '_>) -> Result<(), Error> {
    if c.builder.construction_counters().resource_failed
        || c.witness.capacity() * std::mem::size_of::<Val>() > WITNESS_BYTES
    {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

fn bits(
    c: &mut ConstraintContext<'_, '_>,
    value: u64,
) -> Result<(Wire, [ResidueValue; 64]), Error> {
    budget::guard(c);
    let value_wire = c.input(value);
    let bit_wires =
        pq_modular::bounded_bits(c.builder, value_wire, 52).map_err(|_| Error::Range)?;
    let mut result = [public_constant(c, 0, Q).expect("zero is canonical"); 64];
    for i in 0..52 {
        budget::guard(c);
        let bit = c.residue((value >> i) & 1, Q);
        c.builder.assert_equal(bit.constrained.wire(), bit_wires[i]);
        result[i] = bit;
    }
    Ok((value_wire, result))
}

fn selected(
    c: &mut ConstraintContext<'_, '_>,
    s: &Statement,
    selectors: &[Wire; 10],
    which: usize,
    key: bool,
    poly: usize,
    witness_index: usize,
) -> [ResidueValue; D] {
    let values = if key {
        s.ring[witness_index][which].public_key[poly]
    } else {
        s.ring[witness_index][which].coin[poly]
    };
    std::array::from_fn(|coefficient| {
        budget::guard(c);
        let value = c.residue(values[coefficient], Q);
        let mut sum = c.builder.constant(Val::ZERO);
        for i in 0..10 {
            let public = if key {
                s.ring[i][which].public_key[poly][coefficient]
            } else {
                s.ring[i][which].coin[poly][coefficient]
            };
            let constant = c.builder.constant(Val::from_u64(public));
            let term = c.builder.mul(selectors[i], constant);
            sum = c.builder.add(sum, term);
        }
        c.builder.assert_equal(value.constrained.wire(), sum);
        value
    })
}

/// Reuse the exact 52-bit amount decomposition. Each one-bit constructor still
/// establishes a sealed canonical Q residue, without another private bit hint.
fn bits_ranges(
    c: &mut ConstraintContext<'_, '_>,
    value: u64,
) -> Result<(Wire, [ResidueValue; 64]), Error> {
    budget::guard(c);
    let value_wire = c.input(value);
    let bit_wires =
        pq_modular::bounded_bits(c.builder, value_wire, 52).map_err(|_| Error::Range)?;
    let mut result = [public_constant(c, 0, Q).expect("zero is canonical"); 64];
    for i in 0..52 {
        let constrained =
            ranges::canonical_from_bits_q(c, &bit_wires[i..i + 1], "direct_relation_inputs")?;
        result[i] = ResidueValue {
            value: (value >> i) & 1,
            constrained,
        };
    }
    Ok((value_wire, result))
}

/// Only the private hint depends on witness_index. The ten-way public
/// selection and equality retain the original order and account relation.
fn selected_ranges(
    c: &mut ConstraintContext<'_, '_>,
    s: &Statement,
    selectors: &[Wire; 10],
    which: usize,
    key: bool,
    poly: usize,
    witness_index: usize,
) -> Result<[ResidueValue; D], Error> {
    let values = if key {
        s.ring[witness_index][which].public_key[poly]
    } else {
        s.ring[witness_index][which].coin[poly]
    };
    let mut result = [public_constant(c, 0, Q).expect("zero is canonical"); D];
    for coefficient in 0..D {
        let value = ranges::input_q(c, values[coefficient], "direct_relation_inputs")?;
        let mut sum = c.builder.constant(Val::ZERO);
        for i in 0..10 {
            let public = if key {
                s.ring[i][which].public_key[poly][coefficient]
            } else {
                s.ring[i][which].coin[poly][coefficient]
            };
            let constant = c.builder.constant(Val::from_u64(public));
            let term = c.builder.mul(selectors[i], constant);
            sum = c.builder.add(sum, term);
        }
        c.builder.assert_equal(value.constrained.wire(), sum);
        result[coefficient] = value;
    }
    Ok(result)
}

fn equal(c: &mut ConstraintContext<'_, '_>, left: &[ResidueValue; D], right: &[ResidueValue; D]) {
    for i in 0..D {
        c.builder
            .assert_equal(left[i].constrained.wire(), right[i].constrained.wire());
    }
}

/// Historical default: 400 MiB logical compilation reservation (256 MiB
/// program, 128 MiB witness and 16 MiB auxiliary). This is not an RSS bound.
pub fn compile(
    s: &Statement,
    w: &Witness,
    expected: Context,
    host_allowance: usize,
) -> Result<CompiledRelation, Error> {
    compile_with_diagnostics(s, w, expected, host_allowance).map_err(|failure| failure.error)
}

pub fn compile_with_diagnostics(
    s: &Statement,
    w: &Witness,
    expected: Context,
    host_allowance: usize,
) -> Result<CompiledRelation, CompilationFailure> {
    compile_with_profile_diagnostics(
        s,
        w,
        expected,
        CompilerMemoryProfile::default(),
        host_allowance,
    )
}

/// Explicit memory experiment only. Pre-admit the complete compiler footprint
/// before any compiler allocation, then run once under the selected limit.
/// Wire/row/input bounds and cryptographic semantics are unchanged.
pub fn compile_with_profile_diagnostics(
    s: &Statement,
    w: &Witness,
    expected: Context,
    profile: CompilerMemoryProfile,
    host_allowance: usize,
) -> Result<CompiledRelation, CompilationFailure> {
    compile_with_capacity_diagnostics(s, w, expected, profile.into(), host_allowance)
}

/// Separately select the supported 64m wire experiment. Memory-only and legacy
/// APIs keep the original 16m wire ceiling; witness, input and row bounds remain
/// fixed. There is no implicit escalation after a refusal.
pub fn compile_with_capacity_diagnostics(
    s: &Statement,
    w: &Witness,
    expected: Context,
    profile: CompilerCapacityProfile,
    host_allowance: usize,
) -> Result<CompiledRelation, CompilationFailure> {
    compile_with_representation_diagnostics(
        s,
        w,
        expected,
        profile,
        CompilerRepresentation::default(),
        host_allowance,
    )
}

/// Explicit research-only arithmetic representation. Admission, native public
/// parameters, statement binding and every resource/security bound are shared
/// with the baseline. This API authorizes compilation only, never a proof.
pub fn compile_with_representation_diagnostics(
    s: &Statement,
    w: &Witness,
    expected: Context,
    profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
    host_allowance: usize,
) -> Result<CompiledRelation, CompilationFailure> {
    compile_once(profile, host_allowance, |admitted| {
        compile_inner(s, w, expected, admitted, representation)
    })
    .map_err(|mut failure| {
        failure.representation = representation.name();
        failure
    })
}

fn compile_once<T>(
    profile: CompilerCapacityProfile,
    host_allowance: usize,
    compile: impl FnOnce(&limits::AdmittedLimits) -> Result<T, Error>,
) -> Result<T, CompilationFailure> {
    let admitted = profile
        .admit(host_allowance)
        .map_err(|error| CompilationFailure {
            phase: "whole_compiler_admission",
            logical_limit: "compiler_host_allowance",
            ..CompilationFailure::admission(profile.limits(), host_allowance as u64, error)
        })?;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| compile(&admitted))) {
        Ok(result) => result.map_err(|error| {
            CompilationFailure::admission(admitted.limits, admitted.host_allowance_bytes, error)
        }),
        Err(error) if error.is::<budget::Exhausted>() => {
            let failure = error
                .downcast::<budget::Exhausted>()
                .expect("checked marker type");
            Err(CompilationFailure::primitive(&admitted, *failure))
        }
        Err(error) => std::panic::resume_unwind(error),
    }
}

fn compile_inner(
    s: &Statement,
    w: &Witness,
    expected: Context,
    admitted: &limits::AdmittedLimits,
    representation: CompilerRepresentation,
) -> Result<CompiledRelation, Error> {
    s.admit(expected)?;
    ring::admit_witness(w)?;
    let params = native::parameters(&s.setup_seed)?;
    let serials = [
        native::serial_image(&s.serials[0])?,
        native::serial_image(&s.serials[1])?,
    ];
    // Derived once from public basis vectors, inside the already admitted
    // auxiliary allowance. Neither legacy representation constructs this table.
    let transform = matches!(
        representation,
        CompilerRepresentation::FusedPublicNttV1
            | CompilerRepresentation::FusedTernaryNttV1
            | CompilerRepresentation::FusedTernaryRangesV1
    )
    .then(ntt::PublicTransform::derive);
    let mut builder = ProgramBuilder::new_with_construction_limits(4, admitted.construction)
        .map_err(|_| Error::ResourceLimit)?;
    // Reserve before arithmetic: Context::input otherwise owns a growing Vec.
    // The allocation is counted in the fixed allowance above.
    let mut witness = Vec::new();
    witness
        .try_reserve_exact(MAX_INPUTS)
        .map_err(|_| Error::ResourceLimit)?;
    if witness.capacity() * std::mem::size_of::<Val>() > WITNESS_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut crypto = CryptoObligations::new(s.setup_seed);
    let public = s.binding();
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        for (i, &v) in public.iter().enumerate() {
            let wire = c.builder.public(i).map_err(|_| Error::ResourceLimit)?;
            let constant = c.builder.constant(v);
            c.builder.assert_equal(wire, constant);
        }
        // Keep both earlier representations' exact materialization schedule.
        // The NTT candidate embeds public coefficients in linear equations and
        // does not need unused canonical-residue arrays for public matrices.
        let mat1: Vec<_> = if transform.is_some() {
            Vec::new()
        } else {
            params
                .mat1
                .iter()
                .map(|row| {
                    row.map(|p| {
                        p.map(|v| {
                            public_constant(&mut c, v, Q)
                                .expect("admitted public coefficient is canonical")
                        })
                    })
                })
                .collect()
        };
        let mat2: Vec<_> = if transform.is_some() {
            Vec::new()
        } else {
            params
                .mat2
                .iter()
                .map(|row| {
                    row.map(|p| {
                        p.map(|v| {
                            public_constant(&mut c, v, Q)
                                .expect("admitted public coefficient is canonical")
                        })
                    })
                })
                .collect()
        };
        let selectors: [Wire; 10] = std::array::from_fn(|i| {
            budget::guard(&c);
            let bit = c.input(u64::from(w.selected_pair == i));
            c.builder.assert_bool(bit);
            bit
        });
        let mut sum = c.builder.constant(Val::ZERO);
        for bit in selectors {
            sum = c.builder.add(sum, bit);
        }
        let one = c.builder.constant(Val::ONE);
        c.builder.assert_equal(sum, one);
        let mut ins = c.builder.constant(Val::ZERO);
        let mut outs = c.builder.constant(Val::ZERO);
        for i in 0..2 {
            let spending = w.spending[i].map(|p| {
                p.map(|v| {
                    budget::guard(&c);
                    c.signed(v, 1)
                })
            });
            let g = serials[i].map(|p| {
                p.map(|v| {
                    public_constant(&mut c, v, Q).expect("admitted public coefficient is canonical")
                })
            });
            let pk = match representation {
                CompilerRepresentation::InlinePublicMontgomeryConstantsV2 => native::public_key(
                    &mut budget::Limited(&mut c, "input_ownership"),
                    &spending,
                    &mat1,
                    &g,
                ),
                CompilerRepresentation::FusedPublicLinearV1 => {
                    linear::public_key(&mut c, &spending, &params.mat1, &g, "input_ownership")?
                }
                CompilerRepresentation::FusedPublicNttV1
                | CompilerRepresentation::FusedTernaryNttV1 => {
                    let transform = transform.as_ref().expect("selected public transform");
                    let r = if representation == CompilerRepresentation::FusedTernaryNttV1 {
                        ternary::ntt_many(&mut c, &spending, transform, "input_ownership")?
                    } else {
                        transform.ntt_many(&mut c, &spending, "input_ownership")?
                    };
                    linear::public_key_from_ntt(&mut c, &r, &params.mat1, &g, "input_ownership")?
                }
                CompilerRepresentation::FusedTernaryRangesV1 => {
                    let transform = transform.as_ref().expect("selected public transform");
                    let r =
                        ternary::ntt_many_ranges(&mut c, &spending, transform, "input_ownership")?;
                    linear::public_key_from_ntt_ranges(
                        &mut c,
                        &r,
                        &params.mat1,
                        &g,
                        "input_ownership",
                    )?
                }
            };
            checkpoint(&c)?;
            for (p, computed) in pk.iter().enumerate() {
                let selected = if representation == CompilerRepresentation::FusedTernaryRangesV1 {
                    selected_ranges(&mut c, s, &selectors, i, true, p, w.selected_pair)?
                } else {
                    selected(&mut c, s, &selectors, i, true, p, w.selected_pair)
                };
                equal(&mut c, computed, &selected);
            }
            let opening = w.input_openings[i].map(|p| {
                p.map(|v| {
                    budget::guard(&c);
                    c.signed(v, 1)
                })
            });
            let (value, bits) = if representation == CompilerRepresentation::FusedTernaryRangesV1 {
                bits_ranges(&mut c, w.input_values[i])?
            } else {
                bits(&mut c, w.input_values[i])?
            };
            ins = c.builder.add(ins, value);
            let cn = match representation {
                CompilerRepresentation::InlinePublicMontgomeryConstantsV2 => native::commitment(
                    &mut budget::Limited(&mut c, "input_opening"),
                    &opening,
                    &bits,
                    &mat1,
                    &mat2,
                ),
                CompilerRepresentation::FusedPublicLinearV1 => linear::commitment(
                    &mut c,
                    &opening,
                    &bits,
                    &params.mat1,
                    &params.mat2,
                    "input_opening",
                )?,
                CompilerRepresentation::FusedPublicNttV1
                | CompilerRepresentation::FusedTernaryNttV1 => {
                    let transform = transform.as_ref().expect("selected public transform");
                    let r = if representation == CompilerRepresentation::FusedTernaryNttV1 {
                        ternary::ntt_many(&mut c, &opening, transform, "input_opening")?
                    } else {
                        transform.ntt_many(&mut c, &opening, "input_opening")?
                    };
                    linear::commitment_from_ntt(
                        &mut c,
                        &r,
                        &bits,
                        &params.mat1,
                        &params.mat2,
                        "input_opening",
                    )?
                }
                CompilerRepresentation::FusedTernaryRangesV1 => {
                    let transform = transform.as_ref().expect("selected public transform");
                    let r = ternary::ntt_many_ranges(&mut c, &opening, transform, "input_opening")?;
                    linear::commitment_from_ntt_ranges(
                        &mut c,
                        &r,
                        &bits,
                        &params.mat1,
                        &params.mat2,
                        "input_opening",
                    )?
                }
            };
            checkpoint(&c)?;
            for (p, computed) in cn.iter().enumerate() {
                let selected = if representation == CompilerRepresentation::FusedTernaryRangesV1 {
                    selected_ranges(&mut c, s, &selectors, i, false, p, w.selected_pair)?
                } else {
                    selected(&mut c, s, &selectors, i, false, p, w.selected_pair)
                };
                equal(&mut c, computed, &selected);
            }
        }
        for i in 0..2 {
            let opening = w.output_openings[i].map(|p| {
                p.map(|v| {
                    budget::guard(&c);
                    c.signed(v, 1)
                })
            });
            let (value, bits) = if representation == CompilerRepresentation::FusedTernaryRangesV1 {
                bits_ranges(&mut c, w.output_values[i])?
            } else {
                bits(&mut c, w.output_values[i])?
            };
            outs = c.builder.add(outs, value);
            let cn = match representation {
                CompilerRepresentation::InlinePublicMontgomeryConstantsV2 => native::commitment(
                    &mut budget::Limited(&mut c, "output_opening"),
                    &opening,
                    &bits,
                    &mat1,
                    &mat2,
                ),
                CompilerRepresentation::FusedPublicLinearV1 => linear::commitment(
                    &mut c,
                    &opening,
                    &bits,
                    &params.mat1,
                    &params.mat2,
                    "output_opening",
                )?,
                CompilerRepresentation::FusedPublicNttV1
                | CompilerRepresentation::FusedTernaryNttV1 => {
                    let transform = transform.as_ref().expect("selected public transform");
                    let r = if representation == CompilerRepresentation::FusedTernaryNttV1 {
                        ternary::ntt_many(&mut c, &opening, transform, "output_opening")?
                    } else {
                        transform.ntt_many(&mut c, &opening, "output_opening")?
                    };
                    linear::commitment_from_ntt(
                        &mut c,
                        &r,
                        &bits,
                        &params.mat1,
                        &params.mat2,
                        "output_opening",
                    )?
                }
                CompilerRepresentation::FusedTernaryRangesV1 => {
                    let transform = transform.as_ref().expect("selected public transform");
                    let r =
                        ternary::ntt_many_ranges(&mut c, &opening, transform, "output_opening")?;
                    linear::commitment_from_ntt_ranges(
                        &mut c,
                        &r,
                        &bits,
                        &params.mat1,
                        &params.mat2,
                        "output_opening",
                    )?
                }
            };
            checkpoint(&c)?;
            for (p, computed) in cn.iter().enumerate() {
                let expected = s.output_coins[i][p].map(|v| {
                    public_constant(&mut c, v, Q).expect("admitted public coefficient is canonical")
                });
                equal(&mut c, computed, &expected);
            }
        }
        c.builder.assert_equal(ins, outs);
        checkpoint(&c)?;
    }
    if !crypto.aes.is_empty()
        || !crypto.shake.is_empty()
        || !crypto.ntt.is_empty()
        || !crypto.mul.is_empty()
    {
        return Err(Error::IncompleteProofCoverage);
    }
    let counters = builder.construction_counters();
    let program = builder.finish(None).unwrap_or_else(|error| {
        use lattica_prover_p3::block_v2::machine::program::ExecutionError;
        let logical_limit = match error {
            ExecutionError::InvalidHeight => "program_row_limit",
            ExecutionError::TooLarge => "program_heap_request_allowance",
            _ => "program_finalization_error",
        };
        // The builder is consumed by finish; these are the preceding counters,
        // not a final packing peak or a completed-program measurement.
        budget::refuse("finalization", logical_limit, counters, witness.len())
    });
    if program.height() > MAX_ROWS {
        budget::refuse("finalization", "program_row_limit", counters, witness.len());
    }
    let summary = Summary {
        representation: representation.name(),
        limits: admitted.limits,
        host_allowance_bytes: admitted.host_allowance_bytes,
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        wires: program.wire_count(),
        witness_values: witness.len(),
        compiler_requested_bytes_peak: counters.requested_bytes_peak,
        compiler_packed_admitted_bytes_peak: program.construction_host_bytes(),
        deferred_crypto_obligations: 0,
        cryptographic_proof_available: false,
    };
    Ok(CompiledRelation {
        program,
        witness,
        public,
        summary,
    })
}

#[cfg(test)]
mod public_constant_tests {
    use super::*;

    #[test]
    fn public_constant_reconstructs_boundaries_without_private_hints() {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            for modulus in [Q, ring::QHAT] {
                for value in [0, 1, modulus / 2, modulus - 1] {
                    let residue = public_constant(&mut c, value, modulus).unwrap();
                    assert_eq!(residue.value, value);
                    assert_eq!(u64::from(residue.constrained.modulus().value()), modulus);
                    assert_eq!(
                        c.builder.known_constant(residue.constrained.wire()),
                        Some(Val::from_u64(value))
                    );
                }
            }
            assert!(c.witness.is_empty());
            assert_eq!(c.builder.construction_counters().witnesses, 0);
        }
        // Execute the actual constant reconstruction/equality program, without
        // either private hints or a native acceptance flag.
        MachineAir::new(builder.finish(None).unwrap())
            .trace(&[], &[])
            .unwrap();
    }

    #[test]
    fn invalid_public_constant_rejected_before_program_or_witness_growth() {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let before = c.builder.construction_counters();
        for (value, modulus) in [
            (Q, Q),
            (Q + 1, Q),
            (u64::MAX, Q),
            (ring::QHAT, ring::QHAT),
            (0, 1),
            (0, Q + 1),
        ] {
            assert!(matches!(
                public_constant(&mut c, value, modulus),
                Err(Error::NonCanonical)
            ));
        }
        assert_eq!(c.builder.construction_counters(), before);
        assert!(c.witness.is_empty());
    }
}
