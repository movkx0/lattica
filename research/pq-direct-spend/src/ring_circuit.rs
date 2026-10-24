//! Experimental *direct* constrained relation. It creates no MatRiCT proof and
//! calls no MatRiCT verifier. All NTT/product arithmetic is inlined; no deferred
//! child digest is accepted. Public AES preprocessing is recomputed from the
//! public seed/serials and embedded in the program (see README trust boundary).
//!
//! This module does not expose a cryptographic proof API. Program registration,
//! full proving, independently rebuilt verifier identity, artifacts, resource
//! qualification, and security review remain required.
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
    program::{ConstructionLimits, Program, ProgramBuilder, Val, Wire},
    MachineAir,
};
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;

const PROGRAM_BYTES: usize = 256 << 20;
const WITNESS_BYTES: usize = 128 << 20;
const MAX_WIRES: usize = 1 << 24;
const MAX_INPUTS: usize = MAX_WIRES - 4;
const AUXILIARY_BYTES: usize = 16 << 20;
pub const REPRESENTATION: &str = "inline-public-constant-bits-v1";

#[path = "ring_circuit_budget.rs"]
mod budget;

#[derive(Debug, Serialize)]
pub struct Summary {
    pub representation: &'static str,
    pub active_rows: usize,
    pub padded_rows: usize,
    pub wires: usize,
    pub witness_values: usize,
    pub compiler_requested_bytes_peak: usize,
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
    pub program_byte_limit: usize,
    pub witness_byte_limit: usize,
    pub wire_limit: usize,
    pub input_limit: usize,
    pub requested_program_bytes_peak: Option<usize>,
    pub wires: Option<usize>,
    pub input_values: Option<usize>,
    pub witness_hint_values: Option<usize>,
    pub cryptographic_proof_started: bool,
    #[serde(skip)]
    pub error: Error,
}

impl CompilationFailure {
    fn admission(error: Error) -> Self {
        Self {
            representation: REPRESENTATION,
            phase: "admission_or_finalization",
            logical_limit: "not_observed_at_primitive_boundary",
            program_byte_limit: PROGRAM_BYTES,
            witness_byte_limit: WITNESS_BYTES,
            wire_limit: MAX_WIRES,
            input_limit: MAX_INPUTS,
            requested_program_bytes_peak: None,
            wires: None,
            input_values: None,
            witness_hint_values: None,
            cryptographic_proof_started: false,
            error,
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
    if !matches!(modulus, Q | ring::QHAT) || value >= modulus {
        return Err(Error::NonCanonical);
    }
    budget::guard(c);
    let bits =
        std::array::from_fn::<_, 32, _>(|i| c.builder.constant(Val::from_u64((value >> i) & 1)));
    let modulus = pq_modular::Modulus::new(modulus as u32).map_err(|_| Error::NonCanonical)?;
    let constrained = pq_modular::canonical_from_bits(c.builder, &bits, modulus)
        .map_err(|_| Error::NonCanonical)?;
    let expected = c.builder.constant(Val::from_u64(value));
    c.builder.assert_equal(constrained.wire(), expected);
    budget::guard(c);
    Ok(ResidueValue { value, constrained })
}

pub struct CompiledRelation {
    program: Program,
    witness: Vec<Val>,
    public: [Val; 4],
    summary: Summary,
}
impl CompiledRelation {
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

fn equal(c: &mut ConstraintContext<'_, '_>, left: &[ResidueValue; D], right: &[ResidueValue; D]) {
    for i in 0..D {
        c.builder
            .assert_equal(left[i].constrained.wire(), right[i].constrained.wire());
    }
}

/// Fixed 400 MiB maximum logical compilation reservation (program, witness and
/// auxiliary), below the existing 32 GiB worker host allowance. It is not an RSS
/// peak measurement. There is no fallback, split, or smaller cryptographic profile.
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
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        compile_inner(s, w, expected, host_allowance)
    })) {
        Ok(result) => result.map_err(CompilationFailure::admission),
        Err(error) if error.is::<budget::Exhausted>() => {
            let failure = error
                .downcast::<budget::Exhausted>()
                .expect("checked marker type");
            Err(failure.0)
        }
        Err(error) => std::panic::resume_unwind(error),
    }
}

fn compile_inner(
    s: &Statement,
    w: &Witness,
    expected: Context,
    host_allowance: usize,
) -> Result<CompiledRelation, Error> {
    s.admit(expected)?;
    ring::admit_witness(w)?;
    if host_allowance < PROGRAM_BYTES + WITNESS_BYTES + AUXILIARY_BYTES {
        return Err(Error::ResourceLimit);
    }
    let params = native::parameters(&s.setup_seed)?;
    let serials = [
        native::serial_image(&s.serials[0])?,
        native::serial_image(&s.serials[1])?,
    ];
    let mut builder = ProgramBuilder::new_with_construction_limits(
        4,
        ConstructionLimits {
            max_requested_program_bytes: PROGRAM_BYTES,
            max_wires: MAX_WIRES,
            max_input_values: MAX_INPUTS,
        },
    )
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
        let mat1: Vec<_> = params
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
            .collect();
        let mat2: Vec<_> = params
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
            .collect();
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
            let pk = native::public_key(
                &mut budget::Limited(&mut c, "input_ownership"),
                &spending,
                &mat1,
                &g,
            );
            checkpoint(&c)?;
            for (p, computed) in pk.iter().enumerate() {
                let selected = selected(&mut c, s, &selectors, i, true, p, w.selected_pair);
                equal(&mut c, computed, &selected);
            }
            let opening = w.input_openings[i].map(|p| {
                p.map(|v| {
                    budget::guard(&c);
                    c.signed(v, 1)
                })
            });
            let (value, bits) = bits(&mut c, w.input_values[i])?;
            ins = c.builder.add(ins, value);
            let cn = native::commitment(
                &mut budget::Limited(&mut c, "input_opening"),
                &opening,
                &bits,
                &mat1,
                &mat2,
            );
            checkpoint(&c)?;
            for (p, computed) in cn.iter().enumerate() {
                let selected = selected(&mut c, s, &selectors, i, false, p, w.selected_pair);
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
            let (value, bits) = bits(&mut c, w.output_values[i])?;
            outs = c.builder.add(outs, value);
            let cn = native::commitment(
                &mut budget::Limited(&mut c, "output_opening"),
                &opening,
                &bits,
                &mat1,
                &mat2,
            );
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
    let program = builder.finish(None).map_err(|_| Error::ResourceLimit)?;
    let summary = Summary {
        representation: REPRESENTATION,
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        wires: program.wire_count(),
        witness_values: witness.len(),
        compiler_requested_bytes_peak: counters.requested_bytes_peak,
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
