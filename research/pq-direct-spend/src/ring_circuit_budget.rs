//! Bound every witness-producing primitive before delegating to the existing
//! constraint backend. Generic NTT/product routines have no Result callback, so
//! a private unwind marker aborts compilation at the *first* rejected operation.
//! The outer compiler catches only this marker. No proof is dispatched or retried.
use super::{CompilationFailure, MAX_INPUTS, MAX_WIRES, PROGRAM_BYTES, WITNESS_BYTES};
use lattica_pq_ringct_research::rust_verify::{
    constraints::{ByteValue, ConstraintContext, ResidueValue, SignedValue},
    generic::{Backend, GParameters, GStatement, Polynomial},
    VerifyError,
};

pub(super) struct Exhausted(pub CompilationFailure);
pub(super) fn guard(c: &ConstraintContext<'_, '_>) {
    guard_phase(c, "direct_relation_inputs");
}
fn guard_phase(c: &ConstraintContext<'_, '_>, phase: &'static str) {
    // In constraints.rs, add/sub allocate 2 hints, signed conversion 1, and
    // mont allocates at most 4 (two multiply operations, each quotient/remainder).
    // Eight is a conservative per-call bound, also covering direct one-input
    // allocations in the compiler. No method below requests deferred children.
    let counters = c.builder.construction_counters();
    let hints_exhausted = c.witness.len() > MAX_INPUTS.saturating_sub(8);
    if counters.resource_failed || hints_exhausted {
        let logical_limit = if hints_exhausted {
            "preallocated_witness_hint_count"
        } else if counters.wires >= counters.wire_limit {
            "program_wire_count"
        } else if counters.witnesses >= counters.input_limit {
            "program_input_count"
        } else {
            "program_heap_request_allowance"
        };
        std::panic::resume_unwind(Box::new(Exhausted(CompilationFailure {
            phase,
            logical_limit,
            program_byte_limit: PROGRAM_BYTES,
            witness_byte_limit: WITNESS_BYTES,
            wire_limit: MAX_WIRES,
            input_limit: MAX_INPUTS,
            requested_program_bytes_peak: Some(counters.requested_bytes_peak),
            wires: Some(counters.wires),
            input_values: Some(counters.witnesses),
            witness_hint_values: Some(c.witness.len()),
            cryptographic_proof_started: false,
            error: crate::Error::ResourceLimit,
        })));
    }
}

pub(super) struct Limited<'a, 'c, 'p>(pub &'a mut ConstraintContext<'c, 'p>, pub &'static str);
impl Backend for Limited<'_, '_, '_> {
    type Residue = ResidueValue;
    type Signed = SignedValue;
    type Byte = ByteValue;
    fn constant(&mut self, value: u64, q: u64) -> ResidueValue {
        guard_phase(self.0, self.1);
        self.0.constant(value, q)
    }
    fn add(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        guard_phase(self.0, self.1);
        self.0.add(a, b, q)
    }
    fn sub(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        guard_phase(self.0, self.1);
        self.0.sub(a, b, q)
    }
    fn mont(&mut self, a: ResidueValue, b: ResidueValue, q: u64) -> ResidueValue {
        guard_phase(self.0, self.1);
        self.0.mont(a, b, q)
    }
    fn to_residue(&mut self, a: SignedValue, q: u64) -> ResidueValue {
        guard_phase(self.0, self.1);
        self.0.to_residue(a, q)
    }
    fn signed_neg(&mut self, a: SignedValue) -> SignedValue {
        guard_phase(self.0, self.1);
        self.0.signed_neg(a)
    }
    fn signed_sub(&mut self, a: SignedValue, b: SignedValue) -> SignedValue {
        guard_phase(self.0, self.1);
        self.0.signed_sub(a, b)
    }
    // These are verifier-of-proof operations; the direct relation may not call
    // them, silently delegate them, or accept their native results.
    fn norm(&mut self, _: &[Polynomial<SignedValue>], _: u64) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn g_bound(
        &mut self,
        _: &Polynomial<SignedValue>,
        _: &Polynomial<SignedValue>,
        _: u32,
    ) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn equal_bytes(&mut self, _: &[ByteValue; 32], _: &[ByteValue; 32]) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn equal_signed(
        &mut self,
        _: &Polynomial<SignedValue>,
        _: &Polynomial<SignedValue>,
    ) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn parameters(
        &mut self,
        _: &[ByteValue; 32],
        _: &[ByteValue; 32],
    ) -> Result<GParameters<ResidueValue, ByteValue>, VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn sample_g(
        &mut self,
        _: &[ByteValue; 32],
    ) -> Result<Vec<Polynomial<ResidueValue>>, VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn expand_alpha(
        &mut self,
        _: &[ByteValue; 32],
    ) -> Result<(Vec<Polynomial<ResidueValue>>, Polynomial<SignedValue>), VerifyError> {
        Err(VerifyError::Rejected)
    }
    fn hash_alpha(
        &mut self,
        _: &[ByteValue; 32],
        _: &GStatement<ResidueValue, ByteValue>,
        _: &[Vec<Polynomial<ResidueValue>>],
        _: &[Polynomial<ResidueValue>],
        _: &[Polynomial<ResidueValue>],
        _: &Polynomial<ResidueValue>,
        _: &Polynomial<ResidueValue>,
        _: &Polynomial<ResidueValue>,
        _: &[Polynomial<ResidueValue>],
        _: &[Polynomial<ResidueValue>],
    ) -> [ByteValue; 32] {
        panic!("a MatRiCT verifier transcript is not part of the direct relation")
    }
    fn hash_x(
        &mut self,
        _: &[ByteValue; 32],
        _: &Polynomial<ResidueValue>,
        _: &Polynomial<ResidueValue>,
        _: &[Polynomial<ResidueValue>],
        _: &[Polynomial<ResidueValue>],
        _: &[Polynomial<ResidueValue>],
    ) -> Result<Polynomial<SignedValue>, VerifyError> {
        Err(VerifyError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_pq_ringct_research::rust_verify::{constraints_crypto::CryptoObligations, Q};
    use lattica_prover_p3::block_v2::machine::program::{ConstructionLimits, ProgramBuilder, Val};
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn exhausted_hint_storage_aborts_before_another_primitive_pushes() {
        let mut b = ProgramBuilder::new(4).unwrap();
        let mut hints = Vec::new();
        let mut obligations = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut hints,
            crypto: &mut obligations,
        };
        let one = c.constant_residue(1, Q);
        c.witness.resize(MAX_INPUTS - 7, Val::ZERO);
        let before = c.witness.len();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Limited(&mut c, "test_hint_limit").add(one, one, Q)
        }));
        assert!(result.unwrap_err().is::<Exhausted>());
        assert_eq!(c.witness.len(), before);
    }

    #[test]
    fn sticky_builder_failure_stops_before_more_hint_storage() {
        let mut b = ProgramBuilder::new_with_construction_limits(
            0,
            ConstructionLimits {
                max_requested_program_bytes: 1,
                max_wires: 16,
                max_input_values: 8,
            },
        )
        .unwrap();
        b.input();
        assert!(b.construction_counters().resource_failed);
        let mut hints = Vec::new();
        let mut obligations = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut hints,
            crypto: &mut obligations,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Limited(&mut c, "test_sticky_failure").constant(1, Q)
        }));
        assert!(result.unwrap_err().is::<Exhausted>());
        assert!(c.witness.is_empty());
    }
}
