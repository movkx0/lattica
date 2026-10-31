//! Public-only reconstruction and its owner bounds. The compiler accepts these
//! domain-valid synthetic hints without evaluating the relation. No compiler
//! hint, trace or witness value is an acceptance input for the verifier.
use super::*;
use crate::ring::{Account, Witness};
use std::{cell::Cell, mem::size_of};

const REPORT_AND_SESSION_BYTES: usize = 256 << 10;

// Sealed per-call allocation source. Production constructs only None; the
// test-only entry can return null but cannot supply an arbitrary raw pointer.
// Both entries reach the same admission and null-result handling below.
struct WitnessAllocation<'a> {
    forced_null_attempts: Option<&'a Cell<usize>>,
}

impl WitnessAllocation<'_> {
    fn allocate_zeroed(self, layout: std::alloc::Layout) -> *mut Witness {
        if let Some(attempts) = self.forced_null_attempts {
            attempts.set(attempts.get().saturating_add(1));
            return std::ptr::null_mut();
        }
        // SAFETY: the sole caller supplies the nonzero exact Witness layout.
        unsafe { std::alloc::alloc_zeroed(layout) }.cast::<Witness>()
    }
}

// Compile-time, exhaustive representation guard for the zero-validity argument
// below. This is never called and creates no runtime witness or allocation.
const _: fn(&Witness) = |witness| {
    let Witness {
        selected_pair,
        spending,
        input_openings,
        output_openings,
        input_values,
        output_values,
    } = witness;
    let _: &usize = selected_pair;
    let _: &[[[i64; crate::ring::D]; crate::ring::SPENDING_POLYS]; crate::INPUTS] = spending;
    let _: &[[[i64; crate::ring::D]; crate::ring::OPENING_POLYS]; crate::INPUTS] = input_openings;
    let _: &[[[i64; crate::ring::D]; crate::ring::OPENING_POLYS]; crate::OUTPUTS] = output_openings;
    let _: &[u64; crate::INPUTS] = input_values;
    let _: &[u64; crate::OUTPUTS] = output_values;
};

fn synthetic_witness_bytes() -> Result<usize, Error> {
    // One in-place heap payload. The typed Witness never crosses a return
    // boundary by value; only pointer-sized Box/Result owners move.
    [
        size_of::<Witness>(),
        12 * size_of::<Box<Witness>>(),
        8 * size_of::<Result<Box<Witness>, Error>>(),
        4 * size_of::<Result<usize, Error>>(),
        8 * size_of::<std::alloc::Layout>(),
        8 * size_of::<*mut Witness>(),
        8 * size_of::<&Statement>(),
        // Both wrapper constructors, allocation-source forwarding and the
        // local fault observer are counted even in production's None path.
        4 * size_of::<WitnessAllocation<'static>>(),
        4 * size_of::<Option<&Cell<usize>>>(),
        4 * size_of::<&Cell<usize>>(),
        4 * size_of::<Cell<usize>>(),
        4 * size_of::<usize>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes).ok_or(Error::ResourceLimit)
    })
}

pub(super) fn caller_bytes(statement: &Statement) -> Result<usize, Error> {
    let identity_storage = super::super::identity_reuse::source_host_bytes()?;
    let synthetic_storage = synthetic_witness_bytes()?;
    #[cfg(feature = "ring-recursion-experiment")]
    let recursive_storage = super::recursive_child::caller_bytes()?;
    #[cfg(not(feature = "ring-recursion-experiment"))]
    let recursive_storage = 0usize;
    let bytes = statement
        .ring
        .capacity()
        .checked_mul(size_of::<[Account; crate::INPUTS]>())
        .and_then(|n| n.checked_add(size_of::<Statement>()))
        .and_then(|n| n.checked_add(identity_storage))
        .and_then(|n| n.checked_add(synthetic_storage))
        .and_then(|n| n.checked_add(super::mutation::caller_bytes()))
        .and_then(|n| n.checked_add(recursive_storage))
        .and_then(|n| n.checked_add(size_of::<Artifact>()))
        .and_then(|n| n.checked_add(size_of::<IndependentVerifier>()))
        .and_then(|n| n.checked_add(size_of::<VerificationReport>()))
        // Additive forwarding/results for both entry paths; receipt payload
        // and moves remain a separate additive charge inside the caller limit.
        .and_then(|n| {
            n.checked_add(3 * size_of::<Result<VerificationReport, VerificationFailure>>())
        })
        .and_then(|n| n.checked_add(12 * size_of::<&Statement>()))
        .and_then(|n| n.checked_add(4 * size_of::<VerificationFailure>()))
        .and_then(|n| n.checked_add(REPORT_AND_SESSION_BYTES))
        .and_then(|n| n.checked_add(CALLER_ORCHESTRATION_BYTES))
        .and_then(|n| n.checked_add(16 << 10)) // fixed hashes, errors and Arc headers
        .ok_or(Error::ResourceLimit)?;
    if bytes > REGISTERED_GPU_CALLER_HOST_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

pub(super) fn synthetic_witness(statement: &Statement) -> Result<Box<Witness>, Error> {
    synthetic_witness_with_allocation(
        statement,
        WitnessAllocation {
            forced_null_attempts: None,
        },
    )
}

#[cfg(test)]
pub(super) fn synthetic_witness_with_forced_null(
    statement: &Statement,
    attempts: &Cell<usize>,
) -> Result<Box<Witness>, Error> {
    synthetic_witness_with_allocation(
        statement,
        WitnessAllocation {
            forced_null_attempts: Some(attempts),
        },
    )
}

fn synthetic_witness_with_allocation(
    statement: &Statement,
    allocation: WitnessAllocation<'_>,
) -> Result<Box<Witness>, Error> {
    caller_bytes(statement)?;
    let layout = std::alloc::Layout::new::<Witness>();
    // This fallible allocation initializes that one admitted payload in place,
    // without constructing any full-size stack Witness or returning one.
    let pointer = allocation.allocate_zeroed(layout);
    if pointer.is_null() {
        return Err(Error::ResourceLimit);
    }
    // SAFETY: the allocation uses the global allocator and exact Witness layout.
    // Witness contains only usize, u64 and fixed signed-integer arrays, all
    // valid when zero. Those values exactly match the prior synthetic hints.
    // No fallible operation occurs between allocation success and sole owning
    // Box conversion; Witness::drop zeroizes its payload before deallocation.
    // The exhaustive typed constant above rejects field/type changes until
    // this zero-validity argument is re-audited.
    Ok(unsafe { Box::from_raw(pointer) })
}

pub(super) fn compile(
    statement: &Statement,
    expected: Context,
    profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
) -> Result<CompiledRelation, Error> {
    // Proof backing and all fixed caller owners remain live during compilation.
    // The compiler admits its own complete construction envelope from the
    // remaining worker allowance before deriving AES parameters or hints.
    let compiler_allowance = (HOST_BYTES as usize)
        .checked_sub(artifact::MAX_RETAINED_PROOF_BYTES)
        .and_then(|n| n.checked_sub(REGISTERED_GPU_CALLER_HOST_BYTES))
        .ok_or(Error::ResourceLimit)?;
    compile_in_partition(statement, expected, profile, representation, compiler_allowance)
}

/// Private aggregate callers subtract all retained siblings and reports from
/// the original worker before entry. This cannot increase the old allowance.
pub(in crate::ring_circuit) fn compile_in_partition(
    statement: &Statement,
    expected: Context,
    profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
    compiler_allowance: usize,
) -> Result<CompiledRelation, Error> {
    statement.admit(expected)?;
    caller_bytes(statement)?;
    if compiler_allowance > HOST_BYTES as usize - artifact::MAX_RETAINED_PROOF_BYTES - REGISTERED_GPU_CALLER_HOST_BYTES
        || profile.limits().required_host_bytes > compiler_allowance as u64 {
        return Err(Error::ResourceLimit);
    }
    let witness = synthetic_witness(statement)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        compile_with_representation_diagnostics(
            statement,
            &witness,
            expected,
            profile,
            representation,
            compiler_allowance,
        )
    }));
    drop(witness);
    let relation = match result {
        Ok(value) => value.map_err(|failure| failure.error)?,
        Err(payload) => {
            drop(payload);
            return Err(Error::Backend("public reconstruction panicked".into()));
        }
    };
    let program = &relation.program;
    if relation.summary.deferred_crypto_obligations != 0
        || relation.summary.representation != representation.name()
        || program.public_values() != 4
        || program.witness_values() != relation.witness.len()
        || program.active_rows() != relation.summary.active_rows
        || program.height() != relation.summary.padded_rows
        || program.wire_count() != relation.summary.wires
        || program.witness_values() != relation.summary.witness_values
        || program.height() > MAX_ROWS
        || !program.height().is_power_of_two()
        || program.height() < 8
        || relation.public != artifact::statement_binding(statement)
    {
        return Err(Error::Geometry);
    }
    Ok(relation)
}

pub(super) fn descriptor(program: &Program, manifest: [u8; 32], id: [u64; 4]) -> ProofDescriptor {
    ProofDescriptor {
        active_rows: program.active_rows() as u64,
        padded_rows: program.height() as u64,
        wires: program.wire_count() as u64,
        witness_values: program.witness_values() as u64,
        canonical_manifest_digest: manifest,
        registered_program_id: id,
    }
}

pub(super) fn check_claims(
    relation: &CompiledRelation,
    claims: ProofDescriptor,
) -> Result<(), Error> {
    // Reconstruct dimensions and manifest before dispatch. The stable registered
    // ID is compared separately after independent preprocessing; retaining the
    // packet's ID here conveys no authority to perform that later comparison.
    let local = descriptor(
        &relation.program,
        proving::canonical_manifest_digest(&relation.program)?,
        claims.registered_program_id,
    );
    if local != claims {
        return Err(Error::ProofRejected);
    }
    Ok(())
}
