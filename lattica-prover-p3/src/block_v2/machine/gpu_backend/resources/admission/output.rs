//! Source-derived output declarations for the pinned one-instance GPU producer.
//!
//! This neither authorizes that producer nor reserves enclosing owners. The
//! opening bound deliberately retains all its temporary query/assembly buffers;
//! it is a conservative producer ceiling, not a decoded-size observation.
use super::{opening, Bounds};
use crate::block_v2::{
    gpu_quotient_prover::opened_value_descriptor_host_bound,
    machine::{program::MAX_PUBLIC_VALUES, Program},
    profile::{self, Challenge},
};
use crate::config::Val;
use core::mem::size_of;
use p3_lookup::LookupTerminal;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RegisteredGpuOutputFootprint {
    pub public_values: u64,
    pub rows: u64,
    pub cap_roots: u64,
    pub source_program_retained_host_bytes: u64,
    pub opening_producer_host_bytes: u64,
    pub final_descriptor_host_bytes: u64,
    pub native_commitment_host_bytes: u64,
    pub degree_and_terminal_host_bytes: u64,
    /// Backing ceiling, excluding caller public values and the inline proof.
    pub proof_backing_ceiling_host_bytes: u64,
    /// Independent metadata includes its own public-only Program and its Arc,
    /// retained lookup graphs, trusted cap, and all nested common-data backing.
    pub verifier_metadata_retained_host_bytes: u64,
    pub verifier_construction_peak_host_bytes: u64,
    pub verifier_verification_peak_host_bytes: u64,
    /// The existing full verifier census includes a separately owned 64 MiB
    /// proof. Keeping this in addition to the producer claim is conservative.
    pub verifier_lifecycle_peak_host_bytes: u64,
    pub copied_key_cap_host_bytes: u64,
    pub producer_backing_bound_complete: bool,
    pub enclosing_ownership_bound_complete: bool,
    pub dispatch_authority: bool,
}

fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "registered output host sum overflow".into())
}
fn bytes<T>(count: usize) -> Result<usize, String> {
    count
        .checked_mul(size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or_else(|| "registered output host capacity overflow".into())
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
fn verifier(publics: usize, rows: usize, roots: usize) -> Result<[usize; 4], String> {
    let plan = crate::block_v2::machine::backend::verification_lifetimes::Plan::from_shape(
        publics,
        rows,
        roots,
        roots,
        crate::block_v2::machine::symbolic::verifier::Limits::default(),
    )
    .map_err(|_| "registered output independent verifier profile")?;
    Ok([
        plan.metadata_retained_bytes,
        plan.construction_peak_bytes,
        plan.verification_peak_bytes,
        plan.peak_bytes,
    ])
}
#[cfg(not(all(not(debug_assertions), target_arch = "x86_64")))]
fn verifier(_: usize, _: usize, _: usize) -> Result<[usize; 4], String> {
    Err("registered output requires the pinned release x86_64 verifier".into())
}

/// Inspect immutable Program geometry without allocating a proof or key. The
/// caller must preclaim every output and enclosing owner in its own ledger.
/// This report is copyable and carries no execution or ownership authority.
pub fn inspect_registered_gpu_output(
    program: &Program,
) -> Result<RegisteredGpuOutputFootprint, String> {
    let bounds = Bounds::for_program(program)?;
    if MAX_PUBLIC_VALUES != 64
        || program.public_values() > MAX_PUBLIC_VALUES
        || bounds.main_columns != 94
        || bounds.preprocessing_columns != 200
    {
        return Err("registered output source does not match the pinned wide AIR".into());
    }
    inspect_shape(
        program.public_values(),
        program.height(),
        bounds.program_retained_host_bytes,
    )
}

// Shared arithmetic for pre-native source bounds. This is not a Program,
// verification key or admission. The enclosing source owner separately proves
// that every genuine compiled program falls within these declared capacities.
pub(super) fn inspect_shape(
    public_values: usize,
    rows: usize,
    source_program_retained_host_bytes: u64,
) -> Result<RegisteredGpuOutputFootprint, String> {
    if MAX_PUBLIC_VALUES != 64
        || public_values > MAX_PUBLIC_VALUES
        || !(8..=1 << 20).contains(&rows)
        || !rows.is_power_of_two()
        || source_program_retained_host_bytes == 0
    {
        return Err("registered output source shape refused".into());
    }
    let opening = opening::proof_material_host_bound(rows)?;
    let descriptors = opened_value_descriptor_host_bound::<Challenge>(1, 1, 16)?;
    let log_height = rows.ilog2() as usize + 1 + profile::LOG_BLOWUP;
    let roots = 1usize << log_height.min(profile::CAP_HEIGHT);
    // GPU commitments copy exact cap slices into their independent native
    // commitments (main, quotient, permutation, random). Source tree caps are
    // charged by the existing backend metadata plan, without overlap credit.
    let cap = bytes::<[Val; 4]>(roots)?;
    let commitments = cap
        .checked_mul(4)
        .ok_or("registered output commitment overflow")?;
    // Both upstream vectors use the one-instance exact source length. Their
    // inline headers are within BatchProof, charged by its enclosing owner.
    let scalars = add(
        bytes::<usize>(1)?,
        bytes::<Option<LookupTerminal<Challenge>>>(1)?,
    )?;
    let proof = add(add(opening, descriptors)?, add(commitments, scalars)?)?;
    // Compatibility with the verifier's existing owned-input boundary; this
    // cap is not used to derive or replace the producer bound above.
    if proof > 64 << 20 {
        return Err("derived producer output exceeds independent verifier input profile".into());
    }
    let [metadata, construction, verification, lifecycle] = verifier(public_values, rows, roots)?;
    Ok(RegisteredGpuOutputFootprint {
        public_values: public_values as u64,
        rows: rows as u64,
        cap_roots: roots as u64,
        source_program_retained_host_bytes: source_program_retained_host_bytes,
        opening_producer_host_bytes: opening as u64,
        final_descriptor_host_bytes: descriptors as u64,
        native_commitment_host_bytes: commitments as u64,
        degree_and_terminal_host_bytes: scalars as u64,
        proof_backing_ceiling_host_bytes: proof as u64,
        verifier_metadata_retained_host_bytes: metadata as u64,
        verifier_construction_peak_host_bytes: construction as u64,
        verifier_verification_peak_host_bytes: verification as u64,
        verifier_lifecycle_peak_host_bytes: lifecycle as u64,
        copied_key_cap_host_bytes: cap as u64,
        producer_backing_bound_complete: true,
        enclosing_ownership_bound_complete: false,
        dispatch_authority: false,
    })
}

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "block-v2-wide-lanes"
))]
mod tests {
    use super::*;
    use crate::block_v2::machine::ProgramBuilder;

    #[test]
    fn output_ceiling_covers_both_public_profiles_without_changing_crypto_geometry() {
        let a = ProgramBuilder::new(4)
            .unwrap()
            .finish(Some(1 << 19))
            .unwrap();
        let b = ProgramBuilder::new(46)
            .unwrap()
            .finish(Some(1 << 19))
            .unwrap();
        let a = inspect_registered_gpu_output(&a).unwrap();
        let b = inspect_registered_gpu_output(&b).unwrap();
        assert_eq!(
            a.proof_backing_ceiling_host_bytes,
            b.proof_backing_ceiling_host_bytes
        );
        assert!(a.proof_backing_ceiling_host_bytes < 64 << 20);
        assert_eq!(a.cap_roots, 64);
        assert_eq!(a.native_commitment_host_bytes, 4 * 64 * 32);
        assert!(b.verifier_metadata_retained_host_bytes >= a.verifier_metadata_retained_host_bytes);
        assert!(b.verifier_lifecycle_peak_host_bytes >= b.verifier_metadata_retained_host_bytes);
        assert!(b.producer_backing_bound_complete);
        assert!(!b.enclosing_ownership_bound_complete);
        assert!(!b.dispatch_authority);
    }

    #[test]
    fn output_source_ceiling_is_monotone_and_refuses_unsupported_rows() {
        let mut previous = 0;
        for log in 3..=20 {
            let value = opening::proof_material_host_bound(1 << log).unwrap();
            assert!(value >= previous);
            previous = value;
        }
        for rows in [0, 7, 9, 1 << 21, usize::MAX] {
            assert!(opening::proof_material_host_bound(rows).is_err());
        }
        assert!(bytes::<Val>(usize::MAX).is_err());
        assert!(add(usize::MAX, 1).is_err());
    }
}
