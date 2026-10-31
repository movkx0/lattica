//! CLI smoke mutation checks. Infrastructure failures never earn rejection
//! credit. This module adds no complete-workflow memory admission authority.
use super::{lookup_opening_mut, Limits, Stage};
use crate::component_tree::{NodeKey, NodeProof};
use core::mem::size_of;
use lattica_prover_p3::block_v2::{
    machine::{
        backend::{RegisteredVerificationFailure as Failure, RegisteredVerifier},
        program::Val,
    },
    profile::{Challenge, Config},
};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use serde_json::Value;

type Check = Result<(), Failure>;
type ProbeResult = Result<(), String>;

pub(super) const CLASSIFICATION: &str = "typed-numerical-rejection-v1";
const DIAGNOSTIC_BYTES: usize = 256;
const COPIES: usize = 4;
const ACCEPTED: &str = "changed smoke proof or public value was accepted";
const ADMISSION: &str = "smoke mutation verification refused admission; no rejection credit";
const CONFIGURATION: &str = "smoke mutation verifier configuration failed; no rejection credit";
const ALLOCATION: &str = "smoke mutation verifier allocation failed; no rejection credit";
const PUBLIC_SHAPE: &str = "smoke mutation public input shape is invalid";
const BUDGET: &str = "smoke typed mutation reservation does not fit the original host allowance";
const OVERFLOW: &str = "smoke typed mutation reservation arithmetic overflow";

fn require_rejection(result: Check) -> ProbeResult {
    match result {
        Err(Failure::RelationRejected(_)) => Ok(()),
        Ok(()) => Err(ACCEPTED.into()),
        Err(Failure::Admission(_)) => Err(ADMISSION.into()),
        Err(Failure::Configuration(_)) => Err(CONFIGURATION.into()),
        Err(Failure::Allocation(_)) => Err(ALLOCATION.into()),
    }
}

// The private guards expose only shared proof borrows during verification.
// Their constructors validate the exact slot before changing it. Its shape
// cannot change while the guard lives, so restoration is infallible in Drop.
trait OpeningOwner {
    fn opening_proof(&mut self) -> &mut BatchProof<Config>;
}
impl OpeningOwner for BatchProof<Config> {
    fn opening_proof(&mut self) -> &mut BatchProof<Config> {
        self
    }
}
impl OpeningOwner for NodeProof {
    fn opening_proof(&mut self) -> &mut BatchProof<Config> {
        &mut self.proof
    }
}
struct OpeningMutation<'a, T: OpeningOwner> {
    proof: &'a mut T,
    original: Challenge,
}
impl<'a, T: OpeningOwner> OpeningMutation<'a, T> {
    fn new(proof: &'a mut T) -> Result<Self, String> {
        let opening = lookup_opening_mut(proof.opening_proof())?;
        let original = *opening;
        *opening += Challenge::ONE;
        Ok(Self { proof, original })
    }
}
impl<T: OpeningOwner> Drop for OpeningMutation<'_, T> {
    fn drop(&mut self) {
        self.proof.opening_proof().opened_values.instances[0].permutation_local[0] = self.original;
    }
}
struct PublicMutation<'a> {
    proof: &'a mut NodeProof,
    index: usize,
    original: Val,
}
impl<'a> PublicMutation<'a> {
    fn new(proof: &'a mut NodeProof, index: usize) -> Result<Self, String> {
        let word = proof.public.get_mut(index).ok_or(PUBLIC_SHAPE)?;
        let original = *word;
        *word += Val::ONE;
        Ok(Self {
            proof,
            index,
            original,
        })
    }
}
impl Drop for PublicMutation<'_> {
    fn drop(&mut self) {
        self.proof.public[self.index] = self.original;
    }
}

fn opening<T: OpeningOwner>(proof: &mut T, verify: impl FnOnce(&T) -> Check) -> ProbeResult {
    let guard = OpeningMutation::new(proof)?;
    let result = verify(&*guard.proof);
    drop(guard);
    require_rejection(result)
}
fn public(
    proof: &mut NodeProof,
    index: usize,
    verify: impl FnOnce(&NodeProof) -> Check,
) -> ProbeResult {
    let guard = PublicMutation::new(proof, index)?;
    let result = verify(&*guard.proof);
    drop(guard);
    require_rejection(result)
}
fn wrong_byte_public(public: &[Val]) -> Result<[Val; 2], String> {
    let mut wrong: [Val; 2] = public.try_into().map_err(|_| PUBLIC_SHAPE.to_owned())?;
    wrong[0] += Val::ONE;
    Ok(wrong)
}

pub(super) fn check_byte(
    verifier: &RegisteredVerifier,
    proof: &mut BatchProof<Config>,
    public: &[Val],
) -> ProbeResult {
    let wrong = wrong_byte_public(public)?;
    require_rejection(verifier.verify_classified(proof, &wrong))?;
    opening(proof, |proof| verifier.verify_classified(proof, public))
}
pub(super) fn check_node(key: &NodeKey, proof: &mut NodeProof, index: usize) -> ProbeResult {
    public(proof, index, |proof| key.verify_classified(proof))?;
    opening(proof, |proof| key.verify_classified(proof))
}

/// Incremental CLI smoke reservation, charged inside the existing allowance.
/// It is not a planner token and does not admit any native/outer owned phase.
pub(super) struct Admission {
    original: Limits,
    remaining: Limits,
    reserved: u64,
}
impl Admission {
    pub(super) fn new(stage: Stage, limits: Limits) -> Result<Self, String> {
        limits.validate()?;
        Self::subtract(limits, extra_host_bytes(stage)?)
    }
    fn subtract(limits: Limits, reserved: u64) -> Result<Self, String> {
        let remaining = Limits {
            host_bytes: limits.host_bytes.checked_sub(reserved).ok_or(BUDGET)?,
            ..limits
        };
        // Preserve the original smoke floor and all device/row validation.
        remaining.validate()?;
        Ok(Self {
            original: limits,
            remaining,
            reserved,
        })
    }
    pub(super) fn work_limits(&self) -> Limits {
        self.remaining
    }
    pub(super) fn original_host_bytes(&self) -> u64 {
        self.original.host_bytes
    }
    pub(super) fn reserved_host_bytes(&self) -> u64 {
        self.reserved
    }
}

fn sum(left: usize, right: usize) -> Result<usize, String> {
    left.checked_add(right).ok_or_else(|| OVERFLOW.into())
}
fn times(value: usize, count: usize) -> Result<usize, String> {
    value.checked_mul(count).ok_or_else(|| OVERFLOW.into())
}

/// Complete additional inline owners/arguments/results for both probe routes,
/// both guard specializations, closures, admission and census/report helpers.
/// Retain every term even though the byte and AES routes are exclusive.
fn caller_inline_bytes() -> Result<usize, String> {
    let mut bytes = 0usize;
    macro_rules! add {
        ($ty:ty) => {
            bytes = sum(bytes, size_of::<$ty>())?;
        };
    }
    add!(OpeningMutation<'static, BatchProof<Config>>);
    add!(OpeningMutation<'static, NodeProof>);
    add!(PublicMutation<'static>);
    add!(Result<OpeningMutation<'static, BatchProof<Config>>, String>);
    add!(Result<OpeningMutation<'static, NodeProof>, String>);
    add!(Result<PublicMutation<'static>, String>);
    add!(Check);
    add!(Failure);
    add!(ProbeResult);
    add!(String);
    add!([Val; 2]);
    add!(Result<[Val; 2], String>);
    add!(Challenge);
    add!(Val);
    add!(&'static mut Challenge);
    add!(&'static mut Val);
    add!(Result<&'static mut Challenge, String>);
    add!(Option<&'static mut Val>);
    add!(&'static mut BatchProof<Config>);
    add!(&'static BatchProof<Config>);
    add!(&'static mut NodeProof);
    add!(&'static NodeProof);
    add!(&'static RegisteredVerifier);
    add!(&'static NodeKey);
    add!(&'static [Val]);
    add!(&'static [Val; 2]);
    add!((&'static RegisteredVerifier, &'static [Val])); // byte closure captures
    add!(&'static NodeKey); // AES closure capture
    add!(Admission);
    add!(Result<Admission, String>);
    add!(&'static Admission);
    add!(Limits);
    add!(Stage);
    add!(&'static str);
    add!([usize; 16]); // census locals, nested checked arithmetic, probe indexes
    add!([u64; 4]); // admission original/reserved/remaining and conversion
    add!(&'static mut usize);
    add!(bool);
    add!(Option<usize>);
    add!(Option<u64>);
    add!(Result<usize, String>);
    add!(Result<u64, String>);
    add!(core::array::TryFromSliceError);
    // Four complete layouts cover each helper's arguments, return, caller
    // locals and move overlap. Core classified layouts are charged separately.
    times(bytes, COPIES)
}

fn added_report_bytes() -> Result<usize, String> {
    // Four new scalar report members. The existing top-level smoke map has
    // fewer than 64 keys, so the locked BTreeMap backend has at most two
    // levels. Each insertion is bounded by three nodes. One conservative
    // node holds 16 complete key/value slots and 32 pointer/scalar slots,
    // exceeding Rust's 11 slots and 12 edges. Include key/value strings and
    // complete Value transports, then retain four copies for construction.
    let nodes = times(size_of::<([String; 16], [Value; 16], [usize; 32])>(), 12)?;
    let text = 4 * 128 + 128;
    let transports = times(size_of::<Value>(), 4)?;
    times(sum(sum(nodes, text)?, transports)?, COPIES)
}

fn extra_host_bytes(stage: Stage) -> Result<u64, String> {
    let classified = match stage {
        Stage::PqByte => RegisteredVerifier::classified_call_extra_bytes(),
        Stage::PqAesComponent => NodeKey::classified_call_extra_bytes(),
    };
    let bytes = sum(classified, caller_inline_bytes()?)?;
    // The core diagnostic is already included above. Keep two additional
    // bounded local diagnostics for source/error overlap without cloning it.
    let bytes = sum(bytes, 2 * DIAGNOSTIC_BYTES)?;
    let bytes = sum(bytes, added_report_bytes()?)?;
    u64::try_from(bytes).map_err(|_| OVERFLOW.into())
}

#[cfg(test)]
mod tests;
