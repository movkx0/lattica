//! Complete fixed forwarding layouts of the pinned concrete registered codec.
use super::*;
use core::mem::{size_of, size_of_val};
use lattica_prover_p3::block_v2::gpu_hash::CandidateMmcs;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, BatchProof, proof::OpenedValuesWithLookups};
use p3_commit::BatchOpening;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_symmetric::MerkleCap;

type Challenge = profile::Challenge;
type Proof = BatchProof<profile::Config>;
type Cap = MerkleCap<Val, [Val; 4]>;
type Opening = BatchOpening<Val, CandidateMmcs>;
type Fri = FriProof<Challenge, profile::ChallengeMmcs, Val, Vec<Opening>>;
type Query = QueryProof<Challenge, profile::ChallengeMmcs, Vec<Opening>>;
type Step = CommitPhaseProofStep<Challenge, profile::ChallengeMmcs>;
type Values = p3_uni_stark::OpenedValues<Challenge>;
type LookupValues = OpenedValuesWithLookups<Challenge>;
type R<T> = core::result::Result<T, postcard::Error>;

// Type selector only. No synthetic or real proof is created or inspected.
fn element_size<T>(_: for<'a> fn(&'a Proof) -> &'a Vec<T>) -> usize { size_of::<T>() }

pub(super) fn bytes() -> AdmissionResult<usize> {
    let parts = [
        size_of::<Proof>(), size_of::<R<Proof>>(),
        size_of::<Cap>(), size_of::<R<Cap>>(),
        size_of::<BatchCommitments<Cap>>(), size_of::<R<BatchCommitments<Cap>>>(),
        size_of::<BatchOpenedValues<Challenge>>(), size_of::<R<BatchOpenedValues<Challenge>>>(),
        size_of::<LookupValues>(), size_of::<R<LookupValues>>(),
        size_of::<Values>(), size_of::<R<Values>>(),
        size_of::<Opening>(), size_of::<R<Opening>>(),
        size_of::<Fri>(), size_of::<R<Fri>>(),
        size_of::<Query>(), size_of::<R<Query>>(),
        size_of::<Step>(), size_of::<R<Step>>(),
        size_of::<Challenge>(), size_of::<Val>(),
        size_of::<[Val; 4]>(), size_of::<[u8; 8]>(),
        size_of::<Vec<Vec<Vec<Vec<Challenge>>>>>(),
        size_of::<(Vec<Vec<Val>>, Vec<[Val; 4]>)>(),
        size_of::<R<(Vec<Vec<Val>>, Vec<[Val; 4]>)>>(),
        size_of::<Option<Vec<Challenge>>>(),
        element_size(|p| &p.lookup_terminals),
        size_of::<postcard::Error>(), size_of::<std::collections::TryReserveError>(),
        // Pinned Storage/Attempt/Guard/Visit/Seed/Access, Postcard Slice,
        // fixed-u64 wrappers, serde scalar/array visitors and iteration state.
        size_of::<[usize; 128]>(),
    ];
    let one = parts.into_iter().try_fold(size_of_val(&parts), |sum, part|
        sum.checked_add(part).ok_or(ParentCompileError::Overflow))?;
    // All 32 permitted compound levels and 16 source-traced forwarding frames
    // per level coexist. No inlining, move-elision or union credit is taken.
    one.checked_mul(32).and_then(|n| n.checked_mul(16))
        .ok_or(ParentCompileError::Overflow)
}
