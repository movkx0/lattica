//! Synthetic schema/codec differential only. These objects are NOT proofs.
//! No AIR, Program, registered verifier, GPU/runtime or actual root is created.
use super::super::{self as model, *};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation, WorkerAllowance};
use lattica_prover_p3::block_v2::gpu_hash::CandidateMmcs;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, proof::OpenedValuesWithLookups};
use p3_commit::BatchOpening;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_symmetric::MerkleCap;
use std::time::Instant;

#[path = "differential/fixture.rs"]
mod fixture;
#[path = "differential/census.rs"]
mod census;
#[path = "differential/claims.rs"]
mod claims;

type Cap = MerkleCap<Val, [Val; 4]>;
type Opening = BatchOpening<Val, CandidateMmcs>;
type Fri = FriProof<Challenge, profile::ChallengeMmcs, Val, Vec<Opening>>;
type Query = QueryProof<Challenge, profile::ChallengeMmcs, Vec<Opening>>;
type Step = CommitPhaseProofStep<Challenge, profile::ChallengeMmcs>;
type Values = p3_uni_stark::OpenedValues<Challenge>;
type LookupValues = OpenedValuesWithLookups<Challenge>;
type R<T> = core::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Overflow,
    Layout,
    Allocation,
    FixtureStorage,
    Admission,
    Authority,
    Codec(postcard::Error),
    UnexpectedShortDecodeSuccess,
}

fn sum(a: usize, b: usize) -> R<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn product(a: usize, b: usize) -> R<usize> {
    a.checked_mul(b).ok_or(Error::Overflow)
}
fn require(value: bool) -> R<()> {
    if value { Ok(()) } else { Err(Error::Layout) }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Backing {
    bytes: usize,
    allocations: usize,
    max_vector: usize,
}

#[derive(Debug)]
struct Case {
    rows: usize,
    encoded_bytes: usize,
    fixture_backing: Backing,
    decoded_backing: Backing,
    canonical_bytes: usize,
    exact_decode_limit: usize,
    short_decode_limit: usize,
    short_error: postcard::Error,
    encoding_ns: u128,
    decoding_ns: u128,
    reencoding_ns: u128,
    short_decoding_ns: u128,
}

fn packet() -> R<Vec<u8>> {
    let mut packet = Vec::new();
    packet.try_reserve_exact(INNER_LIMIT).map_err(|_| Error::Allocation)?;
    require(packet.capacity() == INNER_LIMIT)?;
    packet.resize(INNER_LIMIT, 0u8);
    Ok(packet)
}

fn phase(
    expected: HeightShape,
    word: Val,
    ledger: &Ledger,
    caller: &Reservation,
) -> R<Case> {
    if !caller.belongs_to(ledger) || caller.requirements() != claims::driver()? {
        return Err(Error::Authority);
    }
    let original = ledger.admit_phase(claims::phase()?).map_err(|_| Error::Admission)?;
    // This reservation is declared before every payload; payloads die first
    // on success, returned failure and ordinary unwind. The separate caller
    // backs any fixed error returned after the phase reservation is released.
    let mut construction = fixture::Storage::new();
    let fixture = fixture::make(expected.rows, word, &mut construction)?;
    let fixture_backing = census::proof(&fixture)?;
    require(fixture_backing == construction.backing())?;
    require(fixture_backing.bytes == expected.decoded_vector_bytes)?;
    let mut encoded = packet()?;
    let mut canonical = packet()?;
    let started = Instant::now();
    let length = codec::encode_registered_proof_into(&fixture, &mut encoded)
        .map_err(Error::Codec)?.len();
    let encoding_ns = started.elapsed().as_nanos();
    require(length == expected.encoded_inner_bytes)?;
    let canonical_bytes = length.checked_sub(MAGIC_BYTES).ok_or(Error::Overflow)?;
    let exact_decode_limit = sum(fixture_backing.bytes, canonical_bytes)?;
    require(exact_decode_limit == expected.decoded_cumulative_bytes)?;
    require(exact_decode_limit <= DECODE_LIMIT)?;
    let started = Instant::now();
    let decoded = codec::decode_registered_proof_bounded(&encoded[..length], exact_decode_limit)
        .map_err(Error::Codec)?;
    let decoding_ns = started.elapsed().as_nanos();
    let decoded_backing = census::proof(&decoded)?;
    require(decoded_backing == fixture_backing)?;
    require(sum(decoded_backing.allocations, 1)? == expected.decoder_allocations)?;
    require(decoded_backing.max_vector == expected.max_sequence)?;
    let started = Instant::now();
    let reencoded = codec::encode_registered_proof_into(&decoded, &mut canonical)
        .map_err(Error::Codec)?;
    require(reencoded == &encoded[..length])?;
    let reencoding_ns = started.elapsed().as_nanos();
    // The core decoder's canonical allocation remains cumulatively charged.
    // Keep the complete 64 MiB claim even after decoded data are destroyed.
    drop(decoded);
    let short_decode_limit = exact_decode_limit.checked_sub(1).ok_or(Error::Overflow)?;
    let started = Instant::now();
    let short_error = match codec::decode_registered_proof_bounded(&encoded[..length], short_decode_limit) {
        Err(error) => error,
        Ok(unexpected) => {
            drop(unexpected);
            return Err(Error::UnexpectedShortDecodeSuccess);
        }
    };
    let short_decoding_ns = started.elapsed().as_nanos();
    let report = Case {
        rows: expected.rows, encoded_bytes: length, fixture_backing, decoded_backing,
        canonical_bytes, exact_decode_limit, short_decode_limit, short_error,
        encoding_ns, decoding_ns, reencoding_ns, short_decoding_ns,
    };
    // The separate original caller backs the fixed report after this phase.
    // No proof/vector/reference or reservation escapes into the report.
    drop(canonical);
    drop(encoded);
    drop(fixture);
    drop(construction);
    drop(original);
    Ok(report)
}

fn print_case(case: &Case) {
    eprintln!("transport_schema_case rows={} synthetic_lookup_columns=54 encoded_inner_bytes={} fixture_vector_bytes={} decoded_vector_bytes={} canonical_bytes={} exact_decode_limit_bytes={} decoder_vector_allocations={} short_decode_limit_bytes={} short_error={:?} encoding_ns={} decoding_ns={} reencoding_ns={} short_decoding_ns={} short_failure_cause_classified=false schema_only=true real_proof_fit=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        case.rows, case.encoded_bytes, case.fixture_backing.bytes,
        case.decoded_backing.bytes, case.canonical_bytes, case.exact_decode_limit,
        case.decoded_backing.allocations, case.short_decode_limit, case.short_error,
        case.encoding_ns, case.decoding_ns, case.reencoding_ns, case.short_decoding_ns);
}

#[test]
fn all_eighteen_upper_schema_fixtures_cross_check_the_actual_bounded_codec() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let caller = ledger.admit_phase(claims::driver().unwrap()).unwrap();
        let envelope = TransportEnvelope::for_root().unwrap();
        for expected in envelope.cases {
            let before = ledger.snapshot();
            let report = phase(expected, Val::NEG_ONE, &ledger, &caller).unwrap();
            assert_eq!(ledger.snapshot().current, before.current);
            print_case(&report);
        }
    }
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert!(ledger.snapshot().categories.iter().all(|entry| entry.current == Bytes::ZERO));
}

#[test]
fn fixed_u64_wire_size_is_unchanged_for_zero_and_maximum_canonical_words() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let caller = ledger.admit_phase(claims::driver().unwrap()).unwrap();
        let envelope = TransportEnvelope::for_root().unwrap();
        for expected in [envelope.cases[0], envelope.cases[HEIGHTS - 1]] {
            let before = ledger.snapshot();
            let zero = phase(expected, Val::ZERO, &ledger, &caller).unwrap();
            assert_eq!(ledger.snapshot().current, before.current);
            let maximum = phase(expected, Val::NEG_ONE, &ledger, &caller).unwrap();
            assert_eq!(ledger.snapshot().current, before.current);
            assert_eq!(zero.encoded_bytes, maximum.encoded_bytes);
            assert_eq!(zero.exact_decode_limit, maximum.exact_decode_limit);
            assert_eq!(zero.decoded_backing, maximum.decoded_backing);
            print_case(&zero);
            print_case(&maximum);
        }
    }
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert!(ledger.snapshot().categories.iter().all(|entry| entry.current == Bytes::ZERO));
}
