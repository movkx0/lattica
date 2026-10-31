//! Seven public, deterministic research transactions under one original quota.
//! These are test keys and notes, never wallet key generation. The unchanged
//! join-split oracle constructs every commitment, membership root and nullifier.
use super::{add, mul, quota::Reservation, DecodeSession, Error, Geometry, Val};
use crate::{note, Context, Profile, GOLDILOCKS_MODULUS};
use lattica_prover_p3::joinsplit_air as js;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use serde::Serialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};
use std::{mem::size_of, time::Instant};

pub const CASE_COUNT: usize = 7;
const SEED_DOMAIN: &[u8] = b"lattica/research/private-note/seven-distinct-public-fixtures/v1";
// Two input commitments (6), 31 empty subtree hashes, two output recipients,
// and native_outputs: 2*(ownership + commitment*2 + depth + nullifier) + 4.
const PERMUTATIONS_PER_CASE: usize = 6 + 31 + 2 + 2 * (1 + 2 + 32 + 1) + 4;
// Pinned scalar Poseidon2 constructor: two 4x8 external-round vectors and
// one 22-word internal-round vector. No overlap credit: charge all requests.
const PERMUTATION_BACKING_BYTES: usize = (2 * 4 * 8 + 22) * size_of::<Val>();

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureId(u8);

impl FixtureId {
    pub const ALL: [Self; CASE_COUNT] = [
        Self(0),
        Self(1),
        Self(2),
        Self(3),
        Self(4),
        Self(5),
        Self(6),
    ];

    pub const fn ordinal(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FixturePlan {
    pub case_count: usize,
    pub permutations_per_case: usize,
    pub source_heap_requests_bytes: usize,
    pub source_inline_owner_bytes: usize,
    pub required_host_bytes: usize,
}

impl FixturePlan {
    /// Pure source census; the number itself grants no allocation authority.
    /// Allocator metadata and compiled stack frames remain externally guarded.
    pub fn new() -> Result<Self, Error> {
        Geometry::pinned()?;
        if p3_goldilocks::GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS != 4
            || p3_goldilocks::GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8 != 22
        {
            return Err(Error::Geometry);
        }
        let source_heap_requests_bytes = mul(
            CASE_COUNT,
            add(
                mul(PERMUTATIONS_PER_CASE, PERMUTATION_BACKING_BYTES)?,
                mul(js::N_PUBLIC, size_of::<u64>())?,
            )?,
        )?;
        // Charge both arrays during the Option-to-owner move, one construction
        // frame's explicit values and hash objects, and the quota handle. The
        // helper functions allocate no extra vectors beyond the pinned oracle.
        let source_inline_owner_bytes = [
            size_of::<FixtureSet>(),
            size_of::<[Option<Fixture>; CASE_COUNT]>(),
            size_of::<Fixture>(),
            2 * size_of::<js::Witness>(),
            size_of::<js::PublicOutputs>(),
            size_of::<[[Val; 4]; js::DEPTH]>(),
            4 * size_of::<[Val; 4]>(),
            size_of::<[u64; 32]>(),
            size_of::<[u8; 256]>(),
            size_of::<[u8; 32]>(),
            size_of::<Shake256>(),
            size_of::<Shake256Reader>(),
            size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>(),
            4 * size_of::<[Val; 8]>(),
            size_of::<Reservation>(),
            size_of::<FixturePlan>(),
            3 * size_of::<Instant>(),
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| add(total, bytes))?;
        Ok(Self {
            case_count: CASE_COUNT,
            permutations_per_case: PERMUTATIONS_PER_CASE,
            source_heap_requests_bytes,
            source_inline_owner_bytes,
            required_host_bytes: add(source_heap_requests_bytes, source_inline_owner_bytes)?,
        })
    }
}

/// Payload stays borrowed from its enclosing non-cloneable FixtureSet owner.
pub struct Fixture {
    id: FixtureId,
    statement: note::Statement,
    witness: js::Witness,
    generation_ns: u128,
}

impl Fixture {
    pub fn id(&self) -> FixtureId {
        self.id
    }
    pub fn statement(&self) -> &note::Statement {
        &self.statement
    }
    pub fn witness(&self) -> &js::Witness {
        &self.witness
    }
    pub fn generation_ns(&self) -> u128 {
        self.generation_ns
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureReceipt {
    pub source: &'static str,
    pub case_count: usize,
    pub distinct_nullifiers: usize,
    pub distinct_statements: usize,
    pub generation_and_distinctness_ns: u128,
    pub reserved_host_bytes: usize,
    pub production_keys: bool,
}

/// No Clone, owned extraction or callback. Fields drop before their original
/// reservation, even if the DecodeSession was already destroyed.
pub struct FixtureSet {
    cases: [Fixture; CASE_COUNT],
    receipt: FixtureReceipt,
    reservation: Reservation,
}

impl FixtureSet {
    pub fn get(&self, id: FixtureId) -> &Fixture {
        &self.cases[id.ordinal()]
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Fixture> {
        self.cases.iter()
    }
    pub fn receipt(&self) -> FixtureReceipt {
        self.receipt
    }
    pub(super) fn same_ledger(&self, token: &Reservation) -> bool {
        self.reservation.same_ledger(token)
    }
}

impl DecodeSession {
    /// Reserve every fixture/oracle request before constructing any test note.
    /// All fourteen nullifiers and all seven statements are checked before the
    /// owner can be supplied to a proving screen; no GPU call occurs here.
    pub fn research_fixtures(&self, context: Context) -> Result<FixtureSet, Error> {
        let plan = FixturePlan::new()?;
        let reservation = self.reserve_for_producer(plan.required_host_bytes)?;
        let started = Instant::now();
        let mut cases: [Option<Fixture>; CASE_COUNT] = std::array::from_fn(|_| None);
        for id in FixtureId::ALL {
            cases[id.ordinal()] = Some(build_fixture(id, context)?);
        }
        let cases = cases.map(|case| case.expect("all seven fixed cases constructed"));
        distinct(&cases)?;
        Ok(FixtureSet {
            cases,
            receipt: FixtureReceipt {
                source: "seven-distinct-public-fixtures-v1",
                case_count: CASE_COUNT,
                distinct_nullifiers: CASE_COUNT * js::N_IN,
                distinct_statements: CASE_COUNT,
                generation_and_distinctness_ns: started.elapsed().as_nanos(),
                reserved_host_bytes: plan.required_host_bytes,
                production_keys: false,
            },
            reservation,
        })
    }
}

fn build_fixture(id: FixtureId, context: Context) -> Result<Fixture, Error> {
    let started = Instant::now();
    let mut hash = Shake256::default();
    hash.update(SEED_DOMAIN);
    hash.update(&[id.0]);
    let mut bytes = [0u8; 256];
    hash.finalize_xof().read(&mut bytes);
    let words: [u64; 32] = std::array::from_fn(|i| {
        u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()) % GOLDILOCKS_MODULUS
    });
    let field = |i: usize| Val::from_u64(words[i]);
    let asset = field(28);
    let ordinal = u64::from(id.0);
    let mut witness = js::Witness {
        inputs: std::array::from_fn(|i| {
            let offset = i * 7;
            js::Input {
                nk: [words[offset], words[offset + 1]],
                div: field(offset + 2),
                asset,
                value: if i == 0 {
                    (1 << 51) + 1000 + ordinal
                } else {
                    500 + ordinal
                },
                rho: [field(offset + 3), field(offset + 4)],
                rcm: [field(offset + 5), field(offset + 6)],
                sib: [[Val::ZERO; 4]; js::DEPTH],
                bits: [false; js::DEPTH],
            }
        }),
        outputs: std::array::from_fn(|i| {
            let offset = 14 + i * 7;
            js::Output {
                recipient: js::recipient_of(field(offset), field(offset + 1), field(offset + 2)),
                asset,
                value: if i == 0 {
                    (1 << 51) + 900
                } else {
                    600 + 2 * ordinal
                },
                rho: [field(offset + 3), field(offset + 4)],
                rcm: [field(offset + 5), field(offset + 6)],
            }
        }),
        fee: 0,
        mint: 0,
        tx_binding: fixed_context_binding(context),
    };
    let leaves: [[Val; 4]; 2] = std::array::from_fn(|i| {
        let input = &witness.inputs[i];
        let recipient = js::recipient_of(field(i * 7), field(i * 7 + 1), input.div);
        js::commit(
            recipient,
            Val::from_u64(input.value),
            input.rho,
            input.rcm,
            asset,
        )
    });
    let mut empty = [[Val::ZERO; 4]; js::DEPTH];
    for depth in 1..js::DEPTH {
        empty[depth] = js::merge(empty[depth - 1], empty[depth - 1]);
    }
    for (i, input) in witness.inputs.iter_mut().enumerate() {
        input.sib = empty;
        input.sib[0] = leaves[1 - i];
        input.bits[0] = i == 1;
    }
    let public = js::native_outputs(&witness);
    let mut words = Vec::new();
    words
        .try_reserve_exact(js::N_PUBLIC)
        .map_err(|_| Error::ResourceLimit)?;
    if words.capacity() != js::N_PUBLIC {
        return Err(Error::ResourceLimit);
    }
    words.extend(public.anchor.map(|v| v.as_canonical_u64()));
    for values in public.nullifiers.into_iter().chain(public.out_cms) {
        words.extend(values.map(|v| v.as_canonical_u64()));
    }
    words.push(0);
    words.push(0);
    words.extend(witness.tx_binding.map(|v| v.as_canonical_u64()));
    if words.len() != js::N_PUBLIC {
        return Err(Error::Geometry);
    }
    Ok(Fixture {
        id,
        statement: note::Statement {
            profile: Profile::PrivateNoteDirectV1,
            context,
            public: words,
        },
        witness,
        generation_ns: started.elapsed().as_nanos(),
    })
}

fn fixed_context_binding(context: Context) -> [Val; 4] {
    let mut hash = Shake256::default();
    hash.update(Profile::PrivateNoteDirectV1.tag().as_bytes());
    hash.update(&context.0);
    let mut bytes = [0u8; 32];
    hash.finalize_xof().read(&mut bytes);
    std::array::from_fn(|i| {
        Val::from_u64(
            u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()) % GOLDILOCKS_MODULUS,
        )
    })
}

fn distinct(cases: &[Fixture; CASE_COUNT]) -> Result<(), Error> {
    for (i, fixture) in cases.iter().enumerate() {
        for prior in &cases[..i] {
            if fixture.statement == prior.statement {
                return Err(Error::Statement);
            }
        }
        for input in 0..js::N_IN {
            let first = js::PI_NF + input * 4;
            let nullifier = &fixture.statement.public[first..first + 4];
            for prior in 0..i * js::N_IN + input {
                let preceding = &cases[prior / js::N_IN].statement.public;
                let first = js::PI_NF + (prior % js::N_IN) * 4;
                if nullifier == &preceding[first..first + 4] {
                    return Err(Error::Statement);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
