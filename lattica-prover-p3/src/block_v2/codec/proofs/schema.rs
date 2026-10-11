//! Allocation-explicit seeds for the pinned native proof schema. Named-field
//! construction makes added upstream fields a compile error. Existing codec
//! guards still enforce nesting, item counts, field canonicality and encoding.
use super::Storage;
use crate::block_v2::{
    profile::{self, Challenge, Config},
    recursive::{NodeProof, WalletProof},
};
use crate::config::Val;
use serde::{
    de::{self, DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{fmt, marker::PhantomData};

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use crate::block_v2::gpu_hash::CandidateMmcs as ValMmcs;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::config::ValMmcs;

type Cap = p3_symmetric::MerkleCap<Val, [Val; 4]>;
type Batch = p3_batch_stark::BatchProof<Config>;
type BatchCommits = p3_batch_stark::BatchCommitments<Cap>;
type BatchValues = p3_batch_stark::BatchOpenedValues<Challenge>;
type LookupValues = p3_batch_stark::proof::OpenedValuesWithLookups<Challenge>;
type Uni = p3_uni_stark::Proof<Config>;
type UniCommits = p3_uni_stark::Commitments<Cap>;
type UniValues = p3_uni_stark::OpenedValues<Challenge>;
type Opening = p3_commit::BatchOpening<Val, ValMmcs>;
type Fri = p3_fri::FriProof<Challenge, profile::ChallengeMmcs, Val, Vec<Opening>>;
type Query = p3_fri::QueryProof<Challenge, profile::ChallengeMmcs, Vec<Opening>>;
type Step = p3_fri::CommitPhaseProofStep<Challenge, profile::ChallengeMmcs>;

// Private to this module tree: arbitrary Deserialize implementations cannot
// enter the admitted path and silently allocate outside its seeds.
pub(super) trait Decode: Sized {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error>;
}

pub(super) struct Seed<'a, T> {
    storage: &'a Storage,
    marker: PhantomData<T>,
}
impl<'a, T> Seed<'a, T> {
    pub(super) fn new(storage: &'a Storage) -> Self {
        Self {
            storage,
            marker: PhantomData,
        }
    }
}
impl<'de, T: Decode> DeserializeSeed<'de> for Seed<'_, T> {
    type Value = T;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        T::decode(d, self.storage)
    }
}

fn next<'de, A: SeqAccess<'de>, T: Decode>(a: &mut A, s: &Storage) -> Result<T, A::Error> {
    a.next_element_seed(Seed::<T>::new(s))?
        .ok_or_else(|| de::Error::custom("missing proof field"))
}

// Only audited allocation-free scalar/array deserializers are delegated to
// serde. Extension-field Deserialize uses a temporary Vec upstream, so it has
// an explicit stack-only seed below instead.
macro_rules! scalar {
    ($($ty:ty),* $(,)?) => {$(
        impl Decode for $ty {
            fn decode<'de, D: Deserializer<'de>>(d: D, _: &Storage) -> Result<Self, D::Error> {
                <$ty>::deserialize(d)
            }
        }
    )*};
}
scalar!(
    (),
    u8,
    usize,
    Val,
    [Val; 3],
    [Val; 4],
    [Val; crate::block_v2::machine::programs::PUBLIC_VALUES],
    [u8; 32]
);

impl<'de, T: Decode> Visitor<'de> for Seed<'_, Vec<T>> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded proof vector")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let count = a
            .size_hint()
            .ok_or_else(|| de::Error::custom("missing proof vector bound"))?;
        if count > super::super::MAX_SEQUENCE {
            return Err(de::Error::custom("proof vector length"));
        }
        let mut values: Vec<T> = self
            .storage
            .reserve(count, false)
            .map_err(|_| de::Error::custom("decoded proof storage allowance"))?;
        for _ in 0..count {
            values.push(next(&mut a, self.storage)?);
        }
        if a.next_element_seed(Seed::<T>::new(self.storage))?.is_some() {
            return Err(de::Error::custom("proof vector overflow"));
        }
        Ok(values)
    }
}
impl<T: Decode> Decode for Vec<T> {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
        d.deserialize_seq(Seed::<Vec<T>>::new(storage))
    }
}

impl<'de, T: Decode> Visitor<'de> for Seed<'_, Option<T>> {
    type Value = Option<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("optional proof field")
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        T::decode(d, self.storage).map(Some)
    }
}
impl<T: Decode> Decode for Option<T> {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
        d.deserialize_option(Seed::<Option<T>>::new(storage))
    }
}

impl<'de, A: Decode, B: Decode> Visitor<'de> for Seed<'_, (A, B)> {
    type Value = (A, B);
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proof pair")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut a: S) -> Result<Self::Value, S::Error> {
        Ok((
            next::<S, A>(&mut a, self.storage)?,
            next::<S, B>(&mut a, self.storage)?,
        ))
    }
}
impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
        d.deserialize_tuple(2, Seed::<(A, B)>::new(storage))
    }
}

macro_rules! structure {
    ($ty:ident, $name:literal, $($field:ident),+ $(,)?) => {
        impl<'de> Visitor<'de> for Seed<'_, $ty> {
            type Value = $ty;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str($name) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                $(let $field = next(&mut a, self.storage)?;)+
                Ok($ty { $($field),+ })
            }
        }
        impl Decode for $ty {
            fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
                d.deserialize_struct($name, &[$(stringify!($field)),+], Seed::<$ty>::new(storage))
            }
        }
    };
}
structure!(NodeProof, "NodeProof", public, proof);
structure!(WalletProof, "WalletProof", chain, public, proof);
structure!(
    Batch,
    "BatchProof",
    commitments,
    opened_values,
    opening_proof,
    lookup_terminals,
    degree_bits
);
structure!(
    BatchCommits,
    "BatchCommitments",
    main,
    permutation,
    quotient_chunks,
    random
);
structure!(BatchValues, "BatchOpenedValues", instances);
structure!(
    LookupValues,
    "OpenedValuesWithLookups",
    base_opened_values,
    permutation_local,
    permutation_next
);
structure!(
    Uni,
    "Proof",
    commitments,
    opened_values,
    opening_proof,
    degree_bits
);
structure!(UniCommits, "Commitments", trace, quotient_chunks, random);
structure!(
    UniValues,
    "OpenedValues",
    trace_local,
    trace_next,
    preprocessed_local,
    preprocessed_next,
    quotient_chunks,
    random
);
structure!(Opening, "BatchOpening", opened_values, opening_proof);
structure!(
    Fri,
    "FriProof",
    commit_phase_commits,
    commit_pow_witnesses,
    query_proofs,
    final_poly,
    query_pow_witness
);
structure!(Query, "QueryProof", input_proof, commit_phase_openings);
structure!(
    Step,
    "CommitPhaseProofStep",
    log_arity,
    sibling_values,
    opening_proof
);

impl<'de> Visitor<'de> for Seed<'_, Cap> {
    type Value = Cap;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MerkleCap")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Cap, A::Error> {
        let roots: Vec<[Val; 4]> = next(&mut a, self.storage)?;
        let (): () = next(&mut a, self.storage)?;
        if !roots.len().is_power_of_two() {
            return Err(de::Error::custom("proof cap length"));
        }
        Ok(Cap::new(roots))
    }
}
impl Decode for Cap {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
        d.deserialize_struct("MerkleCap", &["cap", "_marker"], Seed::<Cap>::new(storage))
    }
}

impl<'de> Visitor<'de> for Seed<'_, Challenge> {
    type Value = Challenge;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExtField")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Challenge, A::Error> {
        let values: [Val; 3] = next(&mut a, self.storage)?;
        let (): () = next(&mut a, self.storage)?;
        Ok(Challenge::new(values))
    }
}
impl Decode for Challenge {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
        d.deserialize_struct(
            "ExtField",
            &["value", "_phantom"],
            Seed::<Challenge>::new(storage),
        )
    }
}

impl Decode for p3_lookup::LookupTerminal<Challenge> {
    fn decode<'de, D: Deserializer<'de>>(d: D, storage: &Storage) -> Result<Self, D::Error> {
        Challenge::decode(d, storage).map(p3_lookup::LookupTerminal)
    }
}
