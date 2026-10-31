//! Concrete allocation-explicit seeds for the quadratic P3 0.6.1 proof.
//! The closed trait prevents arbitrary Deserialize implementations from
//! entering the path with hidden Vec allocations. Named fields pin the schema.
use super::{Error, Storage};
use crate::note_gpu::{Cap, Challenge, Fri, Opening, Proof, Query, Step, Val};
use serde::{
    de::{self, DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{fmt, marker::PhantomData};

type Commits = p3_uni_stark::Commitments<Cap>;
type Values = p3_uni_stark::OpenedValues<Challenge>;

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
        self.storage
            .item()
            .map_err(|_| de::Error::custom("note proof item allowance"))?;
        T::decode(d, self.storage)
    }
}

fn next<'de, A: SeqAccess<'de>, T: Decode>(a: &mut A, s: &Storage) -> Result<T, A::Error> {
    a.next_element_seed(Seed::<T>::new(s))?
        .ok_or_else(|| de::Error::custom("missing note proof field"))
}

macro_rules! scalar {
    ($($ty:ty),* $(,)?) => {$(
        impl Decode for $ty {
            fn decode<'de, D: Deserializer<'de>>(d: D, _: &Storage) -> Result<Self, D::Error> {
                <$ty>::deserialize(d)
            }
        }
    )*};
}
// Goldilocks' pinned Deserialize rejects out-of-field encodings. Fixed arrays
// deserialize on the stack. Quadratic extension values use the explicit seed.
scalar!((), u8, usize, Val, [Val; 2], [Val; 4]);

impl<'de, T: Decode> Visitor<'de> for Seed<'_, Vec<T>> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded note proof vector")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let count = a
            .size_hint()
            .ok_or_else(|| de::Error::custom("missing vector length"))?;
        if count > 256 {
            self.storage.reject(Error::Geometry);
            return Err(de::Error::custom("note proof vector length"));
        }
        let mut values = self
            .storage
            .reserve::<T>(count, false)
            .map_err(|_| de::Error::custom("note proof vector allowance"))?;
        for _ in 0..count {
            values.push(next(&mut a, self.storage)?);
        }
        if a.next_element_seed(Seed::<T>::new(self.storage))?.is_some() {
            return Err(de::Error::custom("note proof vector overflow"));
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
        f.write_str("optional note proof field")
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        Seed::<T>::new(self.storage).deserialize(d).map(Some)
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
        f.write_str("note proof pair")
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
structure!(
    Proof,
    "Proof",
    commitments,
    opened_values,
    opening_proof,
    degree_bits
);
structure!(Commits, "Commitments", trace, quotient_chunks, random);
structure!(
    Values,
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
            return Err(de::Error::custom("note proof cap shape"));
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
        let values: [Val; 2] = next(&mut a, self.storage)?;
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
