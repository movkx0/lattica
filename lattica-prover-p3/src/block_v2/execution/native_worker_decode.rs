//! Bootstrap payload limits inside the worker's startup input reservation.
//!
//! The caller's encoded bytes, cap vectors, policy bytes, path, and JSON parser
//! scratch coexist here. Allocator/runtime/stack RSS still needs its own plan.

use super::{Bootstrap, Error, PathBuf, Registry, MAX_BOOTSTRAP_BYTES};
use crate::block_v2::{execution, profile};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::{fmt, marker::PhantomData, mem::size_of};

pub(super) const HOST_BYTES: u64 = 1 << 20;
const CAP_LEN: usize = 1 << profile::CAP_HEIGHT;
// The pinned slice parser borrows ordinary strings and doubles scratch only
// for escapes. Include old/new scratch and bounded error formatting separately
// from the exact output path. This is a payload allowance, not an RSS claim.
const PARSER_BYTES: usize = 4 * MAX_BOOTSTRAP_BYTES;

pub(super) fn layout() -> Result<(), Error> {
    let payload = MAX_BOOTSTRAP_BYTES
        + 12 * CAP_LEN * size_of::<[crate::config::Val; 4]>()
        + execution::policy_context::MAX_BYTES
        + MAX_BOOTSTRAP_BYTES
        + PARSER_BYTES
        + size_of::<Bootstrap>()
        + (8 << 10);
    if size_of::<usize>() != 8
        || size_of::<crate::config::Val>() != 8
        || payload as u64 > HOST_BYTES
        || execution::gpu_admission::ASSIGNMENT_HOST_BYTES + HOST_BYTES
            > execution::worker::typed::storage::INPUT_HOST_BYTES
    {
        return Err("native bootstrap decoding exceeds startup input allowance".into());
    }
    Ok(())
}

#[cfg(any(test, feature = "gpu"))]
pub(super) fn admit(assignment: &serde_json::Value) -> Result<(), Error> {
    layout()?;
    let (peak, _) = execution::worker_budget::resources(assignment)?;
    execution::worker::typed::storage::admit_startup(peak.ram_bytes, peak.threads)
}

struct BoundedVec<T, const LIMIT: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const LIMIT: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for BoundedVisitor<T, LIMIT> {
            type Value = BoundedVec<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a native bootstrap array of at most {LIMIT} elements"
                )
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    if values.len() == LIMIT {
                        return Err(de::Error::custom("native bootstrap array exceeds bound"));
                    }
                    if values.capacity() == 0 {
                        values.try_reserve_exact(LIMIT).map_err(de::Error::custom)?;
                        if values.capacity() != LIMIT {
                            return Err(de::Error::custom("native bootstrap array capacity"));
                        }
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }
        decoder.deserialize_seq(BoundedVisitor::<T, LIMIT>(PhantomData))
    }
}

pub(super) fn registry<'de, D: Deserializer<'de>>(decoder: D) -> Result<Registry<12>, D::Error> {
    // Match Registry's existing field semantics, including ignored extra
    // registry fields. The outer Bootstrap still rejects unknown fields.
    #[derive(Deserialize)]
    struct Fields {
        height: usize,
        caps: [BoundedVec<[crate::config::Val; 4], CAP_LEN>; 12],
    }
    let fields = Fields::deserialize(decoder)?;
    Ok(Registry {
        height: fields.height,
        caps: fields.caps.map(|cap| cap.0),
    })
}

pub(super) fn policy<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    const LIMIT: usize = execution::policy_context::MAX_BYTES;
    BoundedVec::<u8, LIMIT>::deserialize(decoder).map(|value| value.0)
}

pub(super) fn path<'de, D: Deserializer<'de>>(decoder: D) -> Result<PathBuf, D::Error> {
    struct PathVisitor;
    impl Visitor<'_> for PathVisitor {
        type Value = PathBuf;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a bounded native bootstrap path")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<PathBuf, E> {
            if value.len() > MAX_BOOTSTRAP_BYTES {
                return Err(E::custom("native bootstrap path exceeds bound"));
            }
            let mut path = String::new();
            path.try_reserve_exact(value.len()).map_err(E::custom)?;
            if path.capacity() != value.len() {
                return Err(E::custom("native bootstrap path capacity"));
            }
            path.push_str(value);
            Ok(PathBuf::from(path))
        }
    }
    decoder.deserialize_str(PathVisitor)
}
