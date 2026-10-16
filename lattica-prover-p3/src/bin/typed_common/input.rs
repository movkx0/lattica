//! Bounded preparation payload owners. Parser/runtime and wallet verification
//! lifetimes require separate composition; this is not a process RSS bound.
use super::*;
use core::{marker::PhantomData, mem::size_of};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

pub(super) const MAX_PUBLIC: usize =
    if lattica_prover_p3::htlc_air::N_PUBLIC > lattica_prover_p3::joinsplit_air::N_PUBLIC {
        lattica_prover_p3::htlc_air::N_PUBLIC
    } else {
        lattica_prover_p3::joinsplit_air::N_PUBLIC
    };
pub(super) const MAX_TASKS: usize = 2 * commitment::CAPACITY - 1;
const CAP_ROOTS: usize = 1 << profile::CAP_HEIGHT;
// Ten bytes bound each legacy u64 varint and the collection-length varint.
pub(super) const KEY_BYTES: usize = 8 + 10 + CAP_ROOTS * 4 * 10;

pub(super) fn exact<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values.try_reserve_exact(count)?;
    if values.capacity() != count {
        return Err("preparation capacity rounding".into());
    }
    Ok(values)
}

struct RejectExtra;
impl<'de> DeserializeSeed<'de> for RejectExtra {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(de::Error::custom("preparation collection limit"))
    }
}

pub(super) fn bounded<'de, D, T, const LIMIT: usize>(decoder: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Values<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Values<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "at most {N} preparation elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|count| count > N) {
                return Err(de::Error::custom("preparation collection limit"));
            }
            let mut values = exact(N).map_err(de::Error::custom)?;
            while values.len() < N {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            // Reject an extra element before its nested payload can allocate.
            sequence.next_element_seed(RejectExtra)?;
            Ok(values)
        }
    }
    decoder.deserialize_seq(Values::<T, LIMIT>(PhantomData))
}

pub(super) fn statement<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    bounded::<D, u64, MAX_PUBLIC>(d)
}

pub(super) fn transactions<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<Transaction>, D::Error> {
    bounded::<D, Transaction, { commitment::CAPACITY }>(d)
}

pub(super) fn authorizations<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<usize, u64>, D::Error> {
    struct Authorizations;
    impl<'de> Visitor<'de> for Authorizations {
        type Value = BTreeMap<usize, u64>;
        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(
                f,
                "at most {} distinct authorizations",
                commitment::CAPACITY
            )
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            if map
                .size_hint()
                .is_some_and(|count| count > commitment::CAPACITY)
            {
                return Err(de::Error::custom("preparation authorization limit"));
            }
            let mut values = BTreeMap::new();
            while values.len() < commitment::CAPACITY {
                let Some(key) = map.next_key::<usize>()? else {
                    return Ok(values);
                };
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate preparation authorization"));
                }
                let value = map.next_value()?;
                values.insert(key, value);
            }
            map.next_key_seed(RejectExtra)?;
            Ok(values)
        }
    }
    d.deserialize_map(Authorizations)
}

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
struct Key(#[serde(deserialize_with = "cap")] Vec<[Val; 4]>);

fn cap<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<[Val; 4]>, D::Error> {
    bounded::<D, [Val; 4], CAP_ROOTS>(d)
}

pub(super) fn key(path: &Path) -> Result<Vec<[Val; 4]>, Error> {
    let bytes = read_bytes(path, KEY_BYTES)?;
    if !bytes.starts_with(KEY_MAGIC) {
        return Err("mixed key envelope".into());
    }
    let key: Key = codec::decode(&bytes[8..])?;
    if key.0.len() != CAP_ROOTS {
        return Err("typed key shape".into());
    }
    Ok(key.0)
}

pub(super) fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("artifact must be a regular nonsymlink file".into());
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > u64::try_from(limit)? {
        return Err("artifact size/type".into());
    }
    read_sized(&mut file, usize::try_from(metadata.len())?)
}

pub(super) fn read_sized(reader: &mut impl Read, count: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = exact(count)?;
    bytes.resize(count, 0);
    reader.read_exact(&mut bytes)?;
    let mut extra = [0u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err("artifact changed size during read".into()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(bytes)
}

pub(super) struct Storage {
    body_bytes: usize,
    expected_bytes: usize,
    entry_bytes: usize,
    task_bytes: usize,
    read_bytes: usize,
    key_canonical_bytes: usize,
}

impl Storage {
    pub(super) fn new() -> Result<Self, Error> {
        use lattica_prover_p3::block_v2::execution::selection::PreparationStorage;
        Ok(Self {
            body_bytes: size_of::<Body>()
                + commitment::CAPACITY * (size_of::<Transaction>() + MAX_PUBLIC * size_of::<u64>()),
            expected_bytes: size_of::<Expected>()
                + PreparationStorage::authorization_map_backing_bytes()?,
            entry_bytes: size_of::<Vec<Entry>>() + commitment::CAPACITY * size_of::<Entry>(),
            task_bytes: size_of::<Vec<Task>>() + MAX_TASKS * size_of::<Task>(),
            read_bytes: size_of::<Vec<u8>>()
                + profile::MAX_PROOF_BYTES.max(JSON_LIMIT).max(KEY_BYTES),
            key_canonical_bytes: size_of::<Vec<u8>>() + KEY_BYTES,
        })
    }
    pub(super) fn total_bytes(&self) -> Result<usize, Error> {
        [
            self.body_bytes,
            self.expected_bytes,
            self.entry_bytes,
            self.task_bytes,
            self.read_bytes,
            self.key_canonical_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes)
                .ok_or_else(|| "preparation ingress overflow".into())
        })
    }
    pub(super) fn print(&self, prefix: &str) -> Result<(), Error> {
        println!(
            "{prefix} body_bytes={} expected_bytes={} entry_bytes={} task_bytes={} read_bytes={} key_canonical_bytes={} total_bytes={}",
            self.body_bytes,
            self.expected_bytes,
            self.entry_bytes,
            self.task_bytes,
            self.read_bytes,
            self.key_canonical_bytes,
            self.total_bytes()?
        );
        Ok(())
    }
}
