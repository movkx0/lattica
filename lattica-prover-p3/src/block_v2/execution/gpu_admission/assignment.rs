//! Bounded assignment decoding before Rayon or device initialization.
//!
//! The quota charges cumulative requested payload, including replacement
//! buffers and duplicate object fields. It is deliberately conservative. Parser
//! scratch, encoded input and fixed decoder metadata have a separate envelope;
//! allocator overhead, caller/environment ownership and complete RSS are separate.

use super::{Error, Value, MAX_ASSIGNMENT_BYTES};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Map;
use std::fmt;
use std::io::{ErrorKind, Read};

pub(super) const HOST_BYTES: u64 = 48 << 20;
const DECODED_BYTES: usize = 32 << 20;
const PARSER_BYTES: usize = 8 << 20;
// On the qualified 64-bit layout, a BTree node holds at most 11 String/Value
// pairs plus 12 edges and metadata, below 1 KiB. Charge two KiB per incoming
// entry, including duplicates, before insertion. This covers splits/root growth
// conservatively without treating len * size_of(Value) as the map's backing.
const MAP_ENTRY_BYTES: usize = 2 << 10;

pub(super) fn admit_host(bytes: u64) -> Result<(), Error> {
    if bytes < HOST_BYTES {
        return Err("worker RAM below assignment decoding allowance".into());
    }
    Ok(())
}

fn layout() -> Result<(), Error> {
    if DECODED_BYTES as u64 + MAX_ASSIGNMENT_BYTES + 1 + PARSER_BYTES as u64 > HOST_BYTES
        || std::mem::size_of::<usize>() != 8
        || std::mem::size_of::<String>() != 24
        || std::mem::size_of::<Value>() != 32
        || std::mem::size_of::<Map<String, Value>>() != 24
    {
        return Err("assignment decoder requires qualified JSON container layout".into());
    }
    Ok(())
}

fn read_bytes(mut reader: impl Read) -> Result<Vec<u8>, Error> {
    let capacity = MAX_ASSIGNMENT_BYTES as usize + 1;
    let mut bytes = super::super::bounded_io::byte_capacity(capacity, capacity)?;
    bytes.resize(capacity, 0);
    let mut used = 0;
    loop {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => {
                used += count;
                if used == capacity {
                    return Err("worker assignment exceeds 1 MiB".into());
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bytes.truncate(used);
    Ok(bytes)
}

pub(super) fn read(reader: impl Read) -> Result<Value, Error> {
    layout()?;
    let bytes = read_bytes(reader)?;
    let (assignment, charged) = decode(&bytes, DECODED_BYTES)?;
    if !assignment.is_object() {
        return Err("worker assignment must be an object".into());
    }
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!("bounded_gpu_assignment encoded_bytes={} charged_decoded_bytes={charged} decoded_limit_bytes={DECODED_BYTES} host_allowance_bytes={HOST_BYTES}", bytes.len());
    }
    Ok(assignment)
}

fn decode(bytes: &[u8], limit: usize) -> Result<(Value, usize), Error> {
    layout()?;
    let mut budget = Budget { charged: 0, limit };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(&mut budget).deserialize(&mut decoder)?;
    decoder.end()?;
    Ok((value, budget.charged))
}

struct Budget {
    charged: usize,
    limit: usize,
}

impl Budget {
    fn charge<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.charged = self
            .charged
            .checked_add(bytes)
            .filter(|&total| total <= self.limit)
            .ok_or_else(|| E::custom("worker assignment decoded payload allowance"))?;
        Ok(())
    }

    fn string<E: de::Error>(&mut self, value: &str) -> Result<String, E> {
        self.charge::<E>(value.len())?;
        let mut result = String::new();
        result.try_reserve_exact(value.len()).map_err(E::custom)?;
        if result.capacity() != value.len() {
            return Err(E::custom("worker assignment string capacity"));
        }
        result.push_str(value);
        Ok(result)
    }
}

struct Seed<'a>(&'a mut Budget);

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bounded JSON assignment value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite worker assignment number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        self.0.string(value).map(Value::String)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values: Vec<Value> = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed(&mut *self.0))? {
            if values.len() == values.capacity() {
                let capacity = values
                    .capacity()
                    .checked_mul(2)
                    .map(|n| n.max(4))
                    .ok_or_else(|| de::Error::custom("worker assignment array capacity"))?;
                let bytes = capacity
                    .checked_mul(std::mem::size_of::<Value>())
                    .ok_or_else(|| de::Error::custom("worker assignment array bytes"))?;
                self.0.charge::<A::Error>(bytes)?;
                values
                    .try_reserve_exact(capacity - values.len())
                    .map_err(de::Error::custom)?;
                if values.capacity() != capacity {
                    return Err(de::Error::custom("worker assignment array capacity"));
                }
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key_seed(Key(&mut *self.0))? {
            self.0.charge::<A::Error>(MAP_ENTRY_BYTES)?;
            let value = object.next_value_seed(Seed(&mut *self.0))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct Key<'a>(&'a mut Budget);

impl<'de> DeserializeSeed<'de> for Key<'_> {
    type Value = String;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<String, D::Error> {
        decoder.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for Key<'_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bounded JSON assignment key")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        self.0.string(value)
    }
}

#[cfg(test)]
#[path = "assignment_tests.rs"]
mod tests;
