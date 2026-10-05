//! Bounded, canonical research-artifact decoding. This is not consensus activation.
//! Length hints are checked BEFORE serde can reserve a Vec from untrusted lengths.
use super::{profile, recursive::NodeProof};
use serde::{
    de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::cell::Cell;

mod fixed_u64;

const LEGACY_NODE_MAGIC: &[u8; 8] = b"LBV2RC01";
const FIXED_NODE_MAGIC: &[u8; 8] = b"LBV2RC02";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Legacy,
    FixedU64,
}
impl Encoding {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Legacy => LEGACY_NODE_MAGIC,
            Self::FixedU64 => FIXED_NODE_MAGIC,
        }
    }
}
const NODE_ENCODING: Encoding = if cfg!(feature = "block-v2-wide-lanes") {
    Encoding::FixedU64
} else {
    Encoding::Legacy
};
/// Research-only envelope selected by the locally trusted build/profile.
/// Never sniff an untrusted header to select another verifier or profile.
pub const NODE_MAGIC: &[u8; 8] = NODE_ENCODING.magic();
const MAX_SEQUENCE: usize = 256;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 1 << 20;

struct Guard<'a, D> {
    inner: D,
    depth: usize,
    items: &'a Cell<usize>,
    encoding: Encoding,
}
struct Visit<'a, V> {
    inner: V,
    depth: usize,
    items: &'a Cell<usize>,
    encoding: Encoding,
    // Tuple/struct arity is trusted schema, unlike untrusted sequence lengths.
    // Postcard may withhold its size hint when zero-byte fields remain.
    sequence_len: Option<usize>,
}
struct Seed<'a, S> {
    inner: S,
    depth: usize,
    items: &'a Cell<usize>,
    encoding: Encoding,
}

impl<'a, D> Guard<'a, D> {
    fn visitor<'de, V>(&self, visitor: V) -> Result<Visit<'a, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Visitor<'de>,
    {
        if self.depth >= MAX_DEPTH {
            return Err(de::Error::custom("artifact nesting limit"));
        }
        Ok(Visit {
            inner: visitor,
            depth: self.depth + 1,
            items: self.items,
            encoding: self.encoding,
            sequence_len: None,
        })
    }
}

macro_rules! scalar {
    ($($method:ident),*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
            self.inner.$method(visitor)
        }
    )*};
}
macro_rules! compound {
    ($($method:ident),*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
            let visitor = self.visitor(visitor)?;
            self.inner.$method(visitor)
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Guard<'_, D> {
    type Error = D::Error;
    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        match self.encoding {
            Encoding::Legacy => self.inner.deserialize_u64(visitor),
            Encoding::FixedU64 => {
                // These eight bytes are one scalar, not eight logical items.
                // The fixed array allocates no heap and cannot recurse.
                let bytes = <[u8; 8]>::deserialize(self.inner)?;
                visitor.visit_u64(u64::from_le_bytes(bytes))
            }
        }
    }
    scalar!(
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier
    );
    compound!(
        deserialize_any,
        deserialize_option,
        deserialize_seq,
        deserialize_map,
        deserialize_ignored_any
    );
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, D::Error> {
        self.inner.deserialize_unit_struct(name, v)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, D::Error> {
        let v = self.visitor(v)?;
        self.inner.deserialize_newtype_struct(name, v)
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, D::Error> {
        if len > MAX_SEQUENCE {
            return Err(de::Error::custom("artifact tuple limit"));
        }
        let mut v = self.visitor(v)?;
        v.sequence_len = Some(len);
        self.inner.deserialize_tuple(len, v)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value, D::Error> {
        if len > MAX_SEQUENCE {
            return Err(de::Error::custom("artifact tuple limit"));
        }
        let mut v = self.visitor(v)?;
        v.sequence_len = Some(len);
        self.inner.deserialize_tuple_struct(name, len, v)
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, D::Error> {
        let mut v = self.visitor(v)?;
        v.sequence_len = Some(fields.len());
        self.inner.deserialize_struct(name, fields, v)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, D::Error> {
        let v = self.visitor(v)?;
        self.inner.deserialize_enum(name, variants, v)
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

fn reserve<E: de::Error>(items: &Cell<usize>, hint: Option<usize>) -> Result<(), E> {
    let count = hint.ok_or_else(|| E::custom("missing artifact sequence bound"))?;
    if count > MAX_SEQUENCE || count > items.get() {
        return Err(E::custom("artifact sequence budget"));
    }
    items.set(items.get() - count);
    Ok(())
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Visit<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(f)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Guard {
            inner: d,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Guard {
            inner: d,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, a: A) -> Result<Self::Value, A::Error> {
        reserve(self.items, self.sequence_len.or_else(|| a.size_hint()))?;
        self.inner.visit_seq(Access {
            inner: a,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, a: A) -> Result<Self::Value, A::Error> {
        reserve(self.items, a.size_hint())?;
        self.inner.visit_map(Access {
            inner: a,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(self, a: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Access {
            inner: a,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Guard {
            inner: d,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
}
struct Access<'a, A> {
    inner: A,
    depth: usize,
    items: &'a Cell<usize>,
    encoding: Encoding,
}
impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Access<'_, A> {
    type Error = A::Error;
    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.inner.next_element_seed(Seed {
            inner: seed,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for Access<'_, A> {
    type Error = A::Error;
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.inner.next_key_seed(Seed {
            inner: seed,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.inner.next_value_seed(Seed {
            inner: seed,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}
impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de> for Access<'a, A> {
    type Error = A::Error;
    type Variant = Access<'a, A::Variant>;
    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), A::Error> {
        let (value, variant) = self.inner.variant_seed(Seed {
            inner: seed,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })?;
        Ok((
            value,
            Access {
                inner: variant,
                depth: self.depth,
                items: self.items,
                encoding: self.encoding,
            },
        ))
    }
}
impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Access<'_, A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, A::Error> {
        self.inner.newtype_variant_seed(Seed {
            inner: seed,
            depth: self.depth,
            items: self.items,
            encoding: self.encoding,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, A::Error> {
        if len > MAX_SEQUENCE || self.depth >= MAX_DEPTH {
            return Err(de::Error::custom("artifact variant budget"));
        }
        self.inner.tuple_variant(
            len,
            Visit {
                inner: v,
                depth: self.depth + 1,
                items: self.items,
                encoding: self.encoding,
                sequence_len: Some(len),
            },
        )
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(de::Error::custom("artifact variant nesting"));
        }
        self.inner.struct_variant(
            fields,
            Visit {
                inner: v,
                depth: self.depth + 1,
                items: self.items,
                encoding: self.encoding,
                sequence_len: Some(fields.len()),
            },
        )
    }
}

fn encode_payload<'a, T: Serialize + ?Sized>(
    value: &T,
    encoding: Encoding,
    output: &'a mut [u8],
) -> Result<&'a mut [u8], postcard::Error> {
    match encoding {
        Encoding::Legacy => postcard::to_slice(value, output),
        Encoding::FixedU64 => postcard::to_slice(&fixed_u64::Value(value), output),
    }
}

fn decode_payload<'de, T: Deserialize<'de> + Serialize>(
    bytes: &'de [u8],
    encoding: Encoding,
) -> Result<T, postcard::Error> {
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err(postcard::Error::SerdeDeCustom);
    }
    let mut d = postcard::Deserializer::from_bytes(bytes);
    let items = Cell::new(MAX_ITEMS);
    let value = T::deserialize(Guard {
        inner: &mut d,
        depth: 0,
        items: &items,
        encoding,
    })?;
    if !d.finalize()?.is_empty() {
        return Err(postcard::Error::SerdeDeCustom);
    }
    // Re-encode into an input-sized buffer: canonicality cannot allocate an
    // unbounded second serialization from attacker-controlled length hints.
    let mut canonical = vec![0; bytes.len()];
    if encode_payload(&value, encoding, &mut canonical)? != bytes {
        return Err(postcard::Error::SerdeDeCustom);
    }
    Ok(value)
}

/// Legacy bounded Postcard decoding, including wallet-proof artifacts.
/// This always keeps the original variable-length integer representation.
pub fn decode<'de, T: Deserialize<'de> + Serialize>(
    bytes: &'de [u8],
) -> Result<T, postcard::Error> {
    decode_payload(bytes, Encoding::Legacy)
}

fn decode_node_with_encoding(
    bytes: &[u8],
    encoding: Encoding,
) -> Result<NodeProof, postcard::Error> {
    if bytes.len() > profile::MAX_PROOF_BYTES || !bytes.starts_with(encoding.magic()) {
        return Err(postcard::Error::SerdeDeCustom);
    }
    decode_payload(&bytes[8..], encoding)
}

/// Encode the selected research node format into a fixed-capacity buffer.
/// The 2 MiB cap includes the header; it is enforced while serializing.
pub fn encode_node(node: &NodeProof) -> Result<Vec<u8>, postcard::Error> {
    let mut bytes = vec![0; profile::MAX_PROOF_BYTES];
    bytes[..8].copy_from_slice(NODE_MAGIC);
    let payload_len = encode_payload(node, NODE_ENCODING, &mut bytes[8..])?.len();
    bytes.truncate(8 + payload_len);
    Ok(bytes)
}

pub fn decode_node(bytes: &[u8]) -> Result<NodeProof, postcard::Error> {
    decode_node_with_encoding(bytes, NODE_ENCODING)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::machine::{programs, verifier::template};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks as Val;

    #[test]
    fn full_recursive_shape_round_trips_but_malformed_encodings_fail() {
        // Shape-only data is deliberately not a cryptographic proof.
        let air = programs::shape(1 << 19).unwrap();
        let node = NodeProof {
            public: [Val::ZERO; programs::PUBLIC_VALUES],
            proof: template::batch(&air).unwrap(),
        };
        let mut bytes = encode_node(&node).unwrap();
        let decoded = decode_node(&bytes).unwrap();
        assert_eq!(encode_node(&decoded).unwrap(), bytes);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_node(&trailing).is_err());
        bytes[0] ^= 1;
        assert!(decode_node(&bytes).is_err());
        assert!(decode_node(&vec![0; profile::MAX_PROOF_BYTES + 1]).is_err());
        assert!(decode::<Val>(
            &postcard::to_allocvec(&crate::block_v2::commitment::MODULUS).unwrap()
        )
        .is_err());
    }

    fn payload<T: Serialize>(value: &T, encoding: Encoding) -> Vec<u8> {
        let mut bytes = vec![0; profile::MAX_PROOF_BYTES];
        let len = encode_payload(value, encoding, &mut bytes).unwrap().len();
        bytes.truncate(len);
        bytes
    }

    #[test]
    fn huge_length_is_rejected_before_the_value_visitor_can_allocate() {
        struct AllocationVisitor<'a>(&'a Cell<bool>);
        impl<'de> Visitor<'de> for AllocationVisitor<'_> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a sequence")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<(), A::Error> {
                self.0.set(true);
                Ok(())
            }
        }
        // Sequence framing remains Postcard varints in BOTH formats.
        let bytes = postcard::to_allocvec(&usize::MAX).unwrap();
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let entered = Cell::new(false);
            let items = Cell::new(MAX_ITEMS);
            let mut d = postcard::Deserializer::from_bytes(&bytes);
            assert!(Guard {
                inner: &mut d,
                depth: 0,
                items: &items,
                encoding,
            }
            .deserialize_seq(AllocationVisitor(&entered))
            .is_err());
            assert!(!entered.get());
            let nested = payload(&vec![vec![0u64; MAX_SEQUENCE + 1]], encoding);
            assert!(decode_payload::<Vec<Vec<u64>>>(&nested, encoding).is_err());
        }
    }

    #[test]
    fn nested_values_are_depth_bounded() {
        #[derive(Deserialize, Serialize)]
        struct Nested(Option<Box<Nested>>);
        let mut value = Nested(None);
        for _ in 0..MAX_DEPTH {
            value = Nested(Some(Box::new(value)));
        }
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            assert!(decode_payload::<Nested>(&payload(&value, encoding), encoding).is_err());
        }
    }

    #[test]
    fn aggregate_budget_applies_across_individually_small_sequences() {
        let values = vec![vec![vec![0u8; 17]; MAX_SEQUENCE]; MAX_SEQUENCE];
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let bytes = payload(&values, encoding);
            assert!(bytes.len() < profile::MAX_PROOF_BYTES);
            assert!(decode_payload::<Vec<Vec<Vec<u8>>>>(&bytes, encoding).is_err());
        }
    }

    #[test]
    fn noncanonical_and_truncated_varints_are_rejected() {
        assert!(decode::<u64>(&[0x80, 0]).is_err());
        assert!(decode::<u64>(&[0x80]).is_err());
        assert!(decode::<Vec<u64>>(&[2, 1]).is_err());
        assert_eq!(decode::<u64>(&[0]).unwrap(), 0);
    }

    #[test]
    fn a_real_wallet_proof_also_fits_the_bounded_decoder() {
        let wallet = crate::block_v2::recursive::demo_wallet(0).unwrap();
        let bytes = postcard::to_allocvec(&wallet).unwrap();
        let decoded: crate::block_v2::recursive::WalletProof = decode(&bytes).unwrap();
        assert_eq!(postcard::to_allocvec(&decoded).unwrap(), bytes);
    }

    fn maximum_value_node(height: usize) -> NodeProof {
        use p3_field::BasedVectorSpace;
        use p3_symmetric::MerkleCap;
        let v = Val::from_u64(crate::block_v2::commitment::MODULUS - 1);
        let c = profile::Challenge::from_basis_coefficients_slice(&[v; 3]).unwrap();
        let mut node = NodeProof {
            public: [v; programs::PUBLIC_VALUES],
            proof: template::batch(&programs::shape(height).unwrap()).unwrap(),
        };
        let cap = |old: &mut MerkleCap<Val, [Val; 4]>| {
            *old = MerkleCap::new(vec![[v; 4]; old.roots().len()]);
        };
        let opening = |old: &mut (Vec<Vec<Val>>, Vec<[Val; 4]>)| {
            for salt in &mut old.0 {
                salt.fill(v);
            }
            old.1.fill([v; 4]);
        };
        let p = &mut node.proof;
        cap(&mut p.commitments.main);
        cap(&mut p.commitments.quotient_chunks);
        cap(p.commitments.permutation.as_mut().unwrap());
        cap(p.commitments.random.as_mut().unwrap());
        for instance in &mut p.opened_values.instances {
            let values = &mut instance.base_opened_values;
            values.trace_local.fill(c);
            for values in [
                &mut values.trace_next,
                &mut values.preprocessed_local,
                &mut values.preprocessed_next,
                &mut values.random,
            ]
            .into_iter()
            .flatten()
            {
                values.fill(c);
            }
            for values in &mut values.quotient_chunks {
                values.fill(c);
            }
            instance.permutation_local.fill(c);
            instance.permutation_next.fill(c);
        }
        for round in &mut p.opening_proof.0 {
            for matrix in round {
                for point in matrix {
                    point.fill(c);
                }
            }
        }
        let fri = &mut p.opening_proof.1;
        for commitment in &mut fri.commit_phase_commits {
            cap(commitment);
        }
        fri.commit_pow_witnesses.fill(v);
        fri.query_pow_witness = v;
        fri.final_poly.fill(c);
        for query in &mut fri.query_proofs {
            for input in &mut query.input_proof {
                for row in &mut input.opened_values {
                    row.fill(v);
                }
                opening(&mut input.opening_proof);
            }
            for step in &mut query.commit_phase_openings {
                step.sibling_values.fill(c);
                opening(&mut step.opening_proof);
            }
        }
        for terminal in p.lookup_terminals.iter_mut().flatten() {
            terminal.0 = c;
        }
        // A serialization bound only: these intentionally inconsistent values are
        // NOT a proof, a valid statement, or a substitute for actual verification.
        node
    }

    #[test]
    fn common_height_worst_case_field_encoding_fits_the_envelope() {
        // Bound serialization at the largest height admitted by the same
        // retained-LDE gate used by recursive::common_height. This does not
        // claim that recursive compilation closes there or that peak RAM fits.
        // The default layout still admits its historical 524288-row height;
        // the wider layout must not inherit that unsupported geometry.
        use crate::block_v2::machine::analysis;
        let mut height = 1 << 16;
        analysis::analyze(&programs::shape(height).unwrap())
            .unwrap()
            .check_ram_lower_bound()
            .unwrap();
        loop {
            let next = height * 2;
            let a = analysis::analyze(&programs::shape(next).unwrap()).unwrap();
            if a.check_ram_lower_bound().is_err() {
                break;
            }
            height = next;
            assert!(height <= 1 << 21);
        }
        #[cfg(not(feature = "block-v2-wide-lanes"))]
        assert_eq!(height, 1 << 19);
        let bytes = encode_node(&maximum_value_node(height)).unwrap();
        eprintln!(
            "worst_case_common_height_envelope_bytes={} retained_lde_admitted_height={height} recursive_closure_proved=false",
            bytes.len()
        );
        assert!(bytes.len() <= profile::MAX_PROOF_BYTES);
        assert!(decode_node(&bytes).is_ok());
    }

    #[cfg(feature = "block-v2-wide-lanes")]
    #[test]
    fn wide_legacy_full_height_template_exceeds_envelope_and_is_rejected() {
        // Preserve the failed LEGACY envelope explicitly. Compact encoding may
        // fit at this height, but that cannot waive the retained-LDE RAM gate.
        let node = maximum_value_node(1 << 19);
        let mut bytes = LEGACY_NODE_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(&node).unwrap());
        eprintln!("rejected_legacy_full_height_envelope_bytes={}", bytes.len());
        assert!(bytes.len() > profile::MAX_PROOF_BYTES);
        assert!(decode_node_with_encoding(&bytes, Encoding::Legacy).is_err());
        assert!(decode_node(&bytes).is_err());
        assert!(
            crate::block_v2::machine::analysis::analyze(&programs::shape(1 << 19).unwrap())
                .unwrap()
                .check_ram_lower_bound()
                .is_err()
        );
    }
    #[test]
    fn fixed_u64_golden_little_endian_words_and_legacy_bytes() {
        for word in [0, 1, 127, 128, 0x0102_0304_0506_0708, u64::MAX] {
            let bytes = payload(&word, Encoding::FixedU64);
            assert_eq!(bytes, word.to_le_bytes());
            assert_eq!(
                decode_payload::<u64>(&bytes, Encoding::FixedU64).unwrap(),
                word
            );
            assert_eq!(
                payload(&word, Encoding::Legacy),
                postcard::to_allocvec(&word).unwrap()
            );
            for len in 0..8 {
                assert!(decode_payload::<u64>(&bytes[..len], Encoding::FixedU64).is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(decode_payload::<u64>(&trailing, Encoding::FixedU64).is_err());
        }
        // Length framing is still a one-byte varint; the two words are fixed.
        assert_eq!(
            payload(&vec![1u64, 128], Encoding::FixedU64),
            vec![2, 1, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn nested_serde_forms_round_trip_in_both_encodings() {
        use std::collections::BTreeMap;
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Word(u64);
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Pair(u64, Option<Word>);
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Unit;
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Kind {
            Unit,
            New(Word),
            Tuple(u64, Option<u64>),
            Struct { word: u64, words: Vec<u64> },
        }
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Composite {
            words: [u64; 3],
            pair: Pair,
            kinds: Vec<Kind>,
            map: BTreeMap<u64, Vec<Word>>,
            tuple: (u64, u32, i64, bool, String),
            units: ((), Unit),
        }
        let value = Composite {
            words: [0, 128, u64::MAX],
            pair: Pair(17, Some(Word(0x0102_0304_0506_0708))),
            kinds: vec![
                Kind::Unit,
                Kind::New(Word(u64::MAX)),
                Kind::Tuple(99, None),
                Kind::Tuple(100, Some(101)),
                Kind::Struct {
                    word: 2,
                    words: vec![3, u64::MAX],
                },
            ],
            map: BTreeMap::from([(u64::MAX, vec![Word(0), Word(u64::MAX)])]),
            tuple: (u64::MAX, 42, -17, true, "canonical".into()),
            units: ((), Unit),
        };
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let bytes = payload(&value, encoding);
            assert_eq!(
                decode_payload::<Composite>(&bytes, encoding)
                    .unwrap_or_else(|err| panic!("composite {encoding:?}: {err:?}")),
                value
            );
        }
    }

    #[test]
    fn schema_bounded_zero_byte_tuple_fields_round_trip() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Unit;
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let bytes = payload(&((), Unit), encoding);
            assert!(bytes.is_empty());
            assert_eq!(
                decode_payload::<((), Unit)>(&bytes, encoding).unwrap(),
                ((), Unit)
            );
        }
    }

    #[test]
    fn fixed_encoding_rejects_noncanonical_fields_and_length_varints() {
        for word in [crate::block_v2::commitment::MODULUS, u64::MAX] {
            assert!(decode_payload::<Val>(&word.to_le_bytes(), Encoding::FixedU64).is_err());
        }
        let mut noncanonical_length = vec![0x81, 0x00];
        noncanonical_length.extend(1u64.to_le_bytes());
        assert!(decode_payload::<Vec<u64>>(&noncanonical_length, Encoding::FixedU64).is_err());
        let mut truncated = vec![2];
        truncated.extend(1u64.to_le_bytes());
        assert!(decode_payload::<Vec<u64>>(&truncated, Encoding::FixedU64).is_err());
    }

    #[test]
    fn node_header_is_selected_locally_and_mixed_encodings_are_rejected() {
        let node = NodeProof {
            public: [Val::ZERO; programs::PUBLIC_VALUES],
            proof: template::batch(&programs::shape(1 << 18).unwrap()).unwrap(),
        };
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let mut bytes = encoding.magic().to_vec();
            bytes.extend(payload(&node, encoding));
            assert!(decode_node_with_encoding(&bytes, encoding).is_ok());
            assert_eq!(decode_node(&bytes).is_ok(), encoding == NODE_ENCODING);
            let other = if encoding == Encoding::Legacy {
                Encoding::FixedU64
            } else {
                Encoding::Legacy
            };
            assert!(decode_node_with_encoding(&bytes, other).is_err());
            // Even relabeling the payload does not make another schema valid.
            bytes[..8].copy_from_slice(other.magic());
            assert!(decode_node_with_encoding(&bytes, other).is_err());
        }
        for header in [b"LBV2RC00", b"LBV2RC03", b"LBV2WL02"] {
            assert!(decode_node(header).is_err());
        }
    }

    #[test]
    fn encoder_enforces_total_envelope_limit_while_serializing() {
        let mut node = maximum_value_node(1 << 18);
        // Invalid in-memory shape: the encoder must still stop at its fixed
        // output capacity, without materializing an unbounded serialization.
        node.proof.opening_proof.1.final_poly = vec![profile::Challenge::ONE; 100_000];
        assert!(encode_node(&node).is_err());
    }

    #[test]
    fn real_small_proof_survives_codec_and_preserves_native_rejection() {
        use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir, ProgramBuilder};
        let mut b = ProgramBuilder::new(programs::PUBLIC_VALUES).unwrap();
        for i in 0..programs::PUBLIC_VALUES {
            let p = b.public(i).unwrap();
            let w = b.input();
            b.assert_equal(p, w);
        }
        let registered =
            RegisteredProgram::new(MachineAir::new(b.finish(Some(32)).unwrap())).unwrap();
        let public = core::array::from_fn(|i| Val::from_usize(i + 1));
        let node = NodeProof {
            public,
            proof: registered.prove(&public, &public).unwrap(),
        };
        let verifier = registered.verifier();
        drop(registered);
        let bytes = encode_node(&node).unwrap();
        let mut decoded = decode_node(&bytes).unwrap();
        verifier.verify(&decoded.proof, &decoded.public).unwrap();
        assert_eq!(encode_node(&decoded).unwrap(), bytes);
        decoded.public[0] += Val::ONE;
        assert!(verifier.verify(&decoded.proof, &decoded.public).is_err());
    }
}
