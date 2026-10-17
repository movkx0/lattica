//! Count the established encoding without allocating a temporary output buffer.

use super::{fixed_u64, profile, Encoding, NodeProof, Serialize, NODE_ENCODING};
use postcard::{ser_flavors::Flavor, Error};

struct BoundedSize {
    bytes: usize,
    limit: usize,
}

impl BoundedSize {
    fn add(&mut self, bytes: usize) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|size| *size <= self.limit)
            .ok_or(Error::SerializeBufferFull)?;
        Ok(())
    }
}

impl Flavor for BoundedSize {
    type Output = usize;

    fn try_push(&mut self, _: u8) -> Result<(), Error> {
        self.add(1)
    }

    fn try_extend(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.add(bytes.len())
    }

    fn finalize(self) -> Result<usize, Error> {
        Ok(self.bytes)
    }
}

fn encoded_len<T: Serialize + ?Sized>(
    value: &T,
    encoding: Encoding,
    limit: usize,
) -> Result<usize, Error> {
    let mut size = BoundedSize { bytes: 0, limit };
    size.add(encoding.magic().len())?;
    match encoding {
        Encoding::Legacy => postcard::serialize_with_flavor(value, size),
        Encoding::FixedU64 => postcard::serialize_with_flavor(&fixed_u64::Value(value), size),
    }
}

/// Includes the same header and enforces the same cap as `encode_node`.
pub(crate) fn encoded_node_len(node: &NodeProof) -> Result<usize, Error> {
    encoded_len(node, NODE_ENCODING, profile::MAX_PROOF_BYTES)
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::block_v2::machine::{programs, verifier::template};
    use crate::spill_alloc::allocation_requests::measure;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks as Val;

    #[test]
    fn counts_match_both_wire_encodings_without_allocation() {
        let node = NodeProof {
            public: [Val::ZERO; programs::PUBLIC_VALUES],
            proof: template::batch(&programs::shape(1 << 19).unwrap()).unwrap(),
        };
        let mut output = vec![0; profile::MAX_PROOF_BYTES];
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let expected = super::super::encode_payload(&node, encoding, &mut output[8..])
                .unwrap()
                .len()
                + 8;
            let (length, allocations) =
                measure(|| encoded_len(&node, encoding, profile::MAX_PROOF_BYTES).unwrap());
            assert_eq!(length, expected);
            assert_eq!(allocations.calls, 0);
            assert_eq!(allocations.bytes, 0);
            assert!(!allocations.overflow);
            assert_eq!(encoded_len(&node, encoding, length).unwrap(), expected);
            assert_eq!(
                encoded_len(&node, encoding, length - 1),
                Err(Error::SerializeBufferFull)
            );
            eprintln!(
                "recursive_size_count encoding={encoding:?} bytes={length} allocation_calls=0"
            );
        }
        assert_eq!(
            encoded_node_len(&node).unwrap(),
            super::super::encode_node(&node).unwrap().len()
        );
    }

    #[test]
    fn envelope_cap_and_variable_width_values_match_the_encoder() {
        let values = [0u64, 127, 128, 16383, 16384, u32::MAX as u64, u64::MAX];
        let mut output = [0u8; 256];
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let expected = super::super::encode_payload(&values, encoding, &mut output[8..])
                .unwrap()
                .len()
                + 8;
            assert_eq!(encoded_len(&values, encoding, expected).unwrap(), expected);
            assert_eq!(
                encoded_len(&values, encoding, expected - 1),
                Err(Error::SerializeBufferFull)
            );
            assert_eq!(
                encoded_len(&values, encoding, 7),
                Err(Error::SerializeBufferFull)
            );
            let oversized = vec![0u8; profile::MAX_PROOF_BYTES];
            assert_eq!(
                encoded_len(&oversized, encoding, profile::MAX_PROOF_BYTES),
                Err(Error::SerializeBufferFull)
            );
        }
    }

    #[test]
    fn serializer_errors_and_size_overflow_are_rejected() {
        struct Rejected;
        impl Serialize for Rejected {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(
                    "deliberate serialization rejection",
                ))
            }
        }
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            assert!(encoded_len(&Rejected, encoding, profile::MAX_PROOF_BYTES).is_err());
        }
        let mut size = BoundedSize {
            bytes: usize::MAX,
            limit: usize::MAX,
        };
        assert_eq!(size.try_push(0), Err(Error::SerializeBufferFull));
        assert_eq!(size.bytes, usize::MAX);
    }
}
