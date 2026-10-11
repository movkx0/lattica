use super::*;
use crate::{
    block_v2::{
        machine::{programs, verifier::template},
        recursive,
    },
    config::Val,
};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Deserializer, Serialize};
use std::mem::size_of;

fn payload<T: Serialize>(value: &T, encoding: Encoding) -> Vec<u8> {
    let mut bytes = vec![0; profile::MAX_PROOF_BYTES];
    let len = encode_payload(value, encoding, &mut bytes).unwrap().len();
    bytes.truncate(len);
    bytes
}

fn template_node() -> NodeProof {
    NodeProof {
        public: [Val::ZERO; programs::PUBLIC_VALUES],
        proof: template::batch(&programs::shape(64).unwrap()).unwrap(),
    }
}

#[test]
fn native_proof_schemas_preserve_both_canonical_encodings_and_exact_quota() {
    for node in [
        template_node(),
        super::super::tests::maximum_value_node(64),
        NodeProof {
            public: [Val::ZERO; programs::PUBLIC_VALUES],
            proof: template::batch(&programs::shape(1 << 19).unwrap()).unwrap(),
        },
    ] {
        for encoding in [Encoding::Legacy, Encoding::FixedU64] {
            let bytes = payload(&node, encoding);
            let baseline = Storage::new(INPUT_STORAGE_LIMIT);
            let decoded: NodeProof = baseline.payload(&bytes, encoding).unwrap();
            assert_eq!(payload(&decoded, encoding), bytes);
            let required = baseline.vector_bytes.get() + baseline.canonical_bytes.get();
            assert!(baseline.vector_bytes.get() > 0);
            assert_eq!(baseline.canonical_bytes.get(), bytes.len());
            assert!(Storage::new(required)
                .payload::<NodeProof>(&bytes, encoding)
                .is_ok());
            let short = Storage::new(required - 1);
            assert!(short.payload::<NodeProof>(&bytes, encoding).is_err());
            assert!(short.rejected.get());
            assert_eq!(short.canonical_bytes.get(), 0);
            let zero = Storage::new(0);
            assert!(zero.payload::<NodeProof>(&bytes, encoding).is_err());
            assert_eq!(zero.allocations.get(), 0);
        }
    }
}

#[test]
fn one_request_quota_keeps_prior_proof_and_canonical_charges() {
    let bytes = super::super::encode_node(&template_node()).unwrap();
    let baseline = Storage::new(INPUT_STORAGE_LIMIT);
    baseline.node(&bytes).unwrap();
    let required = baseline.vector_bytes.get() + baseline.canonical_bytes.get();
    for limit in [required * 2 - 1, required * 2] {
        let storage = Storage::new(limit);
        let first = storage.node(&bytes).unwrap();
        let second = storage.node(&bytes);
        assert_eq!(second.is_ok(), limit == required * 2);
        assert_eq!(super::super::encode_node(&first).unwrap(), bytes);
        assert!(storage.vector_bytes.get() + storage.canonical_bytes.get() <= limit);
        if second.is_err() {
            assert!(storage.payload::<Val>(&[0], Encoding::Legacy).is_err());
        }
    }
}

thread_local! {
    static VISITED: Cell<usize> = const { Cell::new(0) };
    static DROPPED: Cell<usize> = const { Cell::new(0) };
    static PANIC_AT: Cell<usize> = const { Cell::new(0) };
}
#[derive(Serialize)]
#[serde(transparent)]
struct Tracked(Val);
impl schema::Decode for Tracked {
    fn decode<'de, D: Deserializer<'de>>(d: D, _: &Storage) -> Result<Self, D::Error> {
        let value = Val::deserialize(d)?;
        let index = VISITED.with(|n| {
            n.set(n.get() + 1);
            n.get()
        });
        assert_ne!(index, PANIC_AT.with(Cell::get), "injected decoder unwind");
        Ok(Self(value))
    }
}
impl Drop for Tracked {
    fn drop(&mut self) {
        DROPPED.with(|n| n.set(n.get() + 1));
    }
}

#[test]
fn vector_quota_precedes_element_visitors_and_partial_values_drop() {
    let bytes = payload(&vec![Val::ONE; 4], Encoding::Legacy);
    // Preserve Postcard's count hint, then fail inside the final scalar.
    // Removing a byte would reject the whole sequence before its visitor.
    let mut truncated_scalar = bytes.clone();
    *truncated_scalar.last_mut().unwrap() = 0x80;
    for mode in 0..3 {
        VISITED.set(0);
        DROPPED.set(0);
        PANIC_AT.set(if mode == 2 { 2 } else { 0 });
        let storage = Storage::new(if mode == 0 {
            4 * size_of::<Tracked>() - 1
        } else {
            1024
        });
        let slice = if mode == 1 {
            &truncated_scalar[..]
        } else {
            &bytes[..]
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            storage.payload::<Vec<Tracked>>(slice, Encoding::Legacy)
        }));
        match mode {
            0 => {
                assert!(result.unwrap().is_err());
                assert_eq!(VISITED.get(), 0);
                assert_eq!(storage.allocations.get(), 0);
                assert_eq!(DROPPED.get(), 0);
            }
            1 => {
                assert!(result.unwrap().is_err());
                assert_eq!(VISITED.get(), 3);
                assert_eq!(DROPPED.get(), 3);
            }
            _ => {
                assert!(result.is_err());
                assert_eq!(VISITED.get(), 2);
                assert_eq!(DROPPED.get(), 1);
            }
        }
        assert!(storage.rejected.get());
        assert!(storage.payload::<Val>(&[0], Encoding::Legacy).is_err());
    }
    PANIC_AT.set(0);
}

#[test]
fn malformed_fields_lengths_caps_and_envelopes_keep_existing_guards() {
    for encoding in [Encoding::Legacy, Encoding::FixedU64] {
        let noncanonical = payload(&crate::block_v2::commitment::MODULUS, encoding);
        assert!(Storage::new(INPUT_STORAGE_LIMIT)
            .payload::<Val>(&noncanonical, encoding)
            .is_err());
        let cap = payload(&(Vec::<[Val; 4]>::new(), ()), encoding);
        assert!(Storage::new(INPUT_STORAGE_LIMIT)
            .payload::<p3_symmetric::MerkleCap<Val, [Val; 4]>>(&cap, encoding)
            .is_err());
        let too_long = payload(&vec![Val::ZERO; 257], encoding);
        let storage = Storage::new(INPUT_STORAGE_LIMIT);
        assert!(storage.payload::<Vec<Val>>(&too_long, encoding).is_err());
        assert_eq!(storage.allocations.get(), 0);
    }
    let aggregate = payload(&vec![vec![vec![Val::ZERO; 17]; 256]; 256], Encoding::Legacy);
    assert!(Storage::new(INPUT_STORAGE_LIMIT)
        .payload::<Vec<Vec<Vec<Val>>>>(&aggregate, Encoding::Legacy)
        .is_err());
    let mut bytes = super::super::encode_node(&template_node()).unwrap();
    for cut in [0, 7, 8, bytes.len() - 1] {
        assert!(Storage::new(INPUT_STORAGE_LIMIT)
            .node(&bytes[..cut])
            .is_err());
    }
    bytes.push(0);
    assert!(Storage::new(INPUT_STORAGE_LIMIT).node(&bytes).is_err());
    bytes[0] ^= 1;
    let storage = Storage::new(INPUT_STORAGE_LIMIT);
    assert!(storage.node(&bytes).is_err());
    assert_eq!(storage.allocations.get(), 0);
}

#[test]
fn extension_fields_use_stack_coefficients_and_preserve_wire_bytes() {
    let value = profile::Challenge::new([Val::ONE, Val::TWO, Val::NEG_ONE]);
    for encoding in [Encoding::Legacy, Encoding::FixedU64] {
        let bytes = payload(&value, encoding);
        let storage = Storage::new(bytes.len());
        assert_eq!(
            storage
                .payload::<profile::Challenge>(&bytes, encoding)
                .unwrap(),
            value
        );
        assert_eq!(storage.vector_bytes.get(), 0);
        assert_eq!(storage.allocations.get(), 1); // Only canonical re-encoding.
    }
}

#[test]
fn real_wallet_verifies_with_bounded_storage_and_typed_admission() {
    use crate::block_v2::{
        execution::job::{RegistryPin, VerifiedWallet},
        typed_recursive::{Policy, Registry},
    };
    let wallet = recursive::demo_wallet(0).unwrap();
    let bytes = postcard::to_allocvec(&wallet).unwrap();
    let storage = Storage::new(INPUT_STORAGE_LIMIT);
    let decoded = storage.wallet(&bytes).unwrap();
    recursive::verify_wallet(&decoded).unwrap();
    assert_eq!(postcard::to_allocvec(&decoded).unwrap(), bytes);
    let registry = Registry::<12> {
        height: 64,
        caps: std::array::from_fn(|_| vec![[Val::ONE; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let mut artifact = b"LBV2TW01".to_vec();
    artifact.extend_from_slice(&bytes);
    assert!(VerifiedWallet::verify_typed(
        pin,
        &registry,
        wallet.chain,
        Policy::JoinSplit,
        &artifact
    )
    .is_ok());
    assert!(
        VerifiedWallet::verify_typed(pin, &registry, [0; 32], Policy::JoinSplit, &artifact)
            .is_err()
    );
    assert!(VerifiedWallet::verify_typed(
        pin,
        &registry,
        wallet.chain,
        Policy::Issuance { authorized_mint: 1 },
        &artifact
    )
    .is_err());
}
