use super::ledger::{
    AccountBytes, AccountWitness, LedgerCheckpoint, LedgerSnapshot, LedgerSource, ACCOUNT_BYTES,
    RING_ACCOUNTS,
};
use super::*;
use crate::{
    native_packet::{self, NativePacket},
    rust_verify,
};

fn patterned_proof(maximum: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(native_packet::PROOF_BYTES);
    for part in proof::PARTS {
        match part {
            proof::Part::Raw(n) => bytes.extend((0..n).map(|i| i as u8)),
            proof::Part::Polys {
                count, width, base, ..
            } => {
                for polynomial in 0..count {
                    let values = std::array::from_fn(|i| {
                        if maximum {
                            base - 1
                        } else {
                            ((i as u64 * 1_000_003 + polynomial as u64 * 37) % u64::from(base))
                                as u32
                        }
                    });
                    let start = bytes.len();
                    bytes.resize(start + 32 * width, 0);
                    radix::pack_bits(&values, width, &mut bytes[start..]).unwrap();
                }
            }
        }
    }
    assert_eq!(bytes.len(), native_packet::PROOF_BYTES);
    bytes
}

fn packet() -> NativePacket {
    let mut statement = vec![0; native_packet::STATEMENT_BYTES];
    statement[..32].fill(11);
    for (i, value) in statement[32..native_packet::STATEMENT_BYTES - 64]
        .chunks_exact_mut(4)
        .enumerate()
    {
        value.copy_from_slice(&((i as u64 * 413 + 7) % rust_verify::Q).to_le_bytes()[..4]);
    }
    statement[native_packet::STATEMENT_BYTES - 64..native_packet::STATEMENT_BYTES - 32].fill(19);
    statement[native_packet::STATEMENT_BYTES - 32..].fill(20);
    NativePacket {
        context: [7; 32],
        statement,
        proof: patterned_proof(false),
    }
}

fn snapshot(packet: &NativePacket) -> LedgerSnapshot {
    let accounts: Vec<AccountBytes> = packet.statement[statement::RING_START..statement::RING_END]
        .chunks_exact(ACCOUNT_BYTES)
        .map(|a| a.try_into().unwrap())
        .collect();
    LedgerSnapshot::new(
        [23; 32],
        packet.statement[..32].try_into().unwrap(),
        accounts,
    )
    .unwrap()
}

fn indices() -> [u64; RING_ACCOUNTS] {
    std::array::from_fn(|i| i as u64)
}

#[test]
fn radix_matches_independent_power_of_two_byte_layouts() {
    let values = std::array::from_fn(|i| i as u32);
    let mut encoded = [0; 256];
    radix::encode(&values, 256, &mut encoded).unwrap();
    assert_eq!(encoded, std::array::from_fn(|i| i as u8));
    assert_eq!(radix::decode(&encoded, 256).unwrap(), values);
    let values = std::array::from_fn(|i| i as u32 * 257);
    let mut encoded = [0; 512];
    radix::encode(&values, 65_536, &mut encoded).unwrap();
    assert_eq!(encoded, std::array::from_fn(|i| (i / 2) as u8));
    assert_eq!(radix::decode(&encoded, 65_536).unwrap(), values);
}

#[test]
fn radix_rejects_overflow_and_out_of_range_digits() {
    let mut input = [0u8; 257];
    input[256] = 1; // 256^256: one greater than the maximum valid radix-256 block.
    assert_eq!(radix::decode(&input, 256), Err(Error::NonCanonical));
    assert_eq!(
        radix::encode(&[3; 256], 3, &mut [0; 51]),
        Err(Error::NonCanonical)
    );
    assert_eq!(
        radix::encode(&[2; 256], 3, &mut [0; 1]),
        Err(Error::Capacity)
    );
    assert_eq!(radix::decode(&[0; 1025], 3), Err(Error::Capacity));
    let mut maximum = [0; 51];
    radix::encode(&[2; 256], 3, &mut maximum).unwrap();
    for byte in &mut maximum {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    assert_eq!(radix::decode(&maximum, 3), Err(Error::NonCanonical));
}

#[test]
fn every_proof_range_round_trips_and_matches_existing_decoder() {
    for original in [
        vec![0; native_packet::PROOF_BYTES],
        patterned_proof(false),
        patterned_proof(true),
    ] {
        rust_verify::Proof::decode(&original).unwrap();
        let encoded = encode_proof(&original).unwrap();
        assert_eq!(encoded.len(), 51_578);
        let decoded = decode_proof(&encoded).unwrap();
        assert_eq!(decoded, original);
        rust_verify::Proof::decode(&decoded).unwrap();
    }
}

#[test]
fn each_proof_field_rejects_noncanonical_legacy_and_compact_values() {
    let original = patterned_proof(false);
    let packed = encode_proof(&original).unwrap();
    let (mut legacy_offset, mut compact_offset) = (0, 0);
    for part in proof::PARTS {
        match part {
            proof::Part::Raw(n) => {
                legacy_offset += n;
                compact_offset += n;
            }
            proof::Part::Polys {
                count,
                width,
                base,
                bytes,
            } => {
                let mut invalid = original.clone();
                let mut coefficients =
                    radix::unpack_bits(&invalid[legacy_offset..legacy_offset + width * 32], width)
                        .unwrap();
                coefficients[0] = base;
                radix::pack_bits(
                    &coefficients,
                    width,
                    &mut invalid[legacy_offset..legacy_offset + width * 32],
                )
                .unwrap();
                assert!(rust_verify::Proof::decode(&invalid).is_err());
                assert_eq!(encode_proof(&invalid), Err(Error::NonCanonical));
                let mut invalid = packed.clone();
                invalid[compact_offset..compact_offset + bytes].fill(255);
                assert_eq!(decode_proof(&invalid), Err(Error::NonCanonical));
                legacy_offset += count * width * 32;
                compact_offset += count * bytes;
            }
        }
    }
}

#[test]
fn codecs_require_exact_lengths_and_canonical_statement_coefficients() {
    let p = packet();
    let statement = encode_statement(&p.statement).unwrap();
    assert_eq!(statement.len(), 173_346);
    assert_eq!(decode_statement(&statement).unwrap(), p.statement);
    rust_verify::Statement::decode(&p.statement).unwrap();
    let mut invalid = p.statement.clone();
    invalid[32..36].copy_from_slice(&(rust_verify::Q as u32).to_le_bytes());
    assert_eq!(encode_statement(&invalid), Err(Error::NonCanonical));
    let mut invalid = statement.clone();
    invalid[32..32 + 875].fill(255);
    assert_eq!(decode_statement(&invalid), Err(Error::NonCanonical));
    let proof = encode_proof(&p.proof).unwrap();
    assert_eq!(
        encode_proof(&p.proof[..p.proof.len() - 1]),
        Err(Error::Length)
    );
    assert_eq!(decode_proof(&proof[..proof.len() - 1]), Err(Error::Length));
    assert_eq!(decode_proof(&[proof, vec![0]].concat()), Err(Error::Length));
    assert_eq!(
        encode_statement(&p.statement[..p.statement.len() - 1]),
        Err(Error::Length)
    );
    assert_eq!(
        decode_statement(&statement[..statement.len() - 1]),
        Err(Error::Length)
    );
    assert_eq!(
        decode_statement(&[statement, vec![0]].concat()),
        Err(Error::Length)
    );
}

#[test]
fn standalone_and_referenced_packets_restore_the_original_native_packet() {
    let p = packet();
    let full = encode_packet(&p).unwrap();
    assert_eq!(full.len(), 225_004);
    assert_eq!(decode_packet(&full, &p.context).unwrap(), p);
    assert!(NativePacket::decode(&full).is_err());
    let store = snapshot(&p);
    let referenced = encode_referenced_packet(&p, &store.checkpoint(), &indices(), &store).unwrap();
    assert_eq!(referenced.len(), 67_696);
    assert_eq!(
        decode_referenced_packet(&referenced, &p.context, &store.checkpoint(), &store).unwrap(),
        p
    );
    assert!(decode_packet(&referenced, &p.context).is_err());
    assert!(decode_referenced_packet(&full, &p.context, &store.checkpoint(), &store).is_err());
    assert!(decode_packet(&p.encode().unwrap(), &p.context).is_err());
}

struct NoLookup;
impl LedgerSource for NoLookup {
    fn account(&self, _: u64) -> Option<AccountWitness<'_>> {
        panic!("lookup before public admission")
    }
}

#[test]
fn framing_profile_context_checkpoint_and_indices_are_checked_before_lookup() {
    let p = packet();
    let full = encode_packet(&p).unwrap();
    for (offset, error) in [
        (0, Error::Format),
        (8, Error::Profile),
        (10, Error::Profile),
        (12, Error::Profile),
        (44, Error::Context),
        (76, Error::Format),
    ] {
        let mut changed = full.clone();
        changed[offset] ^= 1;
        assert_eq!(decode_packet(&changed, &p.context), Err(error));
    }
    assert_eq!(
        decode_packet(&full[..full.len() - 1], &p.context),
        Err(Error::Length)
    );
    let store = snapshot(&p);
    let checkpoint = store.checkpoint();
    let referenced = encode_referenced_packet(&p, &checkpoint, &indices(), &store).unwrap();
    for (offset, error) in [
        (0, Error::Format),
        (12, Error::Profile),
        (44, Error::Context),
        (76, Error::Format),
        (80, Error::LedgerCheckpoint),
        (112, Error::LedgerCheckpoint),
    ] {
        let mut changed = referenced.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decode_referenced_packet(&changed, &p.context, &checkpoint, &NoLookup),
            Err(error)
        );
    }
    let mut changed = referenced.clone();
    changed[144..152].copy_from_slice(&checkpoint.account_count().to_le_bytes());
    assert_eq!(
        decode_referenced_packet(&changed, &p.context, &checkpoint, &NoLookup),
        Err(Error::Reference)
    );
    assert_eq!(
        decode_referenced_packet(
            &referenced[..referenced.len() - 1],
            &p.context,
            &checkpoint,
            &NoLookup
        ),
        Err(Error::Length)
    );
    assert_eq!(
        decode_referenced_packet(
            &[referenced, vec![0]].concat(),
            &p.context,
            &checkpoint,
            &NoLookup
        ),
        Err(Error::Length)
    );
}

#[test]
fn encoder_rejects_mismatched_account_references() {
    let p = packet();
    let store = snapshot(&p);
    let mut refs = indices();
    refs.swap(0, 1);
    assert_eq!(
        encode_referenced_packet(&p, &store.checkpoint(), &refs, &store),
        Err(Error::Reference)
    );
    refs[0] = store.checkpoint().account_count();
    assert_eq!(
        encode_referenced_packet(&p, &store.checkpoint(), &refs, &store),
        Err(Error::Reference)
    );
}

#[test]
fn referenced_decoder_rejects_bad_membership_even_with_matching_checkpoint_id() {
    let p = packet();
    let store = snapshot(&p);
    let checkpoint = store.checkpoint();
    let bytes = encode_referenced_packet(&p, &checkpoint, &indices(), &store).unwrap();
    struct Corrupted<'a>(&'a LedgerSnapshot);
    impl LedgerSource for Corrupted<'_> {
        fn account(&self, index: u64) -> Option<AccountWitness<'_>> {
            let original = self.0.account(index)?;
            let mut path = original.siblings().to_vec();
            path[0][0] ^= 1;
            Some(AccountWitness::new(original.account(), &path).unwrap())
        }
    }
    assert_eq!(
        decode_referenced_packet(&bytes, &p.context, &checkpoint, &Corrupted(&store)),
        Err(Error::LedgerMembership)
    );
    let wrong_root = LedgerCheckpoint::from_trusted_parts(
        checkpoint.domain(),
        checkpoint.setup_seed(),
        [9; 32],
        checkpoint.account_count(),
    )
    .unwrap();
    let mut relabeled = bytes;
    relabeled[80..112].copy_from_slice(&wrong_root.id());
    assert_eq!(
        decode_referenced_packet(&relabeled, &p.context, &wrong_root, &store),
        Err(Error::LedgerMembership)
    );
    let mut wrong_seed = p.clone();
    wrong_seed.statement[0] ^= 1;
    assert_eq!(
        encode_referenced_packet(&wrong_seed, &checkpoint, &indices(), &NoLookup),
        Err(Error::LedgerCheckpoint)
    );
}

#[test]
fn ledger_membership_binds_account_index_domain_root_count_and_path() {
    let p = packet();
    let store = snapshot(&p);
    let checkpoint = store.checkpoint();
    for index in 0..checkpoint.account_count() {
        store
            .account(index)
            .unwrap()
            .verify(index, &checkpoint)
            .unwrap();
    }
    let witness = store.account(0).unwrap();
    assert_eq!(witness.verify(1, &checkpoint), Err(Error::LedgerMembership));
    let mut account = witness.account().to_vec();
    account[0] ^= 1;
    let changed = AccountWitness::new(&account, witness.siblings()).unwrap();
    assert_eq!(changed.verify(0, &checkpoint), Err(Error::LedgerMembership));
    let mut path = witness.siblings().to_vec();
    path[0][0] ^= 1;
    assert_eq!(
        AccountWitness::new(witness.account(), &path)
            .unwrap()
            .verify(0, &checkpoint),
        Err(Error::LedgerMembership)
    );
    let other_domain = LedgerCheckpoint::from_trusted_parts(
        [24; 32],
        checkpoint.setup_seed(),
        checkpoint.tree_root(),
        20,
    )
    .unwrap();
    assert_ne!(other_domain.id(), checkpoint.id());
    assert_eq!(
        witness.verify(0, &other_domain),
        Err(Error::LedgerMembership)
    );
    let other_root = LedgerCheckpoint::from_trusted_parts(
        checkpoint.domain(),
        checkpoint.setup_seed(),
        [0; 32],
        20,
    )
    .unwrap();
    assert_eq!(witness.verify(0, &other_root), Err(Error::LedgerMembership));
    let other_count = LedgerCheckpoint::from_trusted_parts(
        checkpoint.domain(),
        checkpoint.setup_seed(),
        checkpoint.tree_root(),
        19,
    )
    .unwrap();
    assert_ne!(other_count.id(), checkpoint.id());
    assert_eq!(
        store.account(19).unwrap().verify(19, &other_count),
        Err(Error::Reference)
    );
    assert!(AccountWitness::new(witness.account(), &[[0; 32]; 33]).is_err());
    let other_seed = LedgerCheckpoint::from_trusted_parts(
        checkpoint.domain(),
        [99; 32],
        checkpoint.tree_root(),
        20,
    )
    .unwrap();
    assert_ne!(other_seed.id(), checkpoint.id());
    assert_eq!(witness.verify(0, &other_seed), Err(Error::LedgerMembership));
    assert!(LedgerCheckpoint::from_trusted_parts([0; 32], [0; 32], [0; 32], 0).is_err());
    assert!(
        LedgerCheckpoint::from_trusted_parts([0; 32], [0; 32], [0; 32], (1u64 << 32) + 1).is_err()
    );
}

#[test]
fn single_account_ledger_and_missing_account_are_handled() {
    let store = LedgerSnapshot::new([5; 32], [6; 32], vec![[0; ACCOUNT_BYTES]]).unwrap();
    let witness = store.account(0).unwrap();
    assert!(witness.siblings().is_empty());
    witness.verify(0, &store.checkpoint()).unwrap();
    assert!(store.account(1).is_none());
    assert!(LedgerSnapshot::new([0; 32], [0; 32], vec![]).is_err());
    struct Empty;
    impl LedgerSource for Empty {
        fn account(&self, _: u64) -> Option<AccountWitness<'_>> {
            None
        }
    }
    let p = packet();
    let store = snapshot(&p);
    let checkpoint = store.checkpoint();
    let bytes = encode_referenced_packet(&p, &checkpoint, &indices(), &store).unwrap();
    assert_eq!(
        decode_referenced_packet(&bytes, &p.context, &checkpoint, &Empty),
        Err(Error::MissingAccount)
    );
}

#[cfg(feature = "native-matrict")]
#[test]
fn fresh_native_proofs_round_trip_and_both_verifiers_reject_mutations() {
    use crate::native::{self, FixtureAmounts};
    assert!(
        native::available(),
        "native qualification requires the reference backend"
    );
    for i in 0..3u8 {
        let context = [41 + i; 32];
        let fixture = native::generate_fixture_with_setup_seed(
            context,
            [31 + i; 32],
            u64::from(i) * 4,
            FixtureAmounts {
                input: [100 + u64::from(i), 200],
                output: [150, 150 + u64::from(i)],
            },
        )
        .unwrap();
        let p = NativePacket {
            context,
            statement: fixture.statement,
            proof: fixture.proof,
        };
        let full = encode_packet(&p).unwrap();
        let store = snapshot(&p);
        let checkpoint = store.checkpoint();
        let refs = encode_referenced_packet(&p, &checkpoint, &indices(), &store).unwrap();
        for decoded in [
            decode_packet(&full, &context).unwrap(),
            decode_referenced_packet(&refs, &context, &checkpoint, &store).unwrap(),
        ] {
            assert_eq!(decoded, p);
            assert!(native::verify(&context, &decoded.statement, &decoded.proof).unwrap());
            assert!(rust_verify::verify(&context, &decoded.statement, &decoded.proof).unwrap());
        }
        // A changed valid ledger index resolves successfully, but changes the
        // native statement and must fail the cryptographic relation.
        let mut changed = refs.clone();
        changed[144..152].copy_from_slice(&1u64.to_le_bytes());
        let changed = decode_referenced_packet(&changed, &context, &checkpoint, &store).unwrap();
        assert!(!native::verify(&context, &changed.statement, &changed.proof).unwrap_or(false));
        assert!(
            !rust_verify::verify(&context, &changed.statement, &changed.proof).unwrap_or(false)
        );
        // Alpha is an unchanged raw field, so this mutation is canonical but false.
        let mut changed = full;
        changed[packet::HEADER_BYTES + STATEMENT_BYTES + 11_200] ^= 1;
        let changed = decode_packet(&changed, &context).unwrap();
        assert!(!native::verify(&context, &changed.statement, &changed.proof).unwrap_or(false));
        assert!(
            !rust_verify::verify(&context, &changed.statement, &changed.proof).unwrap_or(false)
        );
    }
}
