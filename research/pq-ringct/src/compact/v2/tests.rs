use super::super::{
    self as v1,
    ledger::{
        AccountBytes, AccountWitness, LedgerSnapshot, LedgerSource, ACCOUNT_BYTES, RING_ACCOUNTS,
    },
    radix, Error,
};
use super::{
    bits::{Reader, Writer},
    proof, *,
};
use crate::native_packet::{self, NativePacket};

fn fixture(mut value: impl FnMut(usize, usize, u32) -> u32) -> Vec<u8> {
    let mut out = Vec::new();
    for (group, part) in v1::proof::PARTS.iter().enumerate() {
        match *part {
            v1::proof::Part::Raw(n) => out.extend(0..n as u8),
            v1::proof::Part::Polys {
                count, width, base, ..
            } => {
                for p in 0..count {
                    let digits = std::array::from_fn(|i| value(group, p * 256 + i, base));
                    let start = out.len();
                    out.resize(start + 32 * width, 0);
                    radix::pack_bits(&digits, width, &mut out[start..]).unwrap();
                }
            }
        }
    }
    assert_eq!(out.len(), native_packet::PROOF_BYTES);
    out
}

fn centered() -> Vec<u8> {
    fixture(|_, _, base| (base - 1) / 2)
}

fn roundtrip(native: &[u8]) -> Vec<u8> {
    let encoded = encode_proof(native).unwrap();
    assert!((MIN_PROOF_BYTES..=MAX_PROOF_BYTES).contains(&encoded.len()));
    assert_eq!(decode_proof(&encoded).unwrap(), native);
    assert_eq!(
        encode_proof(&decode_proof(&encoded).unwrap()).unwrap(),
        encoded
    );
    assert_eq!(
        v1::decode_proof(&v1::encode_proof(native).unwrap()).unwrap(),
        native
    );
    encoded
}

#[test]
fn rice_known_bit_order_and_limits() {
    // k=2: 0 -> 000, 1 -> 010, 4 -> 1000, 7 -> 1011, 8 -> 11000.
    let mut writer = Writer::new(19);
    for u in [0, 1, 4, 7, 8] {
        writer.rice(u, 2).unwrap();
    }
    let bytes = writer.finish().unwrap();
    assert_eq!(bytes, [0x50, 0xf4, 0x00]);
    let mut reader = Reader::new(&bytes);
    for u in [0, 1, 4, 7, 8] {
        assert_eq!(reader.rice(2, 8).unwrap(), u);
    }
    reader.finish().unwrap();
    assert_eq!(Reader::new(&[0xff]).rice(0, 2), Err(Error::NonCanonical));
    assert_eq!(Reader::new(&[0b110]).rice(2, 2), Err(Error::NonCanonical));
    assert_eq!(Reader::new(&[]).rice(0, 2), Err(Error::Length));
    let mut writer = Writer::new(0);
    assert_eq!(writer.rice(0, 0), Err(Error::Capacity));
    assert!(Writer::new(1).finish().is_err());
}

#[test]
fn centered_minimum_and_smallest_parameter_ties() {
    let bytes = roundtrip(&centered());
    assert_eq!(bytes.len(), MIN_PROOF_BYTES);
    assert_eq!(&bytes[..6], &[1, 0, 0, 0, 0, 0]);
    assert!(bytes[proof::RICE_PREFIX..].iter().all(|&b| b == 0));
    // Every u=1: k=0 and k=1 both cost 2 bits, so k=0 must win.
    let native = fixture(|_, _, base| (base - 1) / 2 - 1);
    assert_eq!(&roundtrip(&native)[1..6], &[0; 5]);
}

#[test]
fn all_original_domain_extremes_remain_representable() {
    for pattern in 0..3 {
        let native = fixture(|_, i, base| match pattern {
            0 => 0,
            1 => base - 1,
            _ => {
                if i % 2 == 0 {
                    0
                } else {
                    base - 1
                }
            }
        });
        let bytes = roundtrip(&native);
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes.len(), MAX_PROOF_BYTES);
    }
}

#[test]
fn exact_size_tie_uses_fallback_and_one_byte_smaller_uses_rice() {
    // Monotonically add full-range outliers, then tune the last one to reach
    // the wire-size boundary. This exercises selection by padded byte length.
    let make = |count: usize, last: Option<u32>| {
        let mut position = 0;
        fixture(|g, _, base| {
            if g < 3 {
                return 0;
            }
            let i = position;
            position += 1;
            if i + 1 < count {
                base - 1
            } else if i + 1 == count {
                (base - 1) / 2 + last.unwrap_or((base - 1) / 2)
            } else {
                (base - 1) / 2
            }
        })
    };
    let size = |native: &[u8]| proof::RICE_PREFIX + proof::plan(native).unwrap().bits.div_ceil(8);
    let (mut low, mut high) = (0, 20_224);
    while low < high {
        let mid = (low + high) / 2;
        if size(&make(mid, None)) < MAX_PROOF_BYTES {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    let count = low;
    let mut remaining = count - 1;
    let base = proof::groups()
        .find_map(|(n, _, base)| {
            if remaining < n * 256 {
                Some(base)
            } else {
                remaining -= n * 256;
                None
            }
        })
        .unwrap();
    for target in [MAX_PROOF_BYTES - 1, MAX_PROOF_BYTES] {
        let (mut low, mut high) = (0, (base - 1) / 2);
        while low < high {
            let mid = (low + high) / 2;
            if size(&make(count, Some(mid))) < target {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let native = make(count, Some(low));
        assert_eq!(size(&native), target);
        let bytes = roundtrip(&native);
        assert_eq!(bytes.len(), target);
        assert_eq!(bytes[0], u8::from(target < MAX_PROOF_BYTES));
    }
}

#[test]
fn deterministic_distributions_and_sparse_outliers_roundtrip() {
    let mut seed = 0xa273_5734_c1d9_893du64;
    for scale in [1, 2, 7, 31, 255, 8191, u32::MAX] {
        let native = fixture(|_, _, base| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let radius = scale.min((base - 1) / 2);
            (base - 1) / 2 - radius + (seed % (2 * u64::from(radius) + 1)) as u32
        });
        roundtrip(&native);
    }
    for index in [0, 255, 256, 2047] {
        roundtrip(&fixture(
            |_, i, base| if i == index { base - 1 } else { (base - 1) / 2 },
        ));
    }
}

#[test]
fn invalid_native_lengths_and_each_coefficient_domain_rejected() {
    let native = centered();
    assert_eq!(
        encode_proof(&native[..native.len() - 1]),
        Err(Error::Length)
    );
    let mut position = 0;
    for part in v1::proof::PARTS {
        match part {
            v1::proof::Part::Raw(n) => position += n,
            v1::proof::Part::Polys {
                count, width, base, ..
            } => {
                let mut changed = native.clone();
                let end = position + 32 * width;
                let mut digits = radix::unpack_bits(&changed[position..end], width).unwrap();
                digits[255] = base;
                radix::pack_bits(&digits, width, &mut changed[position..end]).unwrap();
                assert_eq!(encode_proof(&changed), Err(Error::NonCanonical));
                position += count * 32 * width;
            }
        }
    }
}

#[test]
fn framing_truncation_padding_and_unbounded_runs_rejected() {
    let native = fixture(|g, i, base| (base - 1) / 2 - u32::from(g == 3 && i == 0));
    let encoded = roundtrip(&native);
    assert_eq!(encoded.len(), MIN_PROOF_BYTES + 1);
    for end in [0, 1, 5, 6, 11237, MIN_PROOF_BYTES - 1, encoded.len() - 1] {
        assert!(decode_proof(&encoded[..end]).is_err());
    }
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(decode_proof(&changed).is_err());
    let last = encoded.len() - 1;
    for (offset, value) in [
        (0, 2),
        (1, 2),
        (2, 17),
        (3, 11),
        (4, 17),
        (5, 24),
        (last, 0x80),
    ] {
        let mut changed = encoded.clone();
        changed[offset] = value;
        assert!(decode_proof(&changed).is_err(), "offset {offset}");
    }
    let mut changed = encoded;
    changed[6..6 + 875].fill(0xff);
    assert_eq!(decode_proof(&changed), Err(Error::NonCanonical));
    changed = roundtrip(&centered());
    changed[proof::RICE_PREFIX..].fill(0xff);
    assert_eq!(decode_proof(&changed), Err(Error::NonCanonical));
    assert!(decode_proof(&vec![0; MAX_PROOF_BYTES + 1]).is_err());
}

#[test]
fn alternative_parameters_and_unnecessary_fallback_rejected() {
    let native = centered();
    let canonical = roundtrip(&native);
    let mut fallback = vec![0];
    fallback.extend(v1::encode_proof(&native).unwrap());
    assert_eq!(decode_proof(&fallback), Err(Error::NonCanonical));
    for group in 0..5 {
        // Same all-zero zigzags encoded with k=1 in one group are decodable,
        // but nonminimal. All bits still zero, so reconstruct directly.
        let count = proof::groups().nth(group).unwrap().0;
        let mut alternate = canonical.clone();
        alternate[1 + group] = 1;
        alternate.resize(alternate.len() + count * 32, 0);
        assert_eq!(decode_proof(&alternate), Err(Error::NonCanonical));
    }
    // A tied but larger parameter is noncanonical as well.
    let native = fixture(|_, _, base| (base - 1) / 2 - 1);
    let mut alternate = roundtrip(&native);
    alternate[1] = 1;
    // u=1, k=1 is bits 01 instead of k=0 bits 10.
    alternate[proof::RICE_PREFIX..proof::RICE_PREFIX + 64].fill(0xaa);
    assert_eq!(decode_proof(&alternate), Err(Error::NonCanonical));
}

fn packet() -> (NativePacket, LedgerSnapshot) {
    let mut statement = vec![0; native_packet::STATEMENT_BYTES];
    statement[..32].fill(19);
    for (i, word) in statement[32..native_packet::STATEMENT_BYTES - 64]
        .chunks_exact_mut(4)
        .enumerate()
    {
        word.copy_from_slice(&((i as u32 * 17) % 167_770_241).to_le_bytes());
    }
    let accounts: Vec<AccountBytes> = statement[32..32 + RING_ACCOUNTS * ACCOUNT_BYTES]
        .chunks_exact(ACCOUNT_BYTES)
        .map(|a| a.try_into().unwrap())
        .collect();
    let store = LedgerSnapshot::new([23; 32], [19; 32], accounts).unwrap();
    (
        NativePacket {
            context: [7; 32],
            statement,
            proof: centered(),
        },
        store,
    )
}

struct NoLookup;
impl LedgerSource for NoLookup {
    fn account(&self, _: u64) -> Option<AccountWitness<'_>> {
        panic!("lookup before public admission")
    }
}

#[test]
fn both_packet_modes_and_both_proof_modes_roundtrip_without_v1_changes() {
    let (mut packet, store) = packet();
    let indices = std::array::from_fn(|i| i as u64);
    for native in [centered(), fixture(|_, _, base| base - 1)] {
        packet.proof = native;
        let full = encode_packet(&packet).unwrap();
        assert_eq!(decode_packet(&full, &packet.context).unwrap(), packet);
        let refs =
            encode_referenced_packet(&packet, &store.checkpoint(), &indices, &store).unwrap();
        assert_eq!(
            decode_referenced_packet(&refs, &packet.context, &store.checkpoint(), &store).unwrap(),
            packet
        );
        assert_eq!(
            full.len(),
            173_426 + encode_proof(&packet.proof).unwrap().len()
        );
        assert_eq!(
            refs.len(),
            16_118 + encode_proof(&packet.proof).unwrap().len()
        );
        assert!(v1::decode_packet(&full, &packet.context).is_err());
        assert!(decode_packet(&v1::encode_packet(&packet).unwrap(), &packet.context).is_err());
        assert_eq!(
            v1::decode_packet(&v1::encode_packet(&packet).unwrap(), &packet.context).unwrap(),
            packet
        );
    }
}

#[test]
fn packet_public_checks_precede_lookup_and_membership_is_authenticated() {
    let (packet, store) = packet();
    let indices = std::array::from_fn(|i| i as u64);
    let checkpoint = store.checkpoint();
    let full = encode_packet(&packet).unwrap();
    let refs = encode_referenced_packet(&packet, &checkpoint, &indices, &store).unwrap();
    for offset in [0, 8, 10, 12, 44, 76, 80, 112, 144] {
        let mut changed = refs.clone();
        changed[offset] ^= 0xff;
        assert!(
            decode_referenced_packet(&changed, &packet.context, &checkpoint, &NoLookup).is_err()
        );
    }
    for offset in [0, 8, 10, 12, 44, 76] {
        let mut changed = full.clone();
        changed[offset] ^= 1;
        assert!(decode_packet(&changed, &packet.context).is_err());
    }
    assert!(
        decode_referenced_packet(&refs[..80], &packet.context, &checkpoint, &NoLookup).is_err()
    );
    let mut accounts: Vec<AccountBytes> = packet.statement[32..32 + RING_ACCOUNTS * ACCOUNT_BYTES]
        .chunks_exact(ACCOUNT_BYTES)
        .map(|a| a.try_into().unwrap())
        .collect();
    accounts[0][0] ^= 1;
    let wrong_store = LedgerSnapshot::new([23; 32], [19; 32], accounts).unwrap();
    assert!(decode_referenced_packet(&refs, &packet.context, &checkpoint, &wrong_store).is_err());
    let mut wrong = indices;
    wrong[0] = 1;
    assert!(encode_referenced_packet(&packet, &checkpoint, &wrong, &store).is_err());
}

#[test]
fn deterministic_malformed_input_corpus_is_bounded_and_never_panics() {
    let canonical = encode_proof(&centered()).unwrap();
    let mut state = 0xdecafbad_u64;
    for iteration in 0..256 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut bytes = canonical.clone();
        let offset = state as usize % bytes.len();
        bytes[offset] ^= (state >> 32) as u8 | 1;
        if iteration % 4 == 0 {
            bytes.truncate(offset);
        }
        if let Ok(native) = decode_proof(&bytes) {
            assert_eq!(encode_proof(&native).unwrap(), bytes);
        }
    }
}
