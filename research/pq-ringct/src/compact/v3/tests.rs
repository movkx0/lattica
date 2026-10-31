use super::super::{
    ledger::{
        AccountBytes, AccountWitness, LedgerSnapshot, LedgerSource, ACCOUNT_BYTES, RING_ACCOUNTS,
    },
    proof as v1_proof, radix, v2, Error,
};
use super::{ans, head, models::GROUPS, proof, *};
use crate::native_packet::{self, NativePacket};

fn fixture(mut f: impl FnMut(usize, usize, u32) -> u32) -> Vec<u8> {
    let mut out = Vec::new();
    for (group, part) in v1_proof::PARTS.iter().enumerate() {
        match *part {
            v1_proof::Part::Raw(n) => out.extend(0..n as u8),
            v1_proof::Part::Polys {
                count, width, base, ..
            } => {
                for poly in 0..count {
                    let digits = std::array::from_fn(|i| f(group, poly * 256 + i, base));
                    let start = out.len();
                    out.resize(start + 32 * width, 0);
                    radix::pack_bits(&digits, width, &mut out[start..]).unwrap();
                }
            }
        }
    }
    out
}

fn representative() -> Vec<u8> {
    let mut seed = 0x2e7a_017d_9760_b211u64;
    fixture(|group, index, base| {
        if group < 3 {
            return if group == 0 && [0, 1, 2, 3, 128, 129, 130, 131].contains(&index) {
                0
            } else {
                (index as u32 * 1777 + 1) % base
            };
        }
        if group == 3 {
            return if index < 44 {
                if index % 2 == 0 {
                    0
                } else {
                    2
                }
            } else {
                1
            };
        }
        // Deterministic approximate Gaussian, solely to exercise the entropy
        // mode without invoking a prover. Real proofs are tested separately.
        let sigma = match group {
            5 => 95,
            7 => 1_036_000,
            _ => 6400,
        };
        let mut sum = 0i64;
        for _ in 0..12 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            sum += (seed & 65535) as i64;
        }
        let signed = ((sum - 6 * 65535) * sigma / 65535)
            .clamp(-((base - 1) as i64 / 2), (base - 1) as i64 / 2);
        (signed + (base - 1) as i64 / 2) as u32
    })
}

fn roundtrip(native: &[u8]) -> Vec<u8> {
    let encoded = encode_proof(native).unwrap();
    assert!(encoded.len() <= v2::encode_proof(native).unwrap().len());
    assert_eq!(decode_proof(&encoded).unwrap(), native);
    encoded
}

#[test]
fn fixed_models_cover_entire_original_domain() {
    assert_eq!(
        GROUPS
            .iter()
            .map(|g| g.count * 32 * g.low_bits)
            .sum::<usize>(),
        proof::LOW_BYTES
    );
    for (group, part) in GROUPS.iter().zip(&v1_proof::PARTS[3..]) {
        let v1_proof::Part::Polys {
            count, width, base, ..
        } = *part
        else {
            panic!("group kind")
        };
        assert_eq!((group.count, group.width, group.base), (count, width, base));
        assert_eq!(group.cdf[0], 0);
        assert_eq!(*group.cdf.last().unwrap(), 65536);
        assert!(group.cdf.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(
            group.cdf.len() - 1,
            (base as usize).div_ceil(1 << group.low_bits)
        );
    }
}

#[test]
fn rans_roundtrip_capacity_and_terminal_state() {
    let cdf = &[0, 32768, 65536];
    let symbols: Vec<_> = (0..4096).map(|i| ((i * 17 + i / 3) % 2) as usize).collect();
    let mut writer = ans::Encoder::new(1024).unwrap();
    for &symbol in symbols.iter().rev() {
        assert!(writer.symbol(symbol, cdf).unwrap());
    }
    let encoded = writer.finish();
    let mut reader = ans::Decoder::new(&encoded).unwrap();
    for &symbol in &symbols {
        assert_eq!(reader.symbol(cdf).unwrap(), symbol as u32);
    }
    reader.finish().unwrap();
    let mut writer = ans::Encoder::new(encoded.len()).unwrap();
    for &symbol in symbols.iter().rev() {
        assert!(writer.symbol(symbol, cdf).unwrap());
    }
    assert_eq!(writer.finish(), encoded);
    let mut writer = ans::Encoder::new(encoded.len() - 1).unwrap();
    assert!(symbols
        .iter()
        .rev()
        .any(|&s| !writer.symbol(s, cdf).unwrap()));
    for initial in [0, ans::LOWER - 1, ans::LOWER << 8, u32::MAX] {
        assert!(ans::Decoder::new(&initial.to_le_bytes()).is_err());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    let mut reader = ans::Decoder::new(&extra).unwrap();
    for _ in &symbols {
        reader.symbol(cdf).unwrap();
    }
    assert!(reader.finish().is_err());
    let mut reader = ans::Decoder::new(&encoded[..encoded.len() - 1]).unwrap();
    assert!(symbols.iter().any(|_| reader.symbol(cdf).is_err()));
    let bad_end = (ans::LOWER + 1).to_le_bytes();
    assert!(ans::Decoder::new(&bad_end).unwrap().finish().is_err());
}

#[test]
fn entropy_mode_and_exact_tie_fallback() {
    let native = representative();
    let encoded = roundtrip(&native);
    assert_eq!(encoded[0], 2);
    assert!(encoded.len() < v2::encode_proof(&native).unwrap().len());
    assert!(proof::candidate(&native, encoded.len()).unwrap().is_none());
    assert_eq!(
        proof::candidate(&native, encoded.len() + 1)
            .unwrap()
            .unwrap(),
        encoded
    );
    assert_eq!(
        decode_proof(&v2::encode_proof(&native).unwrap()),
        Err(Error::NonCanonical)
    );
    assert!(v2::decode_proof(&encoded).is_err());
}

#[test]
fn every_omitted_position_is_guarded_and_reconstructed() {
    let native = representative();
    for index in [0, 1, 2, 3, 128, 129, 130, 131] {
        let mut changed = native.clone();
        let mut digits = radix::unpack_bits(&changed[..896], 28).unwrap();
        digits[index] = 1;
        radix::pack_bits(&digits, 28, &mut changed[..896]).unwrap();
        assert_eq!(roundtrip(&changed), v2::encode_proof(&changed).unwrap());
    }
    let compact = head::encode(&native[..head::NATIVE_BYTES])
        .unwrap()
        .unwrap();
    assert_eq!(
        head::decode(&compact).unwrap(),
        native[..head::NATIVE_BYTES]
    );
    let mut changed = compact;
    // A value Q^248 fits in 847 bytes but is outside the 248-digit domain.
    let mut digits = [0; 256];
    digits[248] = 1;
    radix::encode(&digits, 167_770_241, &mut changed[..847]).unwrap();
    assert_eq!(head::decode(&changed), Err(Error::NonCanonical));
}

#[test]
fn fallback_preserves_extremes_and_existing_minimum_and_maximum() {
    for value in [0, 1, 2] {
        let native = fixture(|_, _, base| match value {
            0 => 0,
            1 => (base - 1) / 2,
            _ => base - 1,
        });
        assert_eq!(roundtrip(&native), v2::encode_proof(&native).unwrap());
    }
    let centered = fixture(|_, _, base| (base - 1) / 2);
    assert_eq!(roundtrip(&centered).len(), MIN_PROOF_BYTES);
    let maximum = fixture(|_, _, base| base - 1);
    assert_eq!(roundtrip(&maximum).len(), MAX_PROOF_BYTES);
}

#[test]
fn invalid_native_coefficients_and_lengths_rejected() {
    let native = representative();
    assert_eq!(
        encode_proof(&native[..native.len() - 1]),
        Err(Error::Length)
    );
    let mut position = 0;
    for part in v1_proof::PARTS {
        match part {
            v1_proof::Part::Raw(n) => position += n,
            v1_proof::Part::Polys {
                count, width, base, ..
            } => {
                let mut changed = native.clone();
                let end = position + 32 * width;
                let mut digits = radix::unpack_bits(&changed[position..end], width).unwrap();
                digits[255] = base;
                radix::pack_bits(&digits, width, &mut changed[position..end]).unwrap();
                assert!(encode_proof(&changed).is_err());
                position += count * 32 * width;
            }
        }
    }
}

#[test]
fn malformed_streams_and_boundary_lengths_are_rejected() {
    let encoded = roundtrip(&representative());
    for length in [
        0,
        1,
        MIN_PROOF_BYTES - 1,
        proof::ANS_START,
        proof::ANS_START + 3,
        encoded.len() - 1,
    ] {
        assert!(decode_proof(&encoded[..length]).is_err());
    }
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(decode_proof(&changed).is_err());
    changed[0] = 255;
    assert_eq!(decode_proof(&changed), Err(Error::Format));
    let mut changed = encoded.clone();
    changed[1..848].fill(255);
    assert_eq!(decode_proof(&changed), Err(Error::NonCanonical));
    for state in [0u32, ans::LOWER - 1, ans::LOWER << 8, u32::MAX] {
        let mut changed = encoded.clone();
        changed[proof::ANS_START..proof::ANS_START + 4].copy_from_slice(&state.to_le_bytes());
        assert_eq!(decode_proof(&changed), Err(Error::NonCanonical));
    }
    assert!(decode_proof(&vec![2; MAX_PROOF_BYTES + 1]).is_err());
}

#[test]
fn last_bucket_remainders_cannot_exceed_native_coefficient_bounds() {
    let mut native = representative();
    let start = head::NATIVE_BYTES + 32 * 2 + 49 * 32 * 17;
    let mut digits = radix::unpack_bits(&native[start..start + 32 * 11], 11).unwrap();
    digits[0] = 1130;
    radix::pack_bits(&digits, 11, &mut native[start..start + 32 * 11]).unwrap();
    let mut encoded = roundtrip(&native);
    assert_eq!(encoded[0], 2);
    let low_start = 1 + head::COMPACT_BYTES + 49 * 32 * 10;
    // q=70 and r=10 represent the largest allowed zigzag value, 1130.
    // A syntactically valid r=15 must not decode to coefficient 1135.
    encoded[low_start] |= 15;
    assert_eq!(decode_proof(&encoded), Err(Error::NonCanonical));
}

#[test]
fn decodable_entropy_stream_is_rejected_when_an_older_mode_is_smaller() {
    let native = fixture(|group, _, base| if group < 3 { 0 } else { (base - 1) / 2 });
    let previous = v2::encode_proof(&native).unwrap();
    let alternate = proof::candidate(&native, MAX_PROOF_BYTES).unwrap().unwrap();
    assert!(alternate.len() > previous.len());
    assert_eq!(encode_proof(&native).unwrap(), previous);
    assert_eq!(decode_proof(&alternate), Err(Error::NonCanonical));
}

#[test]
fn malformed_mutations_either_reject_or_have_unique_native_roundtrip() {
    let encoded = roundtrip(&representative());
    let mut state = 0xe81a_ba55_5678_9123u64;
    for i in 0..128 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut changed = encoded.clone();
        let offset = state as usize % changed.len();
        changed[offset] ^= (state >> 32) as u8 | 1;
        if i % 4 == 0 {
            changed.truncate(offset);
        }
        if let Ok(native) = decode_proof(&changed) {
            assert_eq!(encode_proof(&native).unwrap(), changed);
        }
    }
}

fn packet() -> (NativePacket, LedgerSnapshot) {
    let mut statement = vec![0; native_packet::STATEMENT_BYTES];
    statement[..32].fill(19);
    for (i, word) in statement[32..native_packet::STATEMENT_BYTES - 64]
        .chunks_exact_mut(4)
        .enumerate()
    {
        word.copy_from_slice(&(i as u32 * 17).to_le_bytes());
    }
    let accounts: Vec<AccountBytes> = statement[32..32 + RING_ACCOUNTS * ACCOUNT_BYTES]
        .chunks_exact(ACCOUNT_BYTES)
        .map(|a| a.try_into().unwrap())
        .collect();
    let ledger = LedgerSnapshot::new([23; 32], [19; 32], accounts).unwrap();
    (
        NativePacket {
            context: [7; 32],
            statement,
            proof: representative(),
        },
        ledger,
    )
}

struct NoLookup;
impl LedgerSource for NoLookup {
    fn account(&self, _: u64) -> Option<AccountWitness<'_>> {
        panic!("lookup before public admission")
    }
}

#[test]
fn packet_versions_modes_and_ledger_trust() {
    let (mut packet, ledger) = packet();
    let checkpoint = ledger.checkpoint();
    let indices = std::array::from_fn(|i| i as u64);
    for proof in [representative(), fixture(|_, _, base| base - 1)] {
        packet.proof = proof;
        let full = encode_packet(&packet).unwrap();
        assert_eq!(decode_packet(&full, &packet.context).unwrap(), packet);
        assert!(v2::decode_packet(&full, &packet.context).is_err());
        assert!(decode_packet(&v2::encode_packet(&packet).unwrap(), &packet.context).is_err());
        let refs = encode_referenced_packet(&packet, &checkpoint, &indices, &ledger).unwrap();
        assert_eq!(
            decode_referenced_packet(&refs, &packet.context, &checkpoint, &ledger).unwrap(),
            packet
        );
        for offset in [0, 8, 10, 12, 44, 76, 80, 112, 144] {
            let mut changed = refs.clone();
            changed[offset] ^= 255;
            assert!(
                decode_referenced_packet(&changed, &packet.context, &checkpoint, &NoLookup)
                    .is_err()
            );
        }
        let mut other = indices;
        other[0] = 1;
        assert!(encode_referenced_packet(&packet, &checkpoint, &other, &ledger).is_err());
        let wrong =
            LedgerSnapshot::new([24; 32], [19; 32], vec![[0; ACCOUNT_BYTES]; RING_ACCOUNTS])
                .unwrap();
        assert!(decode_referenced_packet(&refs, &packet.context, &checkpoint, &wrong).is_err());
    }
}
