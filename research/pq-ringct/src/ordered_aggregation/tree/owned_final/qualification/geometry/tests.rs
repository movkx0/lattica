use super::*;

#[path = "differential.rs"]
mod differential;

#[test]
fn all_eighteen_heights_fit_the_unchanged_inner_and_decode_caps() {
    let envelope = TransportEnvelope::for_root().unwrap();
    assert_eq!(PinnedProfile::current().publics, 25);
    assert_eq!(envelope.cases.len(), 18);
    for (index, case) in envelope.cases.iter().enumerate() {
        assert_eq!(case.rows, 1 << (index + 3));
        assert_eq!(case.encoded_inner_bytes, case.canonical_bytes + 8);
        assert_eq!(
            case.decoded_cumulative_bytes,
            case.decoded_vector_bytes + case.canonical_bytes
        );
        assert!(case.encoded_inner_bytes <= 2 << 20);
        assert!(case.decoded_cumulative_bytes <= 64 << 20);
        assert_eq!(case.max_sequence, 200);
        assert!(case.logical_items <= 1 << 20);
        assert!(case.compound_depth <= 32);
        assert!(case.decoder_allocations > 128);
        assert_eq!(case.decoded_fixed_proof_bytes, size_of::<Proof>());
        if index > 0 {
            let prior = envelope.cases[index - 1];
            assert!(case.encoded_inner_bytes > prior.encoded_inner_bytes);
            assert!(case.decoded_cumulative_bytes > prior.decoded_cumulative_bytes);
        }
    }
    assert_eq!(envelope.encoded_inner_bytes, envelope.cases[17].encoded_inner_bytes);
    assert_eq!(
        envelope.decoded_cumulative_bytes,
        envelope.cases[17].decoded_cumulative_bytes
    );
}

#[test]
fn invalid_height_and_local_profile_drift_are_refused() {
    for rows in [0, 1, 4, 9, (1 << 20) + 1, 1 << 21, usize::MAX] {
        assert_eq!(for_height(rows), Err(Refusal::Height));
    }
    let mutations: [fn(&mut PinnedProfile); 10] = [
        |p| p.publics = 46,
        |p| p.lanes = 8,
        |p| p.opcode_bits = 4,
        |p| p.queries = 64,
        |p| p.log_blowup = 3,
        |p| p.cap_height = 7,
        |p| p.magic = *b"LBV2RP01",
        |p| p.inner_limit += 1,
        |p| p.decode_limit += 1,
        |p| p.challenge_size = 16,
    ];
    for mutate in mutations {
        let mut profile = PinnedProfile::current();
        mutate(&mut profile);
        assert_eq!(profile.check(), Err(Refusal::Profile));
    }
}

#[test]
fn fixed_scalars_and_varint_lengths_have_separate_guard_accounting() {
    assert_eq!(layout::varint_len(0), 1);
    assert_eq!(layout::varint_len(127), 1);
    assert_eq!(layout::varint_len(128), 2);
    assert_eq!(layout::varint_len(256), 2);
    assert_eq!(layout::varint_len(usize::MAX), 10);
    let words = scalar().vector(128, size_of::<Val>()).unwrap();
    assert_eq!(words.encoded, 2 + 128 * 8);
    assert_eq!(words.backing, 128 * 8);
    assert_eq!(words.items, 128); // Not 128 * eight raw codec bytes.
    assert_eq!(words.depth, 1);
    assert_eq!(words.allocations, 1);
    let extension = extension().unwrap();
    assert_eq!(extension.encoded, 24);
    assert_eq!(extension.backing, 0);
    assert_eq!(extension.items, 5); // Two struct fields plus three array entries.
    assert_eq!(extension.depth, 2);
}

#[test]
fn nested_vectors_count_headers_backing_and_canonical_copy_additively() {
    let nested = scalar()
        .vector(4, size_of::<Val>()).unwrap()
        .vector(2, size_of::<Vec<Val>>()).unwrap();
    assert_eq!(nested.backing, 2 * 4 * 8 + 2 * size_of::<Vec<Val>>());
    assert_eq!(nested.encoded, 1 + 2 * (1 + 4 * 8));
    assert_eq!(nested.allocations, 3);
    assert_eq!(nested.items, 10);
    let result = finish(8, nested).unwrap();
    assert_eq!(result.decoded_cumulative_bytes, nested.backing + nested.encoded);
    assert_eq!(result.decoder_allocations, 4);
    let empty = extension().unwrap().vector(0, size_of::<Challenge>()).unwrap();
    assert_eq!(empty.encoded, 1);
    assert_eq!(empty.backing, 0);
    assert_eq!(empty.allocations, 0);
    assert_eq!(empty.items, 0);
    assert_eq!(empty.depth, 1);
}

#[test]
fn magic_is_inside_encoding_cap_and_outside_canonical_copy() {
    let exact = Layout::scalar(INNER_LIMIT - MAGIC_BYTES);
    let accepted = finish(8, exact).unwrap();
    assert_eq!(accepted.encoded_inner_bytes, INNER_LIMIT);
    assert_eq!(accepted.canonical_bytes, INNER_LIMIT - MAGIC_BYTES);
    assert_eq!(
        finish(8, Layout::scalar(INNER_LIMIT - MAGIC_BYTES + 1)),
        Err(Refusal::InnerEncoding)
    );
}

#[test]
fn decoder_backing_limit_is_cumulative_and_exact() {
    let mut exact = Layout::scalar(32);
    exact.backing = DECODE_LIMIT - 32;
    assert_eq!(finish(8, exact).unwrap().decoded_cumulative_bytes, DECODE_LIMIT);
    exact.backing += 1;
    assert_eq!(finish(8, exact), Err(Refusal::DecodeStorage));
    // Both components independently fit; their sum must still be rejected.
    assert!(exact.encoded < DECODE_LIMIT && exact.backing < DECODE_LIMIT);
}

#[test]
fn codec_sequence_depth_and_item_limits_refuse_one_above_boundary() {
    for (field, failure, maximum) in [
        (0, Refusal::Sequence, MAX_SEQUENCE),
        (1, Refusal::Depth, MAX_DEPTH),
        (2, Refusal::Items, MAX_ITEMS),
    ] {
        let mut shape = Layout::EMPTY;
        let set = |shape: &mut Layout, value| match field {
            0 => shape.max_sequence = value,
            1 => shape.depth = value,
            2 => shape.items = value,
            _ => unreachable!(),
        };
        set(&mut shape, maximum);
        assert!(finish(8, shape).is_ok());
        set(&mut shape, maximum + 1);
        assert_eq!(finish(8, shape), Err(failure));
    }
    assert_eq!(
        finish(8, scalar().vector(257, size_of::<Val>()).unwrap()),
        Err(Refusal::Sequence)
    );
}

#[test]
fn checked_arithmetic_refuses_each_unrepresentable_sum_or_product() {
    assert_eq!(add(usize::MAX, 1), Err(Refusal::Overflow));
    assert_eq!(mul(usize::MAX, 2), Err(Refusal::Overflow));
    assert_eq!(scalar().array(usize::MAX), Err(Refusal::Overflow));
    assert_eq!(Layout::EMPTY.vector(usize::MAX, 2), Err(Refusal::Overflow));
    assert_eq!(finish(8, Layout::scalar(usize::MAX)), Err(Refusal::Overflow));
    let mut backing = Layout::scalar(1);
    backing.backing = usize::MAX;
    assert_eq!(finish(8, backing), Err(Refusal::Overflow));
}
