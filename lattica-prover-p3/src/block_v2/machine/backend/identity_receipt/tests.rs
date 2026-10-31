use super::*;

fn fingerprint(domain: u64, fields: &[u64]) -> StreamFingerprint {
    fingerprint_stream(domain, |sink| fields.iter().try_for_each(|&v| sink(v))).unwrap()
}

#[test]
fn sealed_hint_matches_only_identical_domain_count_and_canonical_stream() {
    let fields = [7, 11, 19, 23, 31, 37];
    let original = fingerprint(3, &fields);
    // A private synthetic receipt exercises matching; public callers cannot
    // manufacture receipts or set the protocol identity.
    let receipt = RegisteredIdentityReceipt::from_gpu_result([41, 43, 47, 53], original.clone());
    assert_eq!(
        receipt.matching_id(&fingerprint(3, &fields)),
        Some([41, 43, 47, 53])
    );
    assert!(receipt.matching_id(&fingerprint(5, &fields)).is_none());
    assert!(receipt.matching_id(&fingerprint(3, &fields[..5])).is_none());
    for index in 0..fields.len() {
        let mut changed = fields;
        changed[index] += 1;
        assert!(receipt.matching_id(&fingerprint(3, &changed)).is_none());
    }
    let mut reordered = fields;
    reordered.swap(0, 1);
    assert!(receipt.matching_id(&fingerprint(3, &reordered)).is_none());
    for mutation in 0..3 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.domain += 1,
            1 => changed.fields += 1,
            _ => changed.digest[17] ^= 1,
        }
        assert!(receipt.matching_id(&changed).is_none());
    }
    assert_eq!(
        receipt.accounted_bytes(),
        core::mem::size_of::<RegisteredIdentityReceipt>()
    );
    assert!(receipt.accounted_bytes() <= 128);
}

#[test]
fn fingerprint_rejects_noncanonical_fields_domains_and_changed_stream_length() {
    assert!(fingerprint_stream(MODULUS, |_| Ok(())).is_err());
    assert!(fingerprint_stream(1, |sink| sink(MODULUS)).is_err());
    for first_count in [0usize, 1, 3] {
        let mut pass = 0;
        let result = fingerprint_stream(1, |sink| {
            let count = if pass == 0 { first_count } else { 2 };
            pass += 1;
            (0..count).try_for_each(|_| sink(1))
        });
        assert!(result.is_err());
    }
    let mut pass = 0;
    assert!(fingerprint_stream(1, |sink| {
        pass += 1;
        sink(if pass == 1 { 1 } else { MODULUS })
    })
    .is_err());
    assert!(fingerprint_stream(1, |_| Err("source error".into())).is_err());
    assert_eq!(fingerprint(0, &[]).fields, 0);
    assert_eq!(fingerprint(MODULUS - 1, &[MODULUS - 1]).fields, 1);
}
