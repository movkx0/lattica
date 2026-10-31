use super::*;

#[test]
fn receipt_completion_rejects_every_fresh_identity_observation() {
    // Exercise the exact policy called by Transfer::finish without fabricating
    // the core's opaque GPU telemetry or a registered-program capability. The
    // generic payload cannot affect admission; these are its serialized fields.
    let source = ("baseline", false, true);
    assert_eq!(
        checked_identity_provenance(Some(source), None).unwrap(),
        source
    );
    for fresh in [
        source,
        ("baseline", true, true),
        ("sbox-pair-v1", true, true),
    ] {
        // The first iteration is the regression: equal source/fresh metadata
        // still means the new session observed a completed public-hash batch.
        assert!(matches!(
            checked_identity_provenance(Some(source), Some(fresh)),
            Err(Error::Profile)
        ));
        assert!(matches!(
            checked_identity_provenance(None, Some(fresh)),
            Err(Error::Profile)
        ));
    }
    assert!(matches!(
        checked_identity_provenance::<(&str, bool, bool)>(None, None),
        Err(Error::Profile)
    ));
}

#[test]
fn receipt_budget_is_a_sublimit_never_an_added_allowance() {
    let bytes = source_host_bytes().unwrap();
    assert!(bytes > size_of::<Transfer>());
    assert!(bytes <= RECEIPT_LIMIT_BYTES);
    assert!(check_budget(bytes, bytes, bytes).is_ok());
    assert!(check_budget(bytes, bytes - 1, METADATA_LIMIT_BYTES).is_err());
    assert!(check_budget(bytes, RECEIPT_LIMIT_BYTES, bytes - 1).is_err());
    assert!(check_budget(bytes, RECEIPT_LIMIT_BYTES + 1, METADATA_LIMIT_BYTES).is_err());
    assert!(check_budget(bytes, RECEIPT_LIMIT_BYTES, METADATA_LIMIT_BYTES + 1).is_err());
    assert!(check_budget(usize::MAX, RECEIPT_LIMIT_BYTES, METADATA_LIMIT_BYTES).is_err());
}

#[cfg(feature = "gpu-identity-reuse-experiment")]
#[test]
fn public_keys_and_empty_receipts_cannot_authorize_reuse() {
    let (statement, _) = crate::ring::fixture(Context([19; 32])).unwrap();
    let context = statement.context;
    let representation = CompilerRepresentation::FusedTernaryRangesV1;
    let mut transfer = Transfer::new(&statement, context, representation).unwrap();
    assert!(transfer.check_prover_inputs(&statement, context).is_ok());
    assert!(transfer
        .check_expected(&statement, context, representation)
        .is_err());
    let mut changed_context = context;
    changed_context.0[0] ^= 1;
    assert!(transfer
        .check_prover_inputs(&statement, changed_context)
        .is_err());
    assert!(Expected::new(
        &statement,
        context,
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2
    )
    .is_err());
    transfer.phase = Phase::Retired;
    assert!(transfer
        .check_expected(&statement, context, representation)
        .is_ok());
    assert!(transfer.receipt.is_none());
    // Test metadata alone can never mint the opaque core receipt. Actual use
    // still requires one and a real fresh Session; no numeric-ID conversion.
    let mut key = transfer.expected;
    key.public[0] ^= 1;
    assert_ne!(key, transfer.expected);
    transfer.refuse();
    assert!(transfer.check_prover_inputs(&statement, context).is_err());
    assert!(transfer
        .check_expected(&statement, context, representation)
        .is_err());
    assert!(transfer.receipt.is_none());
    key = transfer.expected;
    key.profile[0] ^= 1;
    assert_ne!(key, transfer.expected);
}

#[cfg(feature = "gpu-identity-reuse-experiment")]
#[test]
fn changed_statements_are_rejected_at_both_transfer_boundaries() {
    let (statement, _) = crate::ring::fixture(Context([19; 32])).unwrap();
    let context = statement.context;
    let representation = CompilerRepresentation::FusedTernaryRangesV1;
    let mut transfer = Transfer::new(&statement, context, representation).unwrap();
    for selector in 0..9 {
        let mut changed = statement.clone();
        match selector {
            0 => changed.setup_seed[0] ^= 1,
            1 => changed.serials[0][0] ^= 1,
            2 => changed.ring[0][0].public_key[0][0] ^= 1,
            3 => changed.ring[0][0].coin[0][0] ^= 1,
            4 => changed.recipients[0][0][0] ^= 1,
            5 => changed.output_coins[0][0][0] ^= 1,
            6 => changed.context.0[0] ^= 1,
            7 => changed.profile = crate::Profile::PrivateNoteDirectV1,
            _ => changed.ring.swap(0, 1),
        }
        transfer.phase = Phase::Empty;
        assert!(transfer
            .check_prover_inputs(&changed, changed.context)
            .is_err());
        transfer.phase = Phase::Retired;
        assert!(transfer
            .check_expected(&changed, changed.context, representation)
            .is_err());
    }
    assert!(transfer
        .check_expected(&statement, context, representation)
        .is_ok());
}

#[test]
fn device_identity_binding_checks_each_field_and_length_tags() {
    let device = lattica_prover_p3::gpu_device::Identity {
        opencl_index: 0,
        uuid: Some("GPU-01234567-89ab-cdef-0123-456789abcdef".into()),
        name: "RTX 5080".into(),
        pci: Some("0000:01:00.0".into()),
        global_bytes: 16 << 30,
        max_allocation_bytes: 4 << 30,
        driver: "test-driver".into(),
    };
    let expected = device_identity_binding(&device).unwrap();
    for selector in 0..8 {
        let mut changed = device.clone();
        match selector {
            0 => changed.opencl_index += 1,
            1 => changed.uuid.as_mut().unwrap().push('1'),
            2 => changed.name.push('1'),
            3 => changed.pci.as_mut().unwrap().push('1'),
            4 => changed.driver.push('1'),
            5 => changed.global_bytes -= 1,
            6 => changed.max_allocation_bytes -= 1,
            _ => changed.pci = None,
        }
        assert_ne!(device_identity_binding(&changed).unwrap(), expected);
    }
    for uuid in [None, Some(String::new())] {
        let mut changed = device.clone();
        changed.uuid = uuid;
        assert!(device_identity_binding(&changed).is_err());
    }
    for selector in 0..4 {
        let mut changed = device.clone();
        match selector {
            0 => changed.uuid = Some("u".repeat(257)),
            1 => changed.name = "n".repeat(257),
            2 => changed.pci = Some("p".repeat(257)),
            _ => changed.driver = "d".repeat(257),
        }
        assert!(device_identity_binding(&changed).is_err());
    }
    let mut left = device.clone();
    left.name = "ab".into();
    left.pci = Some("c".into());
    let mut right = left.clone();
    right.name = "a".into();
    right.pci = Some("bc".into());
    assert_ne!(
        device_identity_binding(&left).unwrap(),
        device_identity_binding(&right).unwrap()
    );
    left.pci = None;
    right = left.clone();
    right.pci = Some(String::new());
    assert_ne!(
        device_identity_binding(&left).unwrap(),
        device_identity_binding(&right).unwrap()
    );
    right = device.clone();
    std::mem::swap(&mut right.name, &mut right.driver);
    assert_ne!(device_identity_binding(&right).unwrap(), expected);
}

#[test]
fn reconstructed_program_changes_are_rejected_without_an_artifact_id() {
    let descriptor = ProofDescriptor {
        active_rows: 5,
        padded_rows: 8,
        wires: 9,
        witness_values: 2,
        canonical_manifest_digest: [3; 32],
        registered_program_id: [7; 4],
    };
    let transfer = Transfer {
        expected: Expected {
            context: [1; 32],
            public: [2; 4],
            profile: [3; 32],
        },
        descriptor: Some(descriptor),
        receipt: None,
        device: [0; 64],
        phase: Phase::Retired,
        captured: None,
        original_public_hash: None,
    };
    let mut no_authority = descriptor;
    no_authority.registered_program_id = [0; 4];
    assert!(transfer.check_reconstructed(no_authority).is_ok());
    for selector in 0..5 {
        let mut changed = descriptor;
        match selector {
            0 => changed.active_rows += 1,
            1 => changed.padded_rows *= 2,
            2 => changed.wires += 1,
            3 => changed.witness_values += 1,
            _ => changed.canonical_manifest_digest[0] ^= 1,
        }
        assert!(transfer.check_reconstructed(changed).is_err());
    }
}
