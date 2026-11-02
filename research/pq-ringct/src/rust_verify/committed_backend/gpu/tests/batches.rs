use super::*;
use lattica_prover_p3::block_v2::native_gpu::{NodeCommitment, FieldCommitment};

#[test]
#[ignore = "exclusive admitted OpenCL; bounded commitment batches, scalar parity and rejection"]
fn commitment_batches_match_scalar_and_reject_invalid_inputs() {
    let worker = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30, device_bytes: 8 << 30, max_rows: 4096 }).unwrap();
    let good = || worker.with_witness_preparation(8 << 20, |op| {
        op.enable_reusable_storage()?;
        assert!(op.commit_node_batch(&[])?.is_empty());
        assert!(op.commit_field_batch(&[])?.is_empty());
        for count in [1, 63, 64] {
            for q in [Q, QHAT] {
                let values: Vec<[u64; D]> = (0..count).map(|n| core::array::from_fn(|i| (i as u64 * 7919 + n as u64) % q)).collect();
                let expected = values.iter().map(|v| op.commit_canonical_node(v, q)).collect::<Result<Vec<_>, _>>()?;
                let inputs: Vec<_> = values.iter().map(|values| NodeCommitment::Canonical { values, modulus: q }).collect();
                assert_eq!(op.commit_node_batch(&inputs)?, expected);
            }
            let values: Vec<[i64; D]> = (0..count).map(|n| core::array::from_fn(|i| [-2147483647, -1, 0, 1, 2147483647][(i+n)%5])).collect();
            let expected = values.iter().map(|v| op.commit_signed_node(v)).collect::<Result<Vec<_>, _>>()?;
            assert_eq!(op.commit_node_batch(&values.iter().map(NodeCommitment::Signed).collect::<Vec<_>>())?, expected);
            let values: Vec<[u8; 32]> = (0..count).map(|n| core::array::from_fn(|i| (i+n) as u8)).collect();
            let expected = values.iter().map(|v| op.commit_bytes32_node(v)).collect::<Result<Vec<_>, _>>()?;
            assert_eq!(op.commit_node_batch(&values.iter().map(NodeCommitment::Bytes).collect::<Vec<_>>())?, expected);
        }
        let lengths = [0, 1, 3, 4, 5, 4095, 4096, 4097];
        let values: Vec<Vec<u64>> = lengths.iter().map(|&n| (0..n).map(|i| i as u64).collect()).collect();
        let inputs: Vec<_> = values.iter().map(|words| FieldCommitment { initial: [7, words.len() as u64, 0, 1], words }).collect();
        let expected = inputs.iter().map(|v| op.commit_field_chunks(v.initial, v.words)).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(op.commit_field_batch(&inputs)?, expected);
        assert_eq!(op.commit_field_batch(&[inputs[0]; 64])?, vec![expected[0]; 64]);
        for count in [131072, 131073] {
            let words: Vec<_> = (0..count).map(|i| i as u64).collect();
            let initial = [17, count as u64, 0, 0];
            let expected = op.commit_field_chunks(initial, &words)?;
            let mut batch = crate::graph_tree::commitment_batches::FieldBatch::new(op, 1, true)?;
            batch.push(initial, words)?;
            assert_eq!(batch.finish()?, vec![expected.map(Val::from_u64)]);
        }
        Ok(())
    });
    good().unwrap();
    for failure in 0..13 {
        assert!(worker.with_witness_preparation(8 << 20, |op| {
            op.enable_reusable_storage()?;
            let polynomial = [0; D];
            let canonical = NodeCommitment::Canonical { values: &polynomial, modulus: Q };
            let rejected = match failure {
                0 => op.commit_node_batch(&[canonical; 65]),
                1 => op.commit_node_batch(&[canonical, NodeCommitment::Bytes(&[0; 32])]),
                2 => op.commit_node_batch(&[canonical, NodeCommitment::Canonical { values: &polynomial, modulus: QHAT }]),
                3..=5 => {
                    let invalid = [Q; D];
                    let mut inputs = [canonical; 64];
                    inputs[[0, 31, 63][failure-3]] = NodeCommitment::Canonical { values: &invalid, modulus: Q };
                    op.commit_node_batch(&inputs)
                }
                6 => op.commit_node_batch(&[NodeCommitment::Signed(&[i64::MIN; D])]),
                7 => op.commit_field_batch(&[FieldCommitment { initial: [0; 4], words: &[] }; 65]),
                8 => op.commit_field_batch(&[FieldCommitment { initial: [0; 4], words: &vec![0; 131073] }]),
                9..=11 => {
                    let mut inputs = [FieldCommitment { initial: [0; 4], words: &[] }; 64];
                    inputs[[0, 31, 63][failure-9]] = FieldCommitment { initial: [0; 4], words: &[u64::MAX] };
                    op.commit_field_batch(&inputs)
                }
                12 => op.commit_field_batch(&[FieldCommitment { initial: [u64::MAX; 4], words: &[] }]),
                _ => unreachable!(),
            };
            assert!(rejected.is_err());
            assert!(op.commit_bytes32_node(&[0; 32]).is_err());
            assert!(op.commit_node_batch(&[]).is_err());
            Ok(())
        }).is_err());
    }
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = worker.with_witness_preparation(8 << 20, |op| -> Result<(), String> {
            op.enable_reusable_storage()?;
            op.commit_node_batch(&[NodeCommitment::Bytes(&[255; 32]); 64])?;
            panic!("injected batch unwind");
        });
    }));
    assert!(unwind.is_err());
    worker.with_witness_preparation(8 << 20, |op| {
        op.enable_reusable_storage()?;
        assert_eq!(op.commit_node_batch(&[NodeCommitment::Bytes(&[255; 32])])?, vec![op.commit_bytes32_node(&[255; 32])?]);
        Ok(())
    }).unwrap();
    assert_eq!(worker.report()["operations"]["prove_calls"], 0);
}

#[test]
#[ignore = "exclusive admitted OpenCL; pending graph publication and failed batch finalization"]
fn pending_graph_roots_cannot_escape_finalization() {
    let worker = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30, device_bytes: 8 << 30, max_rows: 4096 }).unwrap();
    assert!(worker.with_witness_preparation(8 << 20, |op| {
        op.enable_reusable_storage()?;
        let device = PreparedDevice::new(op);
        let mut backend = CommittedBackend::with_device([0; 32], &device);
        backend.byte_node([7; 32], Source::Fixed);
        assert!(backend.pending_commitments);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.into_unproved_graph())).is_err());
        Ok(())
    }).is_err()); // A scope with only pending roots also lacks a completed GPU operation.
    assert!(worker.with_witness_preparation(8 << 20, |op| {
        op.enable_reusable_storage()?;
        let device = PreparedDevice::new(op);
        let mut backend = CommittedBackend::with_device([0; 32], &device);
        backend.canonical_node([Q; D], Q, Source::Fixed);
        assert!(backend.finish_device_commitments().is_err());
        let diagnostic = backend.failure.as_ref().unwrap().as_ptr();
        assert!(backend.finish_device_commitments().is_err());
        assert_eq!(backend.failure.as_ref().unwrap().as_ptr(), diagnostic);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.into_unproved_graph())).is_err());
        Ok(())
    }).is_err());
}
