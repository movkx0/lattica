//! Packet invariants with private synthetic tickets; not proof qualification.
use super::*;
use crate::block_v2::{
    execution::job::test_support::{pin, typed_pin, typed_wallet},
    machine::typed_pairs,
};

fn request(job: &Job, children: &[Job], inputs: Vec<Vec<u8>>) -> Request {
    let kind = if job.wallet_inputs().is_empty() {
        ArtifactKind::Node
    } else {
        ArtifactKind::Wallet
    };
    Request {
        key: [7; 32],
        resources: Resources {
            ram_bytes: 100,
            vram_bytes: 50,
            scratch_bytes: 100,
            threads: 1,
        },
        pin: job.pin(),
        job: job.id(),
        operation: job.operation(),
        start: job.start(),
        expected: job.expected(),
        children: children
            .iter()
            .map(|child| Child {
                job: child.id(),
                operation: child.operation(),
                start: child.start(),
                expected: child.expected(),
            })
            .collect(),
        manifest: inputs
            .iter()
            .map(|b| ArtifactRef::from_bytes(kind, b).unwrap())
            .collect(),
        inputs: inputs.into_iter().map(Arc::from).collect(),
    }
}

#[test]
fn all_typed_pairs_round_trip_and_reject_legacy_family_or_mode_substitution() {
    for (mode, leaves) in typed_pairs::PAIRS {
        let left = typed_wallet(1, leaves[0] as u8, &[1]);
        let right = typed_wallet(2, leaves[1] as u8, &[2]);
        let job = Job::typed_pair(0, left, Some(right)).unwrap();
        assert_eq!(
            job.operation(),
            Operation::TypedPair {
                mode: mode as u8,
                padded: false
            }
        );
        let encoded = request(&job, &[], vec![vec![1], vec![2]]).encode().unwrap();
        assert_eq!(&encoded[..8], TYPED_REQUEST_MAGIC);
        let decoded = Request::decode(&encoded, typed_pin(), [9; 32]).unwrap();
        assert_eq!(decoded.job, job.id());
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert!(Request::decode(&encoded, pin(), [9; 32]).is_err());
        let mut wrong = encoded.clone();
        wrong[..8].copy_from_slice(REQUEST_MAGIC);
        assert!(Request::decode(&wrong, typed_pin(), [9; 32]).is_err());
        let mut wrong = encoded.clone();
        wrong[165] = 64;
        assert!(Request::decode(&wrong, typed_pin(), [9; 32]).is_err());
        let mut wrong = encoded.clone();
        wrong.push(0);
        assert!(Request::decode(&wrong, typed_pin(), [9; 32]).is_err());
        for end in 0..encoded.len() {
            assert!(Request::decode(&encoded[..end], typed_pin(), [9; 32]).is_err());
        }
    }
}

#[test]
fn padded_pair_requires_identical_artifacts_and_finalizer_binds_child_geometry() {
    let wallet = typed_wallet(1, 4, &[1]);
    let pair = Job::typed_pair(0, wallet, None).unwrap();
    let good = request(&pair, &[], vec![vec![1], vec![1]]);
    assert!(good.encode().is_ok());
    assert!(request(&pair, &[], vec![vec![1], vec![2]])
        .encode()
        .is_err());
    let finalizer = Job::finalize(&pair).unwrap();
    let encoded = request(&finalizer, &[pair.clone()], vec![vec![3]])
        .encode()
        .unwrap();
    assert_eq!(
        Request::decode(&encoded, typed_pin(), [9; 32]).unwrap().job,
        finalizer.id()
    );
    let mut wrong = request(&finalizer, &[pair.clone()], vec![vec![3]]);
    wrong.children[0].start = 2;
    assert!(wrong.encode().is_err());
    let mut wrong = request(&finalizer, &[pair], vec![vec![3]]);
    wrong.expected.root[0] ^= 1;
    assert!(wrong.encode().is_err());
}

#[test]
fn typed_resource_assignment_and_result_family_are_encoded_separately() {
    let pair = Job::typed_pair(0, typed_wallet(1, 1, &[1]), None).unwrap();
    let mut packet = request(&pair, &[], vec![vec![1], vec![1]]);
    assert_eq!(
        Request::decode(&packet.encode().unwrap(), typed_pin(), [9; 32])
            .unwrap()
            .resources,
        packet.resources
    );
    packet.resources.threads = 0;
    assert!(packet.encode().is_err());
    let result = encode_result_for(
        true,
        [7; 32],
        pair.id(),
        [8; 32],
        &[9],
        Timings {
            input_verification_ms: 0,
            proving_ms: 0,
            serialization_ms: 0,
        },
        CacheStats::default(),
    )
    .unwrap();
    assert_eq!(&result[..8], TYPED_RESULT_MAGIC);
    let legacy = encode_result(
        [7; 32],
        pair.id(),
        [8; 32],
        &[9],
        Timings {
            input_verification_ms: 0,
            proving_ms: 0,
            serialization_ms: 0,
        },
        CacheStats::default(),
    )
    .unwrap();
    assert_eq!(&legacy[..8], RESULT_MAGIC);
    assert_eq!(&result[8..], &legacy[8..]);
}
