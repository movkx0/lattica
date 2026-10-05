//! Tiny native fixtures test the codec/state boundary, not proof validity.
//! Ignored checks below explicitly use independently pinned real public proofs.
use super::*;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::{CandidateId, Completion, Lease, Limits, WorkerId},
    job::test_support::{pin, wallet},
    journal::{DurableDag, JournalLimits},
    launch::{LaunchLimits, LaunchStore},
    test_fixture,
};
use rand::TryRng;
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

const CHAIN: [u8; 32] = [9; 32];
fn resources() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 0,
        scratch_bytes: 100,
        threads: 1,
    }
}
fn leaf(start: u8) -> Job {
    Job::wrap(start, wallet(u64::from(start) + 1, &[start + 1])).unwrap()
}
fn request(job: &Job, children: &[Job], inputs: Vec<Vec<u8>>) -> Request {
    let kind = if job.operation() == Operation::Merge {
        ArtifactKind::Node
    } else {
        ArtifactKind::Wallet
    };
    Request {
        key: launch::request_digest(b"synthetic lease").unwrap(),
        resources: resources(),
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
            .map(|bytes| ArtifactRef::from_bytes(kind, bytes).unwrap())
            .collect(),
        inputs: inputs.into_iter().map(Arc::from).collect(),
    }
}
fn pair_request() -> Request {
    use crate::block_v2::machine::program::Val;
    use p3_field::PrimeCharacteristicRing;
    let registry = Registry {
        height: 8,
        caps: core::array::from_fn(|_| {
            vec![[Val::ZERO; 4]; 1 << crate::block_v2::profile::CAP_HEIGHT]
        }),
    };
    let pin = RegistryPin::new(
        &registry,
        registry.id().unwrap(),
        WrapperConstruction::GroupedPair,
    )
    .unwrap();
    let context = Context {
        profile_id: pin.profile(),
        chain_id: CHAIN,
    };
    let summaries: Vec<_> = [1, 2]
        .into_iter()
        .map(|v| {
            commitment::leaf(
                context,
                commitment::Entry {
                    kind: commitment::Kind::JoinSplit,
                    statement_digest: [v, 0, 0, 0],
                },
            )
            .unwrap()
        })
        .collect();
    let expected = commitment::merge_nodes(summaries[0], summaries[1]).unwrap();
    Request {
        key: launch::request_digest(b"pair lease").unwrap(),
        resources: resources(),
        pin,
        job: JobId::for_summary(pin, Operation::WrapPair, 0, expected, &[]).unwrap(),
        operation: Operation::WrapPair,
        start: 0,
        expected,
        children: vec![],
        manifest: vec![wallet(1, &[1]).artifact(), wallet(2, &[2]).artifact()],
        inputs: vec![Arc::from([1]), Arc::from([2])],
    }
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "lattica-packet-test-{}",
            crate::block_v2::execution::artifact_store::hex(&nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn owner(&self, pin: RegistryPin, chain: [u8; 32], resources: Resources) -> DurableDag {
        let store = ArtifactStore::create(
            &self.0.join("artifacts"),
            StoreLimits {
                bytes: 64 * (1 << 20),
                entries: 256,
            },
        )
        .unwrap();
        DurableDag::create(
            &self.0.join("journal"),
            JournalLimits {
                snapshot_bytes: 256 * 1024,
            },
            store,
            pin,
            chain,
            1,
            Limits {
                jobs: 256,
                candidates: 8,
                attempts: 128,
                artifact_bytes: 64 * (1 << 20),
                recovery_window_ms: 10,
                workers: resources,
            },
        )
        .unwrap()
    }
    fn launches(&self) -> LaunchStore {
        LaunchStore::create(&self.0.join("launches"), LaunchLimits { records: 16 }).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn attach(d: &mut DurableDag, mut root: Job) -> CandidateId {
    for level in root.expected().level..DEPTH {
        let right = Job::empty(
            root.pin(),
            root.expected().context.chain_id,
            1 << level,
            level,
        )
        .unwrap();
        d.admit(right.clone(), vec![], 0).unwrap();
        root = Job::merge(&root, &right).unwrap();
        d.admit(root.clone(), vec![], 0).unwrap();
    }
    d.attach(root.id(), [1; 32], 7_200_000, 0).unwrap()
}
fn synthetic_assignment(temp: &Temp) -> (DurableDag, Assignment) {
    let mut d = temp.owner(pin(), CHAIN, resources());
    let job = leaf(0);
    d.admit(job.clone(), vec![vec![1]], 0).unwrap();
    attach(&mut d, job.clone());
    let lease = d
        .lease(job.id(), WorkerId(1), resources(), 1, 1000, 0)
        .unwrap();
    let assignment = d.assignment(lease).unwrap();
    (d, assignment)
}
fn bind(temp: &Temp, d: &mut DurableDag, lease: Lease, bytes: &[u8]) -> (LaunchStore, WorkerGate) {
    let mut store = temp.launches();
    let token = store.issue(d, lease, bytes).unwrap();
    let gate = WorkerGate::enter(&temp.0.join("launches"), &token, bytes).unwrap();
    (store, gate)
}

#[test]
fn canonical_packets_roundtrip_all_operation_shapes() {
    let left = leaf(0);
    let right = leaf(1);
    for request in [
        request(&left, &[], vec![vec![1]]),
        pair_request(),
        request(&Job::empty(pin(), CHAIN, 0, 3).unwrap(), &[], vec![]),
        request(
            &Job::merge(&left, &right).unwrap(),
            &[left, right],
            vec![vec![51], vec![52]],
        ),
    ] {
        let bytes = request.encode().unwrap();
        let decoded = Request::decode(&bytes, request.pin, CHAIN).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.job, request.job);
        assert_eq!(decoded.manifest, request.manifest);
    }
}

#[test]
fn frozen_assignment_encodes_exact_launch_key_resources_and_artifacts() {
    let temp = Temp::new();
    let (mut d, assignment) = synthetic_assignment(&temp);
    let bytes = encode_request(&assignment).unwrap();
    let decoded = Request::decode(&bytes, pin(), CHAIN).unwrap();
    assert_eq!(decoded.key, assignment.lease().process_key().unwrap());
    assert_eq!(decoded.resources, assignment.resources());
    assert_eq!(decoded.job, assignment.job().id());
    assert_eq!(decoded.manifest, assignment.manifest());
    let (_store, guard) = bind(&temp, &mut d, assignment.lease(), &bytes);
    decoded.bind(guard.token(), &bytes).unwrap();
    let mut changed = bytes.clone();
    changed[8] ^= 1;
    assert!(decoded.bind(guard.token(), &changed).is_err());
}

#[test]
fn even_valid_launch_hash_cannot_authorize_wrong_packet_key_or_resources() {
    for field in [8, 40] {
        let temp = Temp::new();
        let (mut d, assignment) = synthetic_assignment(&temp);
        let mut bytes = encode_request(&assignment).unwrap();
        bytes[field] ^= 1;
        let decoded = Request::decode(&bytes, pin(), CHAIN).unwrap();
        let (_store, guard) = bind(&temp, &mut d, assignment.lease(), &bytes);
        assert!(decoded.bind(guard.token(), &bytes).is_err());
    }
}

#[test]
fn request_rejects_truncation_trailing_size_and_external_context_changes() {
    let bytes = request(&leaf(0), &[], vec![vec![1]]).encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Request::decode(&bytes[..end], pin(), CHAIN).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(Request::decode(&changed, pin(), CHAIN).is_err());
    assert!(Request::decode(&vec![0; launch::MAX_REQUEST_BYTES + 1], pin(), CHAIN).is_err());
    assert!(Request::decode(&bytes, pin(), [8; 32]).is_err());
    for at in [
        0, 68, 100, 101, 133, 165, 166, 167, 168, 169, 201, 202, 203, 208, 240,
    ] {
        let mut changed = bytes.clone();
        changed[at] ^= 0xff;
        assert!(
            Request::decode(&changed, pin(), CHAIN).is_err(),
            "offset {at}"
        );
    }
}

#[test]
fn lengths_counts_and_noncanonical_fields_reject_before_unbounded_allocation() {
    let bytes = request(&leaf(0), &[], vec![vec![1]]).encode().unwrap();
    for len in [0u32, (MAX_PROOF_BYTES + 1) as u32, u32::MAX] {
        let mut changed = bytes.clone();
        changed[204..208].copy_from_slice(&len.to_le_bytes());
        assert!(Request::decode(&changed, pin(), CHAIN).is_err());
    }
    for offset in [201, 202] {
        let mut changed = bytes.clone();
        changed[offset] = 3;
        assert!(Request::decode(&changed, pin(), CHAIN).is_err());
    }
    for offset in [8, 133, 169, 208] {
        let mut changed = bytes.clone();
        changed[offset..offset + 8].fill(255);
        assert!(Request::decode(&changed, pin(), CHAIN).is_err());
    }
    for value in [
        Resources {
            ram_bytes: 0,
            ..resources()
        },
        Resources {
            ram_bytes: 46 << 30,
            ..resources()
        },
        Resources {
            vram_bytes: 1,
            ..resources()
        },
        Resources {
            scratch_bytes: 129 << 30,
            ..resources()
        },
        Resources {
            threads: 0,
            ..resources()
        },
        Resources {
            threads: 257,
            ..resources()
        },
    ] {
        let mut r = request(&leaf(0), &[], vec![vec![1]]);
        r.resources = value;
        assert!(r.encode().is_err());
    }
}

#[test]
fn ordered_children_and_semantic_job_identity_cannot_be_substituted() {
    let left = leaf(0);
    let right = leaf(1);
    let root = Job::merge(&left, &right).unwrap();
    let base = request(&root, &[left, right], vec![vec![51], vec![52]])
        .encode()
        .unwrap();
    for case in 0..7 {
        let mut r = Request::decode(&base, pin(), CHAIN).unwrap();
        match case {
            0 => r.children.swap(0, 1),
            1 => r.children[1].start = 2,
            2 => r.children[1].expected.context.chain_id = [8; 32],
            3 => r.children[0].job = r.children[1].job,
            4 => r.children[0].operation = Operation::Empty,
            5 => r.children.pop().map(|_| ()).unwrap(),
            _ => r.manifest[0] = ArtifactRef::from_bytes(ArtifactKind::Wallet, &[51]).unwrap(),
        }
        assert!(r.encode().is_err(), "case {case}");
    }
}

fn timings() -> Timings {
    Timings {
        input_verification_ms: 1,
        proving_ms: 2,
        serialization_ms: 3,
    }
}
fn stats() -> CacheStats {
    CacheStats { setups: 1, hits: 0 }
}

#[test]
fn results_bind_original_assignment_packet_and_exact_artifact_but_are_not_tickets() {
    let temp = Temp::new();
    let (_, assignment) = synthetic_assignment(&temp);
    let request = encode_request(&assignment).unwrap();
    // Deliberately not a proof: decoding conveys bytes, never CPU validity.
    let bytes = encode_result(
        assignment.lease().process_key().unwrap(),
        assignment.job().id(),
        launch::request_digest(&request).unwrap(),
        &[1, 2, 3],
        timings(),
        stats(),
    )
    .unwrap();
    let decoded = decode_result(&assignment, &request, &bytes).unwrap();
    assert_eq!(decoded.bytes(), &[1, 2, 3]);
    assert_eq!(decoded.timings(), timings());
    assert_eq!(decoded.stats(), stats());
    let other = Temp::new();
    let (_, other_assignment) = synthetic_assignment(&other);
    assert!(decode_result(&other_assignment, &request, &bytes).is_err());
    let mut wrong_request = request.clone();
    wrong_request[8] ^= 1;
    assert!(decode_result(&assignment, &wrong_request, &bytes).is_err());
    for at in [0, 8, 40, 72, 144, 149, 181] {
        let mut changed = bytes.clone();
        changed[at] ^= 0xff;
        assert!(
            decode_result(&assignment, &request, &changed).is_err(),
            "offset {at}"
        );
    }
}

#[test]
fn result_lengths_and_telemetry_are_bounded_and_do_not_grant_authority() {
    let temp = Temp::new();
    let (_, assignment) = synthetic_assignment(&temp);
    let request = encode_request(&assignment).unwrap();
    let key = assignment.lease().process_key().unwrap();
    let digest = launch::request_digest(&request).unwrap();
    let bytes =
        encode_result(key, assignment.job().id(), digest, &[1], timings(), stats()).unwrap();
    for end in 0..bytes.len() {
        assert!(decode_result(&assignment, &request, &bytes[..end]).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(decode_result(&assignment, &request, &changed).is_err());
    assert!(decode_result(&assignment, &request, &vec![0; MAX_RESULT_BYTES + 1]).is_err());
    for len in [0u32, (MAX_PROOF_BYTES + 1) as u32, u32::MAX] {
        let mut changed = bytes.clone();
        changed[145..149].copy_from_slice(&len.to_le_bytes());
        assert!(decode_result(&assignment, &request, &changed).is_err());
    }
    let excessive = Timings {
        proving_ms: u128::MAX,
        ..timings()
    };
    assert!(encode_result(key, assignment.job().id(), digest, &[1], excessive, stats()).is_err());
    let mut telemetry = bytes.clone();
    telemetry[104..144].fill(255);
    let decoded = decode_result(&assignment, &request, &telemetry).unwrap();
    assert_eq!(decoded.timings().proving_ms, u128::from(u64::MAX));
    assert_eq!(decoded.bytes(), &[1]); // still unverified; telemetry is observational
}

fn real_pair(temp: &Temp, f: &test_fixture::Fixture, r: Resources) -> (DurableDag, Assignment) {
    let mut d = temp.owner(f.pin, [0x5a; 32], r);
    let job = Job::wrap_pair(0, f.wallets[0], f.wallets[1]).unwrap();
    d.admit(job.clone(), vec![f.bytes[0].clone(), f.bytes[1].clone()], 0)
        .unwrap();
    attach(&mut d, job.clone());
    let lease = d.lease(job.id(), WorkerId(1), r, 1, 7_000_000, 0).unwrap();
    let assignment = d.assignment(lease).unwrap();
    (d, assignment)
}

#[test]
#[ignore = "explicit pinned public wallet/root fixtures; CPU packet input verification only"]
fn cpu_packet_verifies_real_pair_empty_and_rejects_substituted_inputs() -> Result<(), Error> {
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let (mut d, assignment) = real_pair(&temp, &f, resources());
    let bytes = encode_request(&assignment)?;
    let (_store, guard) = bind(&temp, &mut d, assignment.lease(), &bytes);
    let worker = CpuWorker::new(f.registry.clone(), f.pin)?;
    let checked = worker.check_packet(&guard, &bytes, [0x5a; 32])?;
    assert_eq!(checked.job, assignment.job().id());
    assert_eq!(checked.resources, resources());
    assert_eq!(checked.expected, assignment.job().expected());
    assert!(worker.check_packet(&guard, &bytes, [1; 32]).is_err());
    let mut decoded = Request::decode(&bytes, f.pin, [0x5a; 32])?;
    decoded.inputs.swap(0, 1);
    decoded.manifest.swap(0, 1);
    assert!(worker.prepare_packet(&decoded).is_err());
    let mut decoded = Request::decode(&bytes, f.pin, [0x5a; 32])?;
    decoded.inputs[0] = Arc::from(f.root_bytes.clone());
    decoded.manifest[0] = ArtifactRef::from_bytes(ArtifactKind::Wallet, &f.root_bytes)?;
    assert!(worker.prepare_packet(&decoded).is_err());
    let job = Job::empty(f.pin, [0x5a; 32], 0, 3)?;
    let empty = request(&job, &[], vec![]);
    assert!(matches!(worker.prepare_packet(&empty)?, Inputs::Empty));
    // Even a well-formed node result does not establish that it is the right job.
    let result = encode_result(
        assignment.lease().process_key()?,
        assignment.job().id(),
        launch::request_digest(&bytes)?,
        &f.root_bytes,
        timings(),
        stats(),
    )?;
    let decoded = decode_result(&assignment, &bytes, &result)?;
    assert!(VerifiedNode::verify(assignment.job(), &f.registry, decoded.bytes()).is_err());
    Ok(())
}

#[test]
#[ignore = "explicit pinned root fixture; repeated subtree is cryptographic input coverage, not host eligibility"]
fn cpu_packet_verifies_both_real_merge_children_without_inner_archives() -> Result<(), Error> {
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let mut d = temp.owner(f.pin, [0x5a; 32], resources());
    let mut roots = Vec::new();
    // Repeat the known public subtree at a new ordered range. Host duplicate-spend
    // policy would reject inclusion; this tests child-proof verification only.
    for start in [0u8, 8] {
        let mut jobs = Vec::new();
        for i in 0..4 {
            let job = Job::wrap_pair(
                start + (2 * i) as u8,
                f.wallets[2 * i],
                f.wallets[2 * i + 1],
            )?;
            d.admit(
                job.clone(),
                vec![f.bytes[2 * i].clone(), f.bytes[2 * i + 1].clone()],
                0,
            )?;
            jobs.push(job);
        }
        while jobs.len() > 1 {
            jobs = jobs
                .chunks_exact(2)
                .map(|pair| {
                    let job = Job::merge(&pair[0], &pair[1])?;
                    d.admit(job.clone(), vec![], 0)?;
                    Ok(job)
                })
                .collect::<Result<Vec<_>, Error>>()?;
        }
        let root = jobs.pop().unwrap();
        let ticket = VerifiedNode::verify(&root, &f.registry, &f.root_bytes)?;
        d.cache_node(ticket, f.root_bytes.clone(), 0)?;
        roots.push(root);
    }
    let job = Job::merge(&roots[0], &roots[1])?;
    d.admit(job.clone(), vec![], 0)?;
    attach(&mut d, job.clone());
    let lease = d.lease(job.id(), WorkerId(1), resources(), 1, 1000, 0)?;
    let bytes = encode_request(&d.assignment(lease)?)?;
    let (_store, guard) = bind(&temp, &mut d, lease, &bytes);
    let worker = CpuWorker::new(f.registry, f.pin)?;
    assert_eq!(
        worker
            .check_packet(&guard, &bytes, [0x5a; 32])?
            .expected
            .count,
        16
    );
    let mut decoded = Request::decode(&bytes, f.pin, [0x5a; 32])?;
    let mut corrupt = decoded.inputs[0].to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    decoded.manifest[0] = ArtifactRef::from_bytes(ArtifactKind::Node, &corrupt)?;
    decoded.inputs[0] = Arc::from(corrupt);
    assert!(worker.prepare_packet(&decoded).is_err());
    Ok(())
}

#[test]
#[cfg(feature = "stream")]
#[ignore = "new full-strength packet-driven paired-wrapper proof; requires explicit bounded 44 GiB service"]
fn cpu_packet_proves_under_gate_and_owner_independently_accepts() -> Result<(), Error> {
    if std::env::var("LATTICA_V2_RUN_CPU_WORKER_PROOF").as_deref() != Ok("1") {
        return Err("explicit bounded proving opt-in required".into());
    }
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let r = Resources {
        ram_bytes: 44 << 30,
        vram_bytes: 0,
        scratch_bytes: 120 << 30,
        threads: 8,
    };
    let (mut d, assignment) = real_pair(&temp, &f, r);
    let request = encode_request(&assignment)?;
    let (mut store, gate) = bind(&temp, &mut d, assignment.lease(), &request);
    let mut worker = CpuWorker::new(f.registry.clone(), f.pin)?;
    let started = Instant::now();
    let result = {
        let _spill = crate::spill_alloc::SpillScope::arm();
        worker.execute_packet(&gate, &request, [0x5a; 32])?
    };
    assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
    assert!(crate::spill_alloc::spill_peak_bytes() <= r.scratch_bytes);
    let decoded = decode_result(&assignment, &request, &result)?;
    let timings = decoded.timings();
    assert_eq!(decoded.stats(), CacheStats { setups: 1, hits: 0 });
    let revoked = store.revoke(assignment.lease())?;
    assert!(store.try_idle(&revoked)?.is_none());
    drop(gate); // synchronous proving/cleanup done; no OS-stop claim is made here
    let _idle = store
        .try_idle(&revoked)?
        .ok_or("packet worker lock still held")?;
    let now = u64::try_from(started.elapsed().as_millis())?;
    d.worker_stopped(assignment.lease(), now)?;
    let expected = d.begin_verification(assignment.lease(), now)?;
    let ticket = VerifiedNode::verify(&expected, &f.registry, decoded.bytes())?;
    assert_eq!(
        d.finish_verification(
            assignment.lease(),
            Some((ticket, decoded.bytes().to_vec())),
            now
        )?,
        Completion::Accepted
    );
    assert_eq!(d.resource_use()?, Resources::default());
    // Save both the local response and raw node for separate CPU-only replay.
    let output = PathBuf::from(std::env::var("LATTICA_V2_WORKER_TEST_OUTPUT")?);
    for (path, bytes) in [
        (output.clone(), decoded.bytes()),
        (output.with_extension("packet"), result.as_slice()),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::File::open(path.parent().ok_or("packet output parent")?)?.sync_all()?;
    }
    println!("cpu_packet_pair_verified proof_bytes={} request_bytes={} result_bytes={} input_verification_ms={} proving_ms={} serialization_ms={} wall_ms={} spill_peak_bytes={} full_block=false production_ready=false",
        decoded.bytes().len(), request.len(), result.len(), timings.input_verification_ms, timings.proving_ms,
        timings.serialization_ms, started.elapsed().as_millis(), crate::spill_alloc::spill_peak_bytes());
    Ok(())
}
