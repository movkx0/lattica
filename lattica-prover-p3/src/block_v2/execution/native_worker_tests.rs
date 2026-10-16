use super::super::worker_budget;
use super::*;

#[test]
fn native_bootstrap_decode_matches_reference_fields() {
    // Preserve the original serde field behavior independently of the new
    // bounded visitors. Registry/policy approval remains a separate step.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        version: u32,
        registry: Registry<12>,
        profile: [u8; 32],
        chain: [u8; 32],
        executable: [u8; 32],
        launches: PathBuf,
        policy_context: Vec<u8>,
    }
    let base = bootstrap();
    let value = serde_json::to_value(&base).unwrap();
    let mut corpus = vec![base.encode().unwrap()];
    for mutation in 0..8 {
        let mut changed = value.clone();
        match mutation {
            0 => changed["registry"]["ignored_by_registry"] = json!({"nested": [1, 2, 3]}),
            1 => changed["launches"] = json!("/tmp/é GPU 🦀\n\t"),
            2 => changed["registry"]["caps"][0] = json!([]),
            3 => changed["policy_context"] = json!([]),
            4 => changed["untrusted_override"] = json!(true),
            5 => changed["registry"]["height"] = json!("8"),
            6 => {
                changed["registry"] =
                    json!([value["registry"]["height"], value["registry"]["caps"]])
            }
            _ => {
                changed = json!([
                    value["version"],
                    value["registry"],
                    value["profile"],
                    value["chain"],
                    value["executable"],
                    value["launches"],
                    value["policy_context"]
                ])
            }
        }
        corpus.push(serde_json::to_vec(&changed).unwrap());
    }
    corpus.extend([
        b"".to_vec(),
        b"{}".to_vec(),
        b"[]{}".to_vec(),
        b"null".to_vec(),
    ]);
    let encoded = String::from_utf8(base.encode().unwrap()).unwrap();
    corpus.push(format!("{{\"version\":1,{}", &encoded[1..]).into_bytes());
    for bytes in &corpus {
        match (
            serde_json::from_slice::<Reference>(bytes),
            Bootstrap::parse_fields(bytes),
        ) {
            (Ok(reference), Ok(bounded)) => assert_eq!(
                serde_json::to_vec(&reference).unwrap(),
                serde_json::to_vec(&bounded).unwrap()
            ),
            (Err(_), Err(_)) => {}
            _ => panic!("native bootstrap field decoding differs"),
        }
    }
    eprintln!(
        "native_bootstrap_decode_equivalence cases={} wire_fields_unchanged=true",
        corpus.len()
    );
}

#[test]
fn native_bootstrap_decode_reserves_exact_bounded_backing() {
    use crate::spill_alloc::allocation_requests::measure;
    let base = bootstrap();
    let encoded = base.encode().unwrap();
    let (decoded, requests) = measure(|| Bootstrap::parse_fields(&encoded).unwrap());
    let cap_len = 1 << profile::CAP_HEIGHT;
    assert!(decoded
        .registry
        .caps
        .iter()
        .all(|cap| cap.len() == cap_len && cap.capacity() == cap_len));
    assert_eq!(
        decoded.policy_context.capacity(),
        super::super::policy_context::MAX_BYTES
    );
    assert_eq!(
        decoded.launches.capacity(),
        decoded.launches.as_os_str().len()
    );
    let expected = 12 * cap_len * std::mem::size_of::<[Val; 4]>()
        + super::super::policy_context::MAX_BYTES
        + decoded.launches.capacity();
    assert!(!requests.overflow);
    assert_eq!((requests.calls, requests.bytes), (14, expected));
    decode::layout().unwrap();
    assert!(
        super::super::gpu_admission::ASSIGNMENT_HOST_BYTES + decode::HOST_BYTES
            <= super::super::worker::typed::storage::INPUT_HOST_BYTES
    );
    eprintln!("native_bootstrap_decode_backing allocations={} requested_bytes={} bootstrap_allowance_bytes={} assignment_allowance_bytes={} input_allowance_bytes={}", requests.calls, requests.bytes, decode::HOST_BYTES, super::super::gpu_admission::ASSIGNMENT_HOST_BYTES, super::super::worker::typed::storage::INPUT_HOST_BYTES);
}

#[test]
fn native_bootstrap_decode_bounds_cap_and_policy_growth() {
    use crate::spill_alloc::allocation_requests::measure;
    let base = bootstrap();
    let cap_limit = 1 << profile::CAP_HEIGHT;
    let policy_limit = super::super::policy_context::MAX_BYTES;
    let mut cases = 0;
    for length in [0, 1, cap_limit - 1, cap_limit, cap_limit + 1, 512, 2000] {
        let mut candidate = base.clone();
        candidate.registry.caps[0] = vec![[Val::ZERO; 4]; length];
        let encoded = serde_json::to_vec(&candidate).unwrap();
        assert!(encoded.len() <= MAX_BOOTSTRAP_BYTES);
        let (result, requests) = measure(|| Bootstrap::parse_fields(&encoded));
        assert_eq!(result.is_ok(), length <= cap_limit);
        assert!(!requests.overflow && requests.bytes < decode::HOST_BYTES as usize);
        assert!(requests.largest <= 4096.max(policy_limit));
        if length > cap_limit {
            // The first cap rejects after one fixed allocation, before later
            // fields can allocate or the oversized vector can grow.
            assert!(requests.bytes < 4096);
        }
        cases += 1;
    }
    for length in [
        0,
        1,
        policy_limit - 1,
        policy_limit,
        policy_limit + 1,
        20000,
    ] {
        let mut candidate = base.clone();
        candidate.policy_context = vec![0; length];
        let encoded = serde_json::to_vec(&candidate).unwrap();
        assert!(encoded.len() <= MAX_BOOTSTRAP_BYTES);
        let (result, requests) = measure(|| Bootstrap::parse_fields(&encoded));
        assert_eq!(result.is_ok(), length <= policy_limit);
        assert!(!requests.overflow && requests.bytes < decode::HOST_BYTES as usize);
        assert!(requests.largest <= 4096.max(policy_limit));
        cases += 1;
    }
    eprintln!("native_bootstrap_decode_vector_bounds cases={cases} cap_limit={cap_limit} policy_limit={policy_limit} growth_rejected_before_allocation=true");
}

#[test]
fn native_bootstrap_decode_escape_scratch_and_errors_fit_allowance() {
    use crate::spill_alloc::allocation_requests::measure;
    let base = bootstrap();
    let mut cases = 0;
    for length in [1, 4096, 40000] {
        let mut candidate = base.clone();
        candidate.launches = PathBuf::from(format!("/{}", "x".repeat(length)));
        let encoded = serde_json::to_vec(&candidate).unwrap();
        assert!(encoded.len() <= MAX_BOOTSTRAP_BYTES);
        let (result, requests) = measure(|| Bootstrap::parse_fields(&encoded).unwrap());
        assert_eq!(result.launches, candidate.launches);
        assert!(!requests.overflow && requests.bytes < decode::HOST_BYTES as usize);
        cases += 1;
    }
    for length in [1, 4096, 8000] {
        let mut candidate = base.clone();
        candidate.launches = PathBuf::from(format!("/{}", "\0".repeat(length)));
        let encoded = serde_json::to_vec(&candidate).unwrap();
        assert!(encoded.len() <= MAX_BOOTSTRAP_BYTES);
        let (result, requests) = measure(|| Bootstrap::parse_fields(&encoded).unwrap());
        assert_eq!(result.launches, candidate.launches);
        assert!(!requests.overflow && requests.bytes < decode::HOST_BYTES as usize);
        eprintln!("native_bootstrap_decode_parser escaped_values={length} encoded_bytes={} requested_bytes={} allowance_bytes={}", encoded.len(), requests.bytes, decode::HOST_BYTES);
        cases += 1;
    }
    for escaped in [false, true] {
        let name = if escaped {
            "\\u0000".repeat(10000)
        } else {
            "x".repeat(60000)
        };
        let encoded = format!("{{\"{name}\":0}}").into_bytes();
        assert!(encoded.len() <= MAX_BOOTSTRAP_BYTES);
        let (result, requests) = measure(|| Bootstrap::parse_fields(&encoded));
        assert!(result.is_err());
        assert!(!requests.overflow && requests.bytes < decode::HOST_BYTES as usize);
        cases += 1;
    }
    let oversized = vec![b' '; MAX_BOOTSTRAP_BYTES + 1];
    let (result, requests) = measure(|| Bootstrap::parse_fields(&oversized));
    assert!(result.is_err());
    assert!(!requests.overflow && requests.bytes < 4096 && requests.largest < 4096);
    eprintln!("native_bootstrap_decode_parser_bounds cases={cases} oversized_input_rejected_before_parse=true");
}

#[test]
fn native_bootstrap_decode_floor_precedes_parsing() {
    use crate::spill_alloc::allocation_requests::measure;
    let base = bootstrap();
    let encoded = base.encode().unwrap();
    let malformed = vec![b'['; MAX_BOOTSTRAP_BYTES];
    let floor = super::super::worker::typed::storage::STARTUP_HOST_BYTES
        + 4 * crate::block_v2::execution::worker_budget::RAYON_THREAD_HOST_BYTES;
    let mut early_rejections = 0;
    for bytes in [&encoded, &malformed] {
        for available in [0, 1, floor - 1] {
            let mut assigned = assignment();
            assigned["host"]["worker_bytes"] = json!(available);
            let (result, requests) = measure(|| Bootstrap::parse_for_worker(bytes, &assigned));
            let error = result.err().expect("short budget must reject");
            assert!(error.downcast_ref::<serde_json::Error>().is_none());
            assert!(!requests.overflow && requests.bytes < 4096 && requests.largest < 4096);
            early_rejections += 1;
        }
    }
    let mut assigned = assignment();
    assigned["host"]["worker_bytes"] = json!(floor);
    let decoded = Bootstrap::parse_for_worker(&encoded, &assigned).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
    assert!(Bootstrap::parse_for_worker(&malformed, &assigned)
        .err()
        .unwrap()
        .downcast_ref::<serde_json::Error>()
        .is_some());
    eprintln!("native_bootstrap_decode_floor early_rejections={early_rejections} startup_host_bytes={floor} checked_before_parse=true gpu_initializations=0");
}

#[test]
fn native_owned_bootstrap_reuses_one_approval_and_moves_launch_path() {
    use crate::spill_alloc::allocation_requests::measure_all;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    pool.install(|| {
        for height in [8, 1024, 1 << 21] {
            let mut base = bootstrap();
            base.registry.height = height;
            base.profile = crate::block_v2::typed_recursive::CheckedRegistryRef::new(&base.registry)
                .unwrap()
                .profile();
            let assigned = assignment();
            let encoded = base.encode().unwrap();
            let caps_bytes: usize = base.registry.caps.iter().map(|cap| cap.len() * 32).sum();
            let (_, approval) = measure_all(|| {
                TypedRegistryContext::new(&base.registry, base.profile).unwrap()
            });
            let ((reference, policy), old) = measure_all(|| {
                Bootstrap::decode(&encoded)
                    .unwrap()
                    .config_and_policy(&assigned)
                    .unwrap()
            });
            let ((worker, original_path), current) = measure_all(|| {
                let fields = Bootstrap::parse_fields(&encoded).unwrap();
                let original_path = fields.launches.as_os_str().as_encoded_bytes().as_ptr();
                (fields.into_worker(&assigned).unwrap(), original_path)
            });
            assert_eq!(worker.config.bytes().unwrap(), reference.bytes().unwrap());
            assert_eq!(worker.policy.encode(), policy.encode());
            assert_eq!(worker.launches, base.launches);
            assert_eq!(worker.launches.as_os_str().as_encoded_bytes().as_ptr(), original_path);
            assert!(!old.overflow && !current.overflow && !approval.overflow);
            assert_eq!(old.bytes - current.bytes, approval.bytes + caps_bytes);
            assert_eq!(old.calls - current.calls, approval.calls + 12);
            eprintln!("native_bootstrap_handoff height={height} reference_bytes={} owned_bytes={} approval_bytes={} cap_copy_bytes={caps_bytes} reference_allocations={} owned_allocations={} approval_allocations={} path_backing_moved=true",
                old.bytes, current.bytes, approval.bytes, old.calls, current.calls, approval.calls);
        }
    });
}

#[test]
fn native_owned_bootstrap_keeps_registry_policy_and_budget_rejections() {
    let base = bootstrap();
    let assigned = assignment();
    for change in 0..9 {
        let mut bad = base.clone();
        match change {
            0 => bad.version += 1,
            1 => bad.executable = [0; 32],
            2 => bad.launches = PathBuf::from("relative/launches"),
            3 => bad.profile[0] ^= 1,
            4 => bad.registry.caps[0].clear(),
            5 => bad.registry.height = 9,
            6 => bad.policy_context.clear(),
            7 => bad.policy_context[0] ^= 1,
            _ => bad.policy_context.extend(b"trailing"),
        }
        assert!(bad.config(&assigned).is_err());
        let parsed = Bootstrap::parse_fields(&serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(parsed.into_worker(&assigned).is_err(), "case {change}");
    }
    for field in ["worker_bytes", "coordinator_bytes", "coordinator_job_bytes"] {
        let mut short = assigned.clone();
        short["host"][field] = json!(0);
        assert!(base.config(&short).is_err());
        assert!(base.clone().into_worker(&short).is_err());
    }
    #[cfg(feature = "gpu")]
    assert!(!crate::block_v2::gpu_hash::is_enabled());
    eprintln!("native_bootstrap_handoff_rejections bootstrap=9 assignment=3 gpu_initializations=0");
}

#[test]
fn bootstrap_identity_matches_reference_with_one_exact_output_allocation() {
    use crate::spill_alloc::allocation_requests::measure;
    let mut base = bootstrap();
    let assignments = [
        json!(null),
        json!({}),
        assignment(),
        json!({"z": [null, true, false, -17, 1.25, u64::MAX],
               "a": {"z": "quote\" slash\\ newline\n tab\t", "a": "é GPU 🦀"}}),
        json!({"large": "ab\"\\\n🦀".repeat(8192)}),
    ];
    for (index, assigned) in assignments.iter().enumerate() {
        base.chain[index] ^= 1;
        base.executable[index] ^= 3;
        base.registry.caps[index][0][0] = Val::from_u64(index as u64 + 1);
        base.launches = PathBuf::from("/tmp/native \"identity\"/é GPU");
        let (reference, old) = measure(|| {
            serde_json::to_vec(&json!({
                "native_bootstrap": &base,
                "assignment": assigned,
            }))
            .unwrap()
        });
        let (encoded, current) = measure(|| base.identity_bytes(assigned).unwrap());
        assert_eq!(encoded, reference);
        assert_eq!(encoded.len(), encoded.capacity());
        assert!(!current.overflow && !old.overflow);
        assert_eq!(current.calls, 1);
        assert_eq!(current.bytes, encoded.len());
        assert_eq!(current.largest, encoded.len());
        assert!(old.bytes > current.bytes && old.calls > current.calls);
        assert_eq!(
            base.identity(assigned).unwrap(),
            process::configuration_digest(&reference).unwrap()
        );
        eprintln!(
            "native_bootstrap_identity variant={index} bytes={} old_requested_bytes={} old_allocations={} current_allocations={}",
            encoded.len(), old.bytes, old.calls, current.calls
        );
    }
}

#[test]
fn bootstrap_identity_checks_size_before_output_allocation() {
    use crate::spill_alloc::allocation_requests::measure;
    let base = bootstrap();
    let limit = process::CONFIGURATION_IDENTITY_MAX_BYTES;
    let overhead = base.identity_bytes(&json!({"padding": ""})).unwrap().len();
    for length in [overhead, limit - 1, limit] {
        let assigned = json!({"padding": "x".repeat(length - overhead)});
        let (bytes, requested) = measure(|| base.identity_bytes(&assigned).unwrap());
        assert_eq!((bytes.len(), bytes.capacity()), (length, length));
        assert!(!requested.overflow && requested.calls == 1 && requested.bytes == length);
        assert!(process::configuration_digest(&bytes).is_ok());
    }
    for length in [limit + 1, limit + 4096, 2 * limit] {
        let assigned = json!({"padding": "x".repeat(length - overhead)});
        let (result, requested) = measure(|| base.identity_bytes(&assigned));
        assert!(result.is_err());
        // Only bounded error formatting is allowed; no output or JSON clone.
        assert!(!requested.overflow && requested.bytes < 4096 && requested.largest < 4096);
    }
    assert!(process::configuration_digest(&[]).is_err());
    assert!(process::configuration_digest(&vec![0; limit + 1]).is_err());
    eprintln!("native_bootstrap_identity_bound limit_bytes={limit} exact_acceptances=3 early_rejections=3 payload_allocations_per_success=1");
}
use crate::config::Val;
use p3_field::PrimeCharacteristicRing;
use serde_json::json;

fn bootstrap() -> Bootstrap {
    let registry = Registry {
        height: 8,
        caps: std::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    Bootstrap::new(
        registry.clone(),
        registry.id().unwrap(),
        [3; 32],
        [4; 32],
        PathBuf::from("/tmp/lattica-native-launches"),
        &PolicyContext::new([5; 32], vec![]).unwrap(),
    )
    .unwrap()
}

const WORKER_BYTES: u64 = super::super::worker::typed::storage::STARTUP_HOST_BYTES
    + 4 * crate::block_v2::execution::worker_budget::RAYON_THREAD_HOST_BYTES
    + 3000;
const JOB_BYTES: u64 = super::super::worker::typed::coordinator::HOST_BYTES + 500;
const COORDINATOR_BYTES: u64 = JOB_BYTES + 500;

fn assignment() -> serde_json::Value {
    json!({"host": {"worker_bytes": WORKER_BYTES, "coordinator_bytes": COORDINATOR_BYTES,
                   "coordinator_job_bytes": JOB_BYTES, "spill_bytes": 9000},
           "gpu": {"managed_bytes": 2000}, "cpu": {"rayon_threads": 4}})
}

#[cfg(feature = "gpu")]
#[test]
fn prepared_cli_config_cannot_substitute_resources_cache_or_executable() {
    let mut base = bootstrap();
    base.executable = transport::running_image_fingerprint().unwrap();
    let assigned = assignment();
    let config = base.config(&assigned).unwrap();
    config.check_admitted_assignment(&assigned).unwrap();
    for (group, field) in [
        ("host", "worker_bytes"),
        ("host", "spill_bytes"),
        ("host", "coordinator_job_bytes"),
        ("gpu", "managed_bytes"),
        ("cpu", "rayon_threads"),
    ] {
        let mut changed = assigned.clone();
        changed[group][field] = json!(changed[group][field].as_u64().unwrap() + 1);
        assert!(
            config.check_admitted_assignment(&changed).is_err(),
            "{group}.{field}"
        );
    }
    let mut changed = assigned.clone();
    changed["preprocessing_cache"] = json!({"entries":2,"reserve_bytes":1});
    assert!(config.check_admitted_assignment(&changed).is_err());
    base.executable[0] ^= 1;
    assert!(base
        .config(&assigned)
        .unwrap()
        .check_admitted_assignment(&assigned)
        .is_err());
    assert!(!crate::block_v2::gpu_hash::is_enabled());
}

#[test]
fn native_assignment_checks_coordinator_floor_and_physical_cap() {
    let mut assigned = assignment();
    let floor = super::super::worker::typed::coordinator::HOST_BYTES;
    assigned["host"]["coordinator_bytes"] = json!(floor);
    assigned["host"]["coordinator_job_bytes"] = json!(floor);
    assert!(bootstrap().config(&assigned).is_ok());
    assigned["host"]["coordinator_job_bytes"] = json!(floor - 1);
    assert!(worker_budget::resources(&assigned).is_err());
    assigned["host"]
        .as_object_mut()
        .unwrap()
        .remove("coordinator_job_bytes");
    assert_eq!(
        worker_budget::resources(&assigned).unwrap().1.ram_bytes,
        floor
    );
    assigned["host"]["coordinator_bytes"] = json!(floor - 1);
    assert!(worker_budget::resources(&assigned).is_err());
    assigned["host"]["coordinator_bytes"] = json!(floor);
    assigned["host"]["coordinator_job_bytes"] = json!(floor + 1);
    assert!(worker_budget::resources(&assigned).is_err());
}

#[test]
fn bootstrap_roundtrip_and_complete_identity() {
    let base = bootstrap();
    let bytes = base.encode().unwrap();
    assert_eq!(Bootstrap::decode(&bytes).unwrap().encode().unwrap(), bytes);
    let assigned = assignment();
    let identity = base.identity(&assigned).unwrap();
    assert!(base.config(&assigned).is_ok());
    let mut extra = assigned.clone();
    extra["independently_enforced_future_resource"] = json!("bound too");
    assert_ne!(identity, base.identity(&extra).unwrap());
    for change in 0..5 {
        let mut changed = base.clone();
        match change {
            0 => changed.chain[0] ^= 1,
            1 => changed.executable[0] ^= 1,
            2 => changed.launches = PathBuf::from("/tmp/other-launches"),
            3 => changed.policy_context = PolicyContext::new([6; 32], vec![]).unwrap().encode(),
            _ => {
                changed.registry.caps[0][0][0] = Val::ONE;
                changed.profile = changed.registry.id().unwrap();
            }
        }
        assert!(changed.config(&assigned).is_ok());
        assert_ne!(identity, changed.identity(&assigned).unwrap());
    }
}

#[test]
fn bootstrap_rejects_bad_shape_pins_paths_and_encoding() {
    assert!(Bootstrap::decode(&[]).is_err());
    assert!(Bootstrap::decode(&vec![b' '; MAX_BOOTSTRAP_BYTES + 1]).is_err());
    let base = bootstrap();
    let mut unknown = serde_json::to_value(&base).unwrap();
    unknown["untrusted_override"] = json!(true);
    assert!(Bootstrap::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut trailing = base.encode().unwrap();
    trailing.extend(b"{}");
    assert!(Bootstrap::decode(&trailing).is_err());
    for change in 0..9 {
        let mut bad = base.clone();
        match change {
            0 => bad.version += 1,
            1 => bad.executable = [0; 32],
            2 => bad.launches = PathBuf::from("relative/launches"),
            3 => bad.profile[0] ^= 1,
            4 => bad.registry.caps[0].clear(),
            5 => bad.registry.height = 9,
            6 => bad.policy_context.clear(),
            7 => bad.policy_context[0] ^= 1,
            _ => bad.policy_context.extend(b"trailing"),
        }
        assert!(bad.encode().is_err(), "case {change}");
        assert!(
            Bootstrap::decode(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "case {change}"
        );
    }
}

#[test]
fn assignment_resources_and_cache_keep_existing_semantics() {
    let mut assigned = assignment();
    let (peak, jobs) = worker_budget::resources(&assigned).unwrap();
    assert_eq!(
        (
            peak.ram_bytes,
            peak.vram_bytes,
            peak.scratch_bytes,
            peak.threads
        ),
        (WORKER_BYTES, 2000, 9000, 4)
    );
    assert_eq!(
        (
            jobs.ram_bytes,
            jobs.vram_bytes,
            jobs.scratch_bytes,
            jobs.threads
        ),
        (JOB_BYTES, 0, 0, 4)
    );
    assigned["host"]
        .as_object_mut()
        .unwrap()
        .remove("coordinator_job_bytes");
    assert_eq!(
        worker_budget::resources(&assigned).unwrap().1.ram_bytes,
        COORDINATOR_BYTES
    );
    assert_eq!(
        worker_budget::preprocessing_cache(&assigned).unwrap(),
        (1, 0)
    );
    assigned["preprocessing_cache"] = json!({"entries": 2, "reserve_bytes": 300});
    assert_eq!(
        worker_budget::preprocessing_cache(&assigned).unwrap(),
        (2, 300)
    );
    assert!(bootstrap().config(&assigned).is_ok());
    let cache_limit = crate::block_v2::typed_recursive::storage::active_memory_bytes(
        WORKER_BYTES
            - super::super::worker::typed::storage::HOST_BYTES
            - super::super::worker::typed::storage::INPUT_HOST_BYTES
            - crate::host_memory::RETAINED_SYSTEM_HOST_BYTES
            - crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES
            - 4 * super::super::worker_budget::RAYON_THREAD_HOST_BYTES,
        0,
    )
    .unwrap();
    assigned["preprocessing_cache"] = json!({"entries": 2, "reserve_bytes": cache_limit - 1});
    assert!(bootstrap().config(&assigned).is_ok());
    for cache in [
        json!({"entries": 0, "reserve_bytes": 0}),
        json!({"entries": 13, "reserve_bytes": 300}),
        json!({"entries": 2, "reserve_bytes": 0}),
        json!({"entries": 1, "reserve_bytes": 300}),
        json!({"entries": 2, "reserve_bytes": cache_limit}),
        json!({"entries": 2, "reserve_bytes": 300, "unknown": true}),
    ] {
        assigned["preprocessing_cache"] = cache;
        assert!(bootstrap().config(&assigned).is_err());
    }
    for (group, key, value) in [
        (
            "host",
            "coordinator_job_bytes",
            json!(COORDINATOR_BYTES + 1),
        ),
        ("host", "coordinator_job_bytes", json!(0)),
        ("host", "coordinator_job_bytes", json!(-1)),
        ("host", "worker_bytes", json!(u64::MAX)),
        ("host", "spill_bytes", json!(0)),
        ("gpu", "managed_bytes", json!(0)),
        ("cpu", "rayon_threads", json!(0)),
        ("cpu", "rayon_threads", json!(u64::MAX)),
    ] {
        let mut bad = assignment();
        bad[group][key] = value;
        assert!(bootstrap().config(&bad).is_err(), "{group}.{key}");
    }
}

#[cfg(feature = "gpu")]
#[test]
fn socket_duplication_preserves_ownership_and_rejects_other_descriptors() {
    use std::{
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::net::{UnixDatagram, UnixListener, UnixStream},
        },
    };
    let (mut original, mut peer) = UnixStream::pair().unwrap();
    let mut duplicate = duplicate_socket(original.as_raw_fd()).unwrap();
    assert_ne!(original.as_raw_fd(), duplicate.as_raw_fd());
    assert_ne!(
        unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    duplicate.write_all(b"a").unwrap();
    let mut byte = [0];
    peer.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"a");
    drop(duplicate);
    original.write_all(b"b").unwrap();
    peer.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"b");
    assert!(duplicate_socket(-1).is_err());
    assert!(duplicate_socket(std::fs::File::open("/dev/null").unwrap().as_raw_fd()).is_err());
    let (datagram, _) = UnixDatagram::pair().unwrap();
    assert!(duplicate_socket(datagram.as_raw_fd()).is_err());
    use std::os::linux::net::SocketAddrExt;
    let address = std::os::unix::net::SocketAddr::from_abstract_name(format!(
        "lattica-native-listener-{}",
        std::process::id()
    ))
    .unwrap();
    let listener = UnixListener::bind_addr(&address).unwrap();
    assert!(duplicate_socket(listener.as_raw_fd()).is_err());
    let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(inet_fd >= 0);
    let inet = unsafe { OwnedFd::from_raw_fd(inet_fd) };
    assert!(duplicate_socket(inet.as_raw_fd()).is_err());
}
