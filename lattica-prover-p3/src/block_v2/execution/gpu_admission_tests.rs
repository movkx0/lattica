use super::*;
use serde_json::json;

#[test]
fn caller_stack_is_reserved_before_assignment_parsing() {
    let caller = super::super::worker_budget::CALLER_STACK_HOST_BYTES;
    let floor = ASSIGNMENT_HOST_BYTES + caller + crate::host_memory::RETAINED_SYSTEM_HOST_BYTES;
    for total in [0, caller - 1, caller, floor - 1] {
        assert!(admit_startup_input(total).is_err());
    }
    admit_startup_input(floor).unwrap();
    eprintln!(
        "caller_stack_startup_input floor_bytes={floor} caller_bytes={caller} early_rejections=4"
    );
}

#[test]
fn rayon_stacks_must_fit_beside_startup_input_before_threads_start() {
    let stacks = super::super::worker_budget::rayon_stack_host_bytes(4).unwrap();
    let floor = stacks
        + ASSIGNMENT_HOST_BYTES
        + super::super::worker_budget::CALLER_STACK_HOST_BYTES
        + crate::host_memory::RETAINED_SYSTEM_HOST_BYTES;
    for (available, accepted) in [(floor - 1, false), (floor, true)] {
        let (mut assignment, mut environment, mut observed) = fixture();
        assignment["host"]["worker_bytes"] = json!(available);
        environment.host_output = available;
        observed.memory = available;
        // Isolate the startup stack boundary from the independent spill/data
        // partition, which cannot fit the fixture's usual 2 GiB spill cap here.
        assignment["host"]["spill_bytes"] = json!(1 << 20);
        environment.spill = 1 << 20;
        assert_eq!(
            Admission::validate(assignment, &environment, observed).is_ok(),
            accepted
        );
    }
}

#[cfg(feature = "stream")]
#[test]
fn private_data_partition_rejects_overlapping_spill_before_threads_start() {
    let (_, _, observed) = fixture();
    let worker = observed.memory;
    let stacks = super::super::worker_budget::rayon_stack_host_bytes(4).unwrap()
        + super::super::worker_budget::CALLER_STACK_HOST_BYTES;
    let shared_boundary = worker - stacks - crate::host_memory::GPU_MAPPED_HOST_BYTES;
    for (spill, accepted) in [
        (0, false),
        (shared_boundary - 1, true),
        (shared_boundary, false),
        (worker, false),
        (u64::MAX, false),
    ] {
        let (mut assignment, mut environment, observed) = fixture();
        assignment["host"]["spill_bytes"] = json!(spill);
        environment.spill = spill;
        assert_eq!(
            Admission::validate(assignment, &environment, observed).is_ok(),
            accepted
        );
    }
}

#[test]
fn explicit_rayon_stacks_override_environment_in_a_fresh_process() {
    const CHILD: &str = "LATTICA_RAYON_STACK_TEST_CHILD";
    if std::env::var(CHILD).as_deref() == Ok("1") {
        let (assignment, environment, observed) = fixture();
        let admission = Admission::validate(assignment, &environment, observed).unwrap();
        // libtest's caller inherited RUST_MIN_STACK=64 MiB. Reject it before
        // creating the pool; a bounded caller can then initialize successfully.
        assert!(admission.initialize_rayon().is_err());
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                admission.initialize_rayon().unwrap();
                #[cfg(feature = "stream")]
                {
                    let requests = crate::spill_alloc::system_budget::snapshot();
                    assert_eq!(requests.limit_bytes, Some(2666594304));
                    assert!(requests.accounting_valid);
                    assert_eq!(requests.rejected_requests, 0);
                }
                assert_eq!(rayon::current_num_threads(), 4);
                assert!(admission.initialize_rayon().is_err());
                #[cfg(feature = "gpu")]
                assert!(!crate::block_v2::gpu_hash::is_enabled());
            })
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            concat!(
                module_path!(),
                "::explicit_rayon_stacks_override_environment_in_a_fresh_process"
            )
            .split_once("::")
            .unwrap()
            .1,
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("RUST_MIN_STACK", (64 << 20).to_string())
        .env("LATTICA_PROVING_REPORT", "1")
        .env("LATTICA_SPILL_MAX_BYTES", (2u64 << 30).to_string())
        .env("LATTICA_SPILL_DIR", "/tmp")
        .env("LATTICA_SPILL_BACKING", "file")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "{stdout}"
    );
    assert!(stderr.contains("bounded_rayon_stacks threads=4 stack_bytes=2097152"));
    assert!(stderr.contains("reserved_host_bytes=9175040"));
    #[cfg(feature = "stream")]
    assert!(stderr.contains("bounded_system_requests "));
    eprint!("{stderr}");
    print!("{stdout}");
}

fn fixture() -> (Value, Environment, Observed) {
    let unit = "lattica-v2-multi-admission-fixture.service";
    let assignment = json!({
        "unit": unit,
        "slice": "lattica-v2-multi.slice",
        "gpu": {"version": 1, "uuid": "GPU-fixture", "managed_bytes": 1 << 30,
                "context_bytes": 64 << 20, "max_allocation_bytes": 1 << 28},
        "cpu": {"version": 1, "quota_percent": "400%", "allowed_cpus": [2, 3, 7, 8],
                "rayon_threads": 4},
        "host": {"version": 1, "worker_bytes": 3u64 << 30, "fleet_bytes": 8u64 << 30,
                 "spill_bytes": 2u64 << 30, "scratch_device": 42, "scratch_path": "/tmp"},
        "existing_workload_metadata": {"retained": true}
    });
    let environment = Environment {
        unit: unit.into(),
        direct: false,
        threads: 4,
        gpu_uuid: "GPU-fixture".into(),
        managed: 1 << 30,
        context: 64 << 20,
        host_output: 3 << 30,
        spill: 2 << 30,
    };
    let observed = Observed {
        unit: unit.into(),
        slice: "lattica-v2-multi.slice".into(),
        memory: 3 << 30,
        fleet_memory: 8 << 30,
        swap: 0,
        fleet_swap: 0,
        cpu_max: "400000 100000".into(),
        cpus: "2-3,7-8".into(),
        scratch_device: 42,
    };
    (assignment, environment, observed)
}

#[test]
fn retains_the_original_assignment_and_supports_both_readback_layouts() {
    for layout in [None, Some("banded"), Some("direct")] {
        let (mut assignment, mut environment, observed) = fixture();
        if let Some(layout) = layout {
            assignment["readback_layout"] = json!(layout);
            environment.direct = layout == "direct";
        }
        let admitted = Admission::validate(assignment.clone(), &environment, observed).unwrap();
        assert_eq!(admitted.assignment(), &assignment);
        assert_eq!(admitted.rayon_threads(), 4);
        assert_eq!(admitted.cpu_max(), "400000 100000");
    }
}

#[test]
fn isolated_fleet_slices_retain_exact_assignment_and_limit_binding() {
    let name = "lattica-v2-multi-native-qualification.slice";
    let (mut assignment, environment, mut observed) = fixture();
    assignment["slice"] = json!(name);
    observed.slice = name.into();
    assert!(Admission::validate(assignment, &environment, observed).is_ok());
    let (mut assignment, environment, observed) = fixture();
    assignment["slice"] = json!(name);
    assert!(Admission::validate(assignment, &environment, observed).is_err());
    for name in [
        "other.slice",
        "lattica-v2-multiple.slice",
        "lattica-v2-multi-test.service",
        "lattica-v2-multi-/escape.slice",
    ] {
        assert!(!worker_slice(name));
    }
}

#[test]
fn rejects_every_observed_resource_mismatch() {
    let changes: &[fn(&mut Observed)] = &[
        |o| o.unit.push_str(".other"),
        |o| o.slice.push_str(".other"),
        |o| o.memory += 1,
        |o| o.fleet_memory += 1,
        |o| o.swap = 1,
        |o| o.fleet_swap = 1,
        |o| o.cpu_max = "300000 100000".into(),
        |o| o.cpus = "2-3,7,9".into(),
        |o| o.scratch_device += 1,
    ];
    for change in changes {
        let (assignment, environment, mut observed) = fixture();
        change(&mut observed);
        assert!(Admission::validate(assignment, &environment, observed).is_err());
    }
}

#[test]
fn rejects_every_environment_mismatch_before_thread_start() {
    let changes: &[fn(&mut Environment)] = &[
        |e| e.unit.push_str(".other"),
        |e| e.direct = true,
        |e| e.threads += 1,
        |e| e.gpu_uuid.push_str(".other"),
        |e| e.managed += 1,
        |e| e.context += 1,
        |e| e.host_output += 1,
        |e| e.spill += 1,
    ];
    for change in changes {
        let (assignment, mut environment, observed) = fixture();
        change(&mut environment);
        assert!(Admission::validate(assignment, &environment, observed).is_err());
    }
}

#[test]
fn rejects_invalid_assignment_fields() {
    for (pointer, value) in [
        ("/gpu/version", json!(2)),
        ("/cpu/version", json!(2)),
        ("/host/version", json!(2)),
        ("/gpu/managed_bytes", json!(-1)),
        ("/gpu/max_allocation_bytes", Value::Null),
        ("/gpu/max_allocation_bytes", json!(0)),
        ("/gpu/max_allocation_bytes", json!(-1)),
        ("/gpu/max_allocation_bytes", json!(1.5)),
        ("/gpu/context_bytes", Value::Null),
        ("/host/worker_bytes", json!("3221225472")),
        ("/host/fleet_bytes", Value::Null),
        ("/cpu/rayon_threads", json!(0)),
        ("/cpu/rayon_threads", Value::Null),
        ("/cpu/allowed_cpus", json!([])),
        ("/gpu/uuid", Value::Null),
        ("/host/spill_bytes", Value::Null),
        ("/host/scratch_device", Value::Null),
        ("/unit", json!("unassigned.service")),
        ("/slice", json!("unassigned.slice")),
    ] {
        let (mut assignment, environment, observed) = fixture();
        *assignment.pointer_mut(pointer).unwrap() = value;
        assert!(
            Admission::validate(assignment, &environment, observed).is_err(),
            "{pointer}"
        );
    }
    for layout in [json!("other"), json!(true), Value::Null] {
        let (mut assignment, environment, observed) = fixture();
        assignment["readback_layout"] = layout;
        assert!(Admission::validate(assignment, &environment, observed).is_err());
    }
}

#[test]
fn quota_parsing_rejects_nan_zero_unlimited_and_malformed_values() {
    for actual in [
        "",
        "1",
        "1 2 3",
        "max 100000",
        "0 100000",
        "1 0",
        "0 0",
        "-1 1",
    ] {
        assert!(validate_quota(actual, "400%").is_err(), "{actual}");
    }
    for assigned in ["NaN", "NaN%", "inf%", "-inf", "0%", "-400%", "", "bogus"] {
        assert!(
            validate_quota("400000 100000", assigned).is_err(),
            "{assigned}"
        );
    }
    assert!(validate_quota("400000 100000", "400.0%").is_ok());
    assert!(validate_quota("100000 100000", "99.999%").is_ok());
    assert!(validate_quota("100000 100000", "99.99%").is_err());
}

#[test]
fn cpuset_comparison_is_bounded_by_the_assignment() {
    assert!(validate_cpuset("2-3,7,9-10", &json!([2, 3, 7, 9, 10])).is_ok());
    assert!(validate_cpuset("18446744073709551615", &json!([u64::MAX])).is_ok());
    for actual in [
        "",
        "2-",
        "-2",
        "3-2",
        "2-3-7",
        "2,2",
        "3,2",
        "2-4,4",
        "2,3,",
        "0-18446744073709551615",
    ] {
        assert!(validate_cpuset(actual, &json!([2, 3])).is_err(), "{actual}");
    }
    for assigned in [
        json!([]),
        json!([2]),
        json!([3, 2]),
        json!([2, 2]),
        json!([2, "3"]),
        json!([2, 3, 4]),
        Value::Null,
    ] {
        assert!(validate_cpuset("2-3", &assigned).is_err(), "{assigned}");
    }
}

#[test]
fn reads_only_bounded_object_assignments() {
    let mut bytes = vec![b' '; MAX_ASSIGNMENT_BYTES as usize - 2];
    bytes.extend_from_slice(b"{}");
    assert_eq!(read_assignment(bytes.as_slice()).unwrap(), json!({}));
    bytes.push(b' ');
    assert!(read_assignment(bytes.as_slice()).is_err());
    for bytes in [
        b"".as_slice(),
        b"[]",
        b"null",
        b"{}{}",
        b"{",
        b"{\"nested\":",
    ] {
        assert!(read_assignment(bytes).is_err());
    }
}

#[test]
fn membership_must_identify_one_absolute_v2_cgroup() {
    assert_eq!(
        current_group("0::/user.slice/lattica-v2-multi.slice/example.service\n").unwrap(),
        Path::new("/sys/fs/cgroup/user.slice/lattica-v2-multi.slice/example.service")
    );
    for membership in [
        "",
        "1:cpu:/example",
        "0::relative",
        "0::/../escape",
        "0::/user/../../escape",
        "0::/a\n0::/b",
    ] {
        assert!(current_group(membership).is_err(), "{membership}");
    }
}

/// Run only in a fresh, bounded process: mutates its environment and global
/// Rayon pool. The existing fleet slice is deliberately left unchanged.
#[test]
#[ignore = "native admission rejection check in an isolated systemd process"]
fn native_rejection_leaves_rayon_uninitialized() {
    assert_eq!(
        std::env::var("LATTICA_ADMISSION_NATIVE").as_deref(),
        Ok("1")
    );
    let directory = PathBuf::from(std::env::var("LATTICA_ADMISSION_OUTPUT").unwrap());
    let path = directory.join("assignment.json");
    let (assignment, _, _) = fixture();
    fs::write(&path, serde_json::to_vec_pretty(&assignment).unwrap()).unwrap();
    for (key, value) in [
        ("LATTICA_V2_WORKER_BUDGET", path.to_str().unwrap()),
        (
            "LATTICA_V2_ACCOUNTING_UNIT",
            "lattica-v2-multi-admission-fixture.service",
        ),
        ("LATTICA_V2_GPU_DIRECT_READBACK", "0"),
        ("RAYON_NUM_THREADS", "4"),
        ("LATTICA_GPU_DEVICE_UUID", "GPU-fixture"),
        ("LATTICA_V2_GPU_MANAGED_BYTES", "1073741824"),
        ("LATTICA_V2_GPU_CONTEXT_BYTES", "67108864"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "3221225472"),
        ("LATTICA_SPILL_MAX_BYTES", "2147483648"),
        ("LATTICA_SPILL_DIR", directory.to_str().unwrap()),
    ] {
        std::env::set_var(key, value);
    }
    std::env::set_var("LATTICA_WALLET_WORKER_BUDGET", "private-wallet-assignment");
    assert!(Admission::from_env()
        .err()
        .unwrap()
        .to_string()
        .contains("private wallet assignments"));
    std::env::remove_var("LATTICA_WALLET_WORKER_BUDGET");
    let error = Admission::from_env()
        .err()
        .expect("foreign assignment must reject");
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build_global()
        .unwrap();
    assert_eq!(rayon::current_num_threads(), 4);
    let report = json!({
        "accepted": false,
        "error": error.to_string(),
        "rayon_initialized_after_rejection": true,
        "rayon_threads": rayon::current_num_threads(),
        "current_cgroup": fs::read_to_string("/proc/self/cgroup").unwrap(),
        "gpu_initialized": false,
    });
    fs::write(
        directory.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
