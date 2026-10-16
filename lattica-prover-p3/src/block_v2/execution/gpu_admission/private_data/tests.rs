use super::*;

#[test]
fn private_data_status_requires_bounded_unambiguous_kernel_units() {
    let input = b"Name:\tfixture-\xff\nVmData:\t32 kB\nThreads:\t3\n";
    assert_eq!(
        read_status(&input[..]).unwrap(),
        Status {
            data_bytes: 32768,
            threads: 3
        }
    );
    for input in [
        &b"VmData: 32 kB\n"[..],
        &b"Threads: 1\n"[..],
        &b"VmData: 32 MB\nThreads: 1\n"[..],
        &b"VmData: 32 kB extra\nThreads: 1\n"[..],
        &b"VmData: 18446744073709551615 kB\nThreads: 1\n"[..],
        &b"VmData: -1 kB\nThreads: 1\n"[..],
        &b"VmData: 32 kB\nVmData: 32 kB\nThreads: 1\n"[..],
        &b"VmData: 32 kB\nThreads: 0\n"[..],
        &b"VmData: 32 kB\nThreads: 4294967296\n"[..],
        &b"VmData: 32 kB\nThreads: 1\nThreads: 1\n"[..],
        &b"VmData: 32 kB\nThreads: 1 extra\n"[..],
    ] {
        assert!(read_status(input).is_err());
    }
    assert!(read_status(&vec![b'x'; STATUS_BYTES + 1][..]).is_err());
    assert!(current().unwrap().threads > 0);
    for accepted in [&b"N\n"[..], &b"0\n"[..]] {
        require_kernel_enforcement(accepted).unwrap();
    }
    for refused in [&b"Y\n"[..], &b"1\n"[..], &b""[..], &b"N\nextra"[..]] {
        assert!(require_kernel_enforcement(refused).is_err());
    }
}

#[test]
fn cold_data_charges_potential_private_backing_and_keeps_an_exact_boundary() {
    assert_eq!(COLD_BYTES, 536870912);
    admit_observed(COLD_BYTES).unwrap();
    assert!(admit_observed(COLD_BYTES + 1).is_err());
    assert!(admit_observed(COLD_BYTES + worker_budget::CALLER_STACK_HOST_BYTES).is_err());
    assert!(admit_observed(u64::MAX).is_err());
}

#[test]
fn private_data_hard_limit_is_tightened_and_cannot_be_relaxed_in_a_fresh_process() {
    const CHILD: &str = "LATTICA_PRIVATE_DATA_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "block_v2::execution::gpu_admission::private_data::tests::private_data_hard_limit_is_tightened_and_cannot_be_relaxed_in_a_fresh_process",
                "--test-threads=1", "--nocapture",
            ])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    install(3 << 30, 4, 1 << 30).unwrap();
    let applied = limits().unwrap();
    assert_eq!(applied.rlim_cur, 2062614528);
    assert_eq!(applied.rlim_max, applied.rlim_cur);
    assert!(install(4 << 30, 4, 1 << 30).is_err());
    assert_eq!(limits().unwrap().rlim_max, applied.rlim_max);
    let raised = libc::rlimit {
        rlim_cur: applied.rlim_cur + 4096,
        rlim_max: applied.rlim_max + 4096,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_DATA, &raised) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    eprintln!("private_data_limit_verified soft_bytes=2062614528 hard_bytes=2062614528 cannot_raise=true inherited_lower_rejected=true");
}

#[test]
fn private_limit_keeps_shared_spill_and_staging_outside_its_allowance() {
    const CHILD: &str = "LATTICA_PRIVATE_SHARED_PARTITION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact",
                "block_v2::execution::gpu_admission::private_data::tests::private_limit_keeps_shared_spill_and_staging_outside_its_allowance",
                "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    struct Mapping(*mut libc::c_void, usize);
    impl Mapping {
        fn new(bytes: usize, shared: bool) -> Result<Self, std::io::Error> {
            // SAFETY: anonymous kernel-owned storage, never exposed as Rust
            // references; Drop releases exactly this mapping once.
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS
                        | if shared {
                            libc::MAP_SHARED
                        } else {
                            libc::MAP_PRIVATE
                        },
                    -1,
                    0,
                )
            };
            if address == libc::MAP_FAILED {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self(address, bytes))
            }
        }
    }
    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: the address and extent belong to this live mapping.
            assert_eq!(unsafe { libc::munmap(self.0, self.1) }, 0);
        }
    }
    let worker = 3u64 << 30;
    let spill = 1u64 << 30;
    install(worker, 4, spill).unwrap();
    let limit = limits().unwrap().rlim_cur as u64;
    let before = current().unwrap().data_bytes;
    // Linux implements these anonymous shared mappings with file backing.
    // Reserving their virtual extent does not count as private writable data.
    let spill_mapping = Mapping::new(spill as usize, true).unwrap();
    let staging = Mapping::new(crate::host_memory::GPU_MAPPED_HOST_BYTES as usize, true).unwrap();
    let with_shared = current().unwrap().data_bytes;
    let private = Mapping::new(64 << 20, false).unwrap();
    let with_private = current().unwrap().data_bytes;
    let rejected = Mapping::new(limit as usize + 4096, false);
    let error = rejected.as_ref().err().and_then(|e| e.raw_os_error());
    drop((rejected, private, staging, spill_mapping));
    assert_eq!(with_shared, before);
    assert_eq!(with_private - with_shared, 64 << 20);
    assert_eq!(error, Some(libc::ENOMEM));
    assert_eq!(
        limit
            + spill
            + crate::host_memory::GPU_MAPPED_HOST_BYTES
            + worker_budget::rayon_stack_host_bytes(4).unwrap()
            + worker_budget::CALLER_STACK_HOST_BYTES,
        worker
    );
    eprintln!("private_shared_partition_verified private_limit_bytes={limit} spill_bytes={spill} mapped_staging_bytes={} stacks_bytes={} worker_bytes={worker} oversized_private_errno={} virtual_reservations_only=true complete_rss_admission=false",
        crate::host_memory::GPU_MAPPED_HOST_BYTES,
        worker_budget::rayon_stack_host_bytes(4).unwrap() + worker_budget::CALLER_STACK_HOST_BYTES,
        libc::ENOMEM);
}
