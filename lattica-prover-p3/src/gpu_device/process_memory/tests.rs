use super::*;

const UUID: &str = "GPU-01234567-89ab-cdef-0123-456789abcdef";
const ROW: &str = "123, GPU-01234567-89ab-cdef-0123-456789abcdef, 4096\n";

#[test]
fn matching_process_is_unique_and_bound_to_the_expected_device() {
    let observation = parse(ROW.as_bytes(), UUID, 123).unwrap();
    assert_eq!(observation.process_bytes, 4 << 30);
    assert_eq!(observation.rows_examined, 1);
    assert_eq!(parse(ROW.as_bytes(), UUID, 124), Err(Error::MissingProcess));
    let duplicate = ROW.repeat(2);
    assert_eq!(
        parse(duplicate.as_bytes(), UUID, 123),
        Err(Error::DuplicateProcess)
    );
    let wrong = ROW.replace("01234567", "11234567");
    assert_eq!(parse(wrong.as_bytes(), UUID, 123), Err(Error::WrongDevice));
    let other = format!("999, GPU-11234567-89ab-cdef-0123-456789abcdef, N/A\n{ROW}");
    assert_eq!(parse(other.as_bytes(), UUID, 123).unwrap().rows_examined, 2);
    assert_eq!(
        parse(ROW.as_bytes(), &UUID.to_ascii_uppercase(), 123).unwrap(),
        observation
    );
}

#[test]
fn malformed_rows_and_capacity_overflow_cannot_be_observations() {
    for text in ["", "\n", "123", "123, x", "123, x, 2, 3", "abc, x, 1"] {
        assert!(parse(text.as_bytes(), UUID, 123).is_err());
    }
    for value in ["", "N/A", "+1", "-1", "1.5", "18446744073709551615"] {
        let row = format!("123, {UUID}, {value}\n");
        assert!(parse(row.as_bytes(), UUID, 123).is_err());
    }
    assert_eq!(parse(&[0xff], UUID, 123), Err(Error::Utf8));
    assert_eq!(
        parse(&[b' '; OUTPUT_BYTES + 1], UUID, 123),
        Err(Error::OutputLimit)
    );
    let many = format!("{}{}", "999, ignored, ignored\n".repeat(MAX_ROWS), ROW);
    assert_eq!(parse(many.as_bytes(), UUID, 123), Err(Error::RowLimit));
    assert_eq!(parse(ROW.as_bytes(), UUID, 0), Err(Error::InvalidRequest));
    for uuid in ["", "GPU-", "GPU-01234567_89ab-cdef-0123-456789abcdef"] {
        assert_eq!(parse(ROW.as_bytes(), uuid, 123), Err(Error::InvalidRequest));
    }
}

#[test]
fn fixed_reader_refuses_an_extra_byte_and_preserves_read_failure() {
    let mut output = [0; OUTPUT_BYTES + 1];
    let input = [7; OUTPUT_BYTES];
    assert_eq!(read_bounded(&mut &input[..], &mut output), Ok(OUTPUT_BYTES));
    assert_eq!(&output[..OUTPUT_BYTES], input);
    let input = [7; OUTPUT_BYTES + 1];
    assert_eq!(
        read_bounded(&mut &input[..], &mut output),
        Err(Error::OutputLimit)
    );
    struct Interrupted(bool);
    impl Read for Interrupted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            if core::mem::replace(&mut self.0, false) {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(0)
            }
        }
    }
    assert_eq!(read_bounded(&mut Interrupted(true), &mut output), Ok(0));
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    assert_eq!(read_bounded(&mut Broken, &mut output), Err(Error::Read));
}

#[test]
fn checkpoint_preserves_both_managed_and_context_reserve_limits() {
    let observed = |process_bytes| Observation {
        pid: 123,
        process_bytes,
        rows_examined: 1,
    };
    let checkpoint = observed(12 << 30)
        .checkpoint(8 << 30, 8 << 30, 4 << 30)
        .unwrap();
    assert_eq!(checkpoint.context_difference_bytes, 4 << 30);
    assert_eq!(
        observed((12 << 30) + 1).checkpoint(8 << 30, 8 << 30, 4 << 30),
        Err(Error::Envelope)
    );
    assert_eq!(
        observed(5 << 30).checkpoint(0, 8 << 30, 4 << 30),
        Err(Error::Envelope)
    );
    assert_eq!(
        observed(12 << 30).checkpoint(9 << 30, 8 << 30, 4 << 30),
        Err(Error::Envelope)
    );
    assert_eq!(
        observed(1).checkpoint(0, usize::MAX, 1),
        Err(Error::Overflow)
    );
    assert_eq!(
        observed(1)
            .checkpoint(2, 2, 1)
            .unwrap()
            .context_difference_bytes,
        0
    );
}

#[test]
fn invalid_sampling_request_cannot_spawn_a_helper() {
    assert_eq!(sample("not a UUID", 123), Err(Error::InvalidRequest));
    assert_eq!(sample(UUID, 0), Err(Error::InvalidRequest));
}

#[test]
fn running_scope_reaps_live_and_already_finished_helpers() {
    for (executable, arguments, finish_first) in [
        ("/usr/bin/sleep", &["60"][..], false),
        ("/usr/bin/true", &[][..], true),
    ] {
        let child = Command::new(executable)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut running = Running {
            child,
            reaped: false,
        };
        if finish_first {
            assert!(running.wait().success());
        }
        drop(running);
        let mut status = 0;
        // SAFETY: the child is already reaped by Running. A nonblocking query
        // verifies that no waitable ownership escaped that scope.
        let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        assert_eq!(result, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

#[test]
#[ignore = "serialized real-device observation only; pinned UUID and process guard required"]
fn selected_process_observation_is_bounded_and_matches_its_device() {
    use crate::gpu_device::bounded::{Request, Scratch, Snapshot};
    let index = std::env::var("LATTICA_V2_GPU_DEVICE").unwrap();
    let uuid = std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap();
    let request = Request::parse(&index, &uuid).unwrap();
    let selected = Snapshot::capture(request, &mut Scratch::new()).unwrap();
    let context = ocl::Context::builder()
        .platform(selected.platform())
        .devices(selected.device())
        .build()
        .unwrap();
    let queue = ocl::Queue::new(&context, selected.device(), None).unwrap();
    let payload_bytes = 1 << 20;
    let buffer = ocl::Buffer::<u64>::builder()
        .queue(queue.clone())
        .len(payload_bytes / core::mem::size_of::<u64>())
        .fill_val(0)
        .build()
        .unwrap();
    queue.finish().unwrap();
    let observed = sample(&uuid, std::process::id()).unwrap();
    assert!(observed.process_bytes >= payload_bytes);
    let checkpoint = observed
        .checkpoint(payload_bytes, 8 << 30, 4 << 30)
        .unwrap();
    selected.recheck(request, &mut Scratch::new()).unwrap();
    eprintln!(
        "bounded_process_observation pid={} process_bytes={} rows={} context_difference_bytes={} complete_admission=false",
        observed.pid, observed.process_bytes, observed.rows_examined,
        checkpoint.context_difference_bytes
    );
    drop(buffer);
    drop(queue);
    drop(context);
}
