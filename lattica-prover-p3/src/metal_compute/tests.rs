use super::*;

#[test]
fn transfer_reservation_is_bounded_and_consistent_with_the_engine() {
    for limit in [512 << 10, 16 << 20, 256 << 20, 8usize << 30] {
        let bytes = transfer_budget(limit);
        assert!(bytes > 0 && bytes <= limit / 64 && bytes <= 8 << 20);
    }
}

#[test]
fn allocation_limit_and_drop_return_the_exact_native_reservation() {
    let budget = Arc::new(Budget {
        limit: 100,
        counters: Mutex::new(Accounting::default()),
    });
    let a = NativeAllocation::new(75, &budget).unwrap();
    assert!(NativeAllocation::new(26, &budget).is_err());
    assert_eq!(budget.counters.lock().unwrap().live, 75);
    let b = NativeAllocation::new(25, &budget).unwrap();
    assert_eq!(budget.counters.lock().unwrap().peak, 100);
    drop(a);
    drop(b);
    assert_eq!(budget.counters.lock().unwrap().live, 0);
}

#[test]
#[ignore = "requires Apple unified-memory GPU; run with --test-threads=1"]
fn chunked_transfers_preserve_individual_gpu_intervals() {
    let runtime = ProQue::new(0, 64 << 20).unwrap();
    let words = runtime.transfer_bytes() / 8 * 3 + 1;
    let input: Vec<_> = (0..words as u64)
        .map(|n| n.wrapping_mul(0x9e3779b97f4a7c15))
        .collect();
    let buffer = Buffer::builder()
        .queue(runtime.queue().clone())
        .flags(flags::MEM_READ_WRITE)
        .len(words)
        .build()
        .unwrap();
    let mut upload = Event::empty();
    buffer.write(&input).enew(&mut upload).enq().unwrap();
    let mut download = Event::empty();
    let mut actual = vec![0; words];
    buffer.read(&mut actual).enew(&mut download).enq().unwrap();
    assert_eq!(input, actual);
    let copy = runtime.queue.0.mode == MemoryMode::Copy;
    for event in [upload, download] {
        let intervals = event.device_intervals().unwrap();
        assert_eq!(intervals.len(), if copy { 4 } else { 0 });
        for pair in intervals.windows(2) {
            assert!(pair[0].1 <= pair[1].0);
        }
        assert!(intervals
            .iter()
            .all(|(start, end)| *start > 0 && end >= start));
        let expected: u128 = intervals
            .iter()
            .map(|(start, end)| u128::from(end - start))
            .sum();
        assert_eq!(event.duration().unwrap(), expected);
    }
    let counters = runtime.queue.0.budget.counters.lock().unwrap();
    assert_eq!(counters.host_copy_bytes, (words * 8 * 2) as u64);
    assert_eq!(
        counters.transfer_blit_bytes,
        if copy { (words * 8 * 2) as u64 } else { 0 }
    );
}

#[test]
#[ignore = "requires Apple unified-memory GPU; run with --test-threads=1"]
fn arithmetic_matches_full_width_integer_oracle_in_both_memory_modes() {
    const P: u64 = 0xffff_ffff_0000_0001;
    let edges = [
        0,
        1,
        2,
        0xffff_ffff,
        0x1_0000_0000,
        P - 2,
        P - 1,
        P,
        u64::MAX,
    ];
    let mut a = Vec::new();
    let mut b = Vec::new();
    for x in edges {
        for y in edges {
            a.push(x);
            b.push(y);
        }
    }
    let mut state = 0x9e3779b97f4a7c15u64;
    for _ in 0..16384 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        a.push(state);
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.push(state);
    }
    for mode in ["shared", "copy"] {
        std::env::set_var("LATTICA_V2_METAL_MEMORY", mode);
        let runtime = ProQue::new(0, 64 << 20).unwrap();
        let buffer = |n| {
            Buffer::builder()
                .queue(runtime.queue().clone())
                .flags(flags::MEM_READ_WRITE)
                .len(n)
                .build()
                .unwrap()
        };
        let aa = buffer(a.len());
        let bb = buffer(b.len());
        let out = buffer(a.len() * 4);
        aa.write(&a).enq().unwrap();
        bb.write(&b).enq().unwrap();
        let kernel = runtime
            .kernel_builder("arithmetic_probe")
            .arg(&aa)
            .arg(&bb)
            .arg(&out)
            .global_work_size(a.len())
            .build()
            .unwrap();
        let mut event = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut event).enq().unwrap();
        }
        assert!(event.duration().unwrap() > 0);
        let mut actual = vec![0; a.len() * 4];
        out.read(&mut actual).enq().unwrap();
        for (i, (&a, &b)) in a.iter().zip(&b).enumerate() {
            let (a, b) = (a as u128, b as u128);
            let p = P as u128;
            let expected = [
                ((a * b) % p) as u64,
                ((a + b) % p) as u64,
                ((a % p + p - b % p) % p) as u64,
                ((a * b) >> 64) as u64,
            ];
            assert_eq!(
                &actual[i * 4..i * 4 + 4],
                &expected,
                "{mode} input {i}: {a:x}, {b:x}"
            );
        }
        assert!(aa.read(&mut [0; 2]).offset(a.len() - 1).enq().is_err());
        assert!(Buffer::builder()
            .queue(runtime.queue().clone())
            .len(64 << 20)
            .build()
            .is_err());
        runtime.report();
    }
    std::env::remove_var("LATTICA_V2_METAL_MEMORY");
}

#[test]
#[ignore = "requires Apple GPU; run serially"]
fn pending_command_retention_is_bounded_and_fully_accounted() {
    let pq = ProQue::new(0, 16 << 20).unwrap();
    for _ in 0..MAX_PENDING_COMMANDS * 3 + 1 {
        pq.queue().enqueue_marker(None).unwrap();
        assert!(pq.queue.0.pending.lock().unwrap().len() <= MAX_PENDING_COMMANDS);
    }
    pq.queue().finish().unwrap();
    assert!(pq.queue.0.pending.lock().unwrap().is_empty());
    assert_eq!(
        pq.queue.0.budget.counters.lock().unwrap().blits,
        (MAX_PENDING_COMMANDS * 3 + 1) as u64
    );
}
