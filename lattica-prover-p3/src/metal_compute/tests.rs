use super::*;

#[test]
#[ignore = "requires Apple GPU with >8 GiB buffer capacity; run serially"]
fn large_buffer_shader_offsets_and_zero_fill_cover_full_ranges() {
    let runtime = ProQue::new(0, 10usize << 30).unwrap();
    let high_word = 1usize << 30;
    let output = Buffer::builder()
        .queue(runtime.queue().clone())
        .len(high_word + 8)
        .build()
        .unwrap();
    let input = Buffer::builder()
        .queue(runtime.queue().clone())
        .len(1)
        .build()
        .unwrap();
    input.write(&[0x1234_5678_9abc_def0]).enq().unwrap();
    // Only touch the tested pages: buffer size must not change addressing or
    // require a multi-gigabyte host-side reference allocation.
    for word in [0, (1usize << 29) - 1, 1usize << 29, high_word] {
        output.write(&[0]).offset(word).enq().unwrap();
    }
    for word in [(1usize << 29) - 1, 1usize << 29, high_word] {
        unsafe {
            runtime
                .kernel_builder("prefix_scatter")
                .arg(&input)
                .arg(&output)
                .arg((high_word + 1) as u32)
                .arg(word as u32)
                .arg(1u32)
                .global_work_size(1)
                .build()
                .unwrap()
                .cmd()
                .enq()
                .unwrap();
        }
        let mut actual = [0];
        output.read(&mut actual).offset(word).enq().unwrap();
        assert_eq!(actual, [0x1234_5678_9abc_def0], "word offset {word}");
    }
    let mut low = [1];
    output.read(&mut low).enq().unwrap();
    assert_eq!(low, [0], "large offsets must not wrap into the first page");
    let probes = [
        0,
        (1usize << 28) - 1,
        1usize << 28,
        (1usize << 29) - 1,
        1usize << 29,
        high_word - 1,
        high_word,
        high_word + 7,
    ];
    for word in probes {
        output.write(&[u64::MAX]).offset(word).enq().unwrap();
    }
    output.cmd().fill(0, None).enq().unwrap();
    for word in probes {
        let mut actual = [u64::MAX];
        output.read(&mut actual).offset(word).enq().unwrap();
        assert_eq!(actual, [0], "zero fill at byte offset {}", word * 8);
    }
    // A partial fill must clear its entire requested range without touching
    // the adjacent word, including when the boundary is beyond 4 GiB.
    let count = (1usize << 29) + 3;
    output.write(&[17, 29]).offset(count - 1).enq().unwrap();
    output.cmd().fill(0, Some(count)).enq().unwrap();
    let mut boundary = [0, 0];
    output.read(&mut boundary).offset(count - 1).enq().unwrap();
    assert_eq!(boundary, [0, 29]);
}

#[test]
#[ignore = "requires Apple GPU; run serially"]
fn diagonal_and_poseidon_match_cpu_for_redundant_representatives() {
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
    use p3_symmetric::Permutation;
    const P: u64 = 0xffff_ffff_0000_0001;
    let mut values = vec![0, 1, 2, P - 2, P - 1, P, P + 1, u64::MAX];
    let mut seed = 0x7f44_3311_0022_99aau64;
    for _ in 0..4099 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        values.push(seed);
    }
    let pq = ProQue::new(0, 64 << 20).unwrap();
    let buffer = |words: &[u64]| {
        let b = Buffer::builder()
            .queue(pq.queue().clone())
            .len(words.len())
            .build()
            .unwrap();
        b.write(words).enq().unwrap();
        b
    };
    let input = buffer(&values);
    let output = buffer(&vec![0; values.len() * 8]);
    let diag = crate::gpu_constants::poseidon2_consts().3;
    unsafe {
        pq.kernel_builder("diagonal_probe")
            .arg(&input)
            .arg(&output)
            .global_work_size(values.len())
            .build()
            .unwrap()
            .cmd()
            .enq()
            .unwrap();
    }
    let mut actual = vec![0; values.len() * 8];
    output.read(&mut actual).enq().unwrap();
    for (row, &v) in values.iter().enumerate() {
        for lane in 0..8 {
            assert_eq!(
                actual[row * 8 + lane],
                ((v as u128 * diag[lane] as u128) % P as u128) as u64,
                "diagonal input={v:x} lane={lane}"
            );
        }
    }
    let rows = 513;
    let state_words: Vec<_> = (0..rows * 8).map(|i| values[i % values.len()]).collect();
    let row_words: Vec<_> = (0..rows * 4)
        .map(|i| values[(i * 13) % values.len()])
        .collect();
    let states = buffer(&state_words);
    let inputs = buffer(&row_words);
    let (initial, internal, final_, diagonal) = crate::gpu_constants::poseidon2_consts();
    let constants = [
        buffer(&initial),
        buffer(&internal),
        buffer(&final_),
        buffer(&diagonal),
    ];
    unsafe {
        pq.kernel_builder("lde_absorb")
            .arg(&inputs)
            .arg(&states)
            .arg(0u32)
            .arg(rows as u32)
            .arg(4u32)
            .arg(0u32)
            .arg(&constants[0])
            .arg(&constants[1])
            .arg(&constants[2])
            .arg(&constants[3])
            .global_work_size(rows)
            .build()
            .unwrap()
            .cmd()
            .enq()
            .unwrap();
    }
    let mut actual = vec![0; rows * 8];
    states.read(&mut actual).enq().unwrap();
    let perm = default_goldilocks_poseidon2_8();
    for row in 0..rows {
        let mut expected: [Goldilocks; 8] =
            std::array::from_fn(|i| Goldilocks::from_u64(state_words[row * 8 + i]));
        for i in 0..4 {
            expected[i] = Goldilocks::from_u64(row_words[row * 4 + i]);
        }
        perm.permute_mut(&mut expected);
        for i in 0..8 {
            assert_eq!(
                Goldilocks::from_u64(actual[row * 8 + i]).as_canonical_u64(),
                expected[i].as_canonical_u64(),
                "Poseidon row={row} lane={i}"
            );
        }
    }
    pq.report();
}

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
        limit: Some(100),
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
fn resident_native_accounting_allows_allocations_above_worker_estimate() {
    // Exercise accounting only; no large host or GPU allocation is needed.
    let budget = Arc::new(Budget {
        limit: None,
        counters: Mutex::new(Accounting::default()),
    });
    let a = NativeAllocation::new(17usize << 30, &budget).unwrap();
    let b = NativeAllocation::new(192 << 20, &budget).unwrap();
    let expected = (17usize << 30) + (192 << 20);
    assert_eq!(budget.counters.lock().unwrap().live, expected);
    assert_eq!(budget.counters.lock().unwrap().peak, expected);
    assert!(NativeAllocation::new(usize::MAX, &budget).is_err());
    drop((a, b));
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
    assert!(pq.queue.0.last.lock().unwrap().is_none(), "completed command must not retain its last resources");
    assert_eq!(
        pq.queue.0.budget.counters.lock().unwrap().blits,
        (MAX_PENDING_COMMANDS * 3 + 1) as u64
    );
}

#[test]
#[ignore = "requires Apple GPU; serial environment"]
fn resident_batches_count_each_interval_once_and_flush_incomplete_work() {
    std::env::set_var("LATTICA_V2_METAL_PIPELINE", "resident");
    std::env::set_var("LATTICA_V2_METAL_MEMORY", "shared");
    let pq = ProQue::new(0, 64 << 20).unwrap();
    let a = Buffer::builder()
        .queue(pq.queue().clone())
        .len(32)
        .build()
        .unwrap();
    let b = Buffer::builder()
        .queue(pq.queue().clone())
        .len(32)
        .build()
        .unwrap();
    let out = Buffer::builder()
        .queue(pq.queue().clone())
        .len(128)
        .build()
        .unwrap();
    a.write(&[7; 32]).enq().unwrap();
    b.write(&[11; 32]).enq().unwrap();
    let k = pq
        .kernel_builder("arithmetic_probe")
        .arg(&a)
        .arg(&b)
        .arg(&out)
        .global_work_size(32)
        .build()
        .unwrap();
    let mut events = Vec::new();
    for _ in 0..19 {
        let mut e = Event::empty();
        unsafe {
            k.cmd().enew(&mut e).enq().unwrap();
        }
        events.push(e);
    }
    let mut values = vec![0; 128];
    out.read(&mut values).enq().unwrap();
    assert_eq!(values[0], 77);
    let intervals = events
        .iter()
        .map(|e| e.device_intervals().unwrap().len())
        .sum::<usize>();
    assert_eq!(intervals, 3);
    let a = pq.queue.0.budget.counters.lock().unwrap();
    assert_eq!(a.kernels, 19);
    assert_eq!(a.kernel_commands, 3);
}

#[test]
#[ignore = "requires Apple GPU; serial environment"]
fn frozen_storage_rejects_writable_aliases_and_compacts_after_completion() {
    std::env::set_var("LATTICA_V2_METAL_MEMORY", "shared");
    let pq = ProQue::new(0, 64 << 20).unwrap();
    let mut words = resident::SharedWords::new(pq.queue(), 32).unwrap();
    words
        .with_cpu_mut(|w| {
            for (i, v) in w.iter_mut().enumerate() {
                *v = i as u64;
            }
        })
        .unwrap();
    let alias = words.buffer().clone();
    assert!(words.freeze().is_err());
    drop(alias);
    let mut words = resident::SharedWords::new(pq.queue(), 32).unwrap();
    words
        .with_cpu_mut(|w| {
            for (i, v) in w.iter_mut().enumerate() {
                *v = i as u64;
            }
        })
        .unwrap();
    let frozen = words.freeze().unwrap();
    let prefix = frozen.prefix(11).unwrap();
    drop(frozen);
    assert_eq!(prefix.words(), &(0..11).collect::<Vec<u64>>());
    drop(prefix);
    assert_eq!(
        pq.queue.0.budget.counters.lock().unwrap().live,
        pq.transfer_bytes()
    );
}
