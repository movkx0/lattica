//! Independent integer oracles for the OpenCL lazy field representation.
use super::KERNEL_SRC;
use ocl::{Buffer, ProQue};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

const ORACLE_KERNELS: &str = concat!(
    include_str!("../block_v2/gpu_hash/engine/extension_multiply.cl"),
    r#"
__kernel void field_arithmetic(__global const ulong *a, __global const ulong *b,
                               __global ulong *out) {
    uint i=get_global_id(0);
    out[4*i]=gl_canon(gl_sub(a[i],b[i]));
    out[4*i+1]=gl_canon(gl_add(a[i],b[i]));
    out[4*i+2]=gl_canon(gl_mul(a[i],b[i]));
    out[4*i+3]=gl_canon(gl_reduce128(a[i],b[i]));
}
__kernel void internal_diagonal(__global const ulong *input, __global ulong *out,
                                __global const ulong *diagonal) {
    uint i=get_global_id(0); ulong state[8];
    for(uint lane=0;lane<8;lane++)state[lane]=input[8*i+lane];
    intl(state,diagonal);
    for(uint lane=0;lane<8;lane++)out[8*i+lane]=gl_canon(state[lane]);
}
__kernel void field_sum8(__global const ulong *input, __global ulong *out) {
    uint i=get_global_id(0); ulong state[8];
    for(uint lane=0;lane<8;lane++)state[lane]=input[8*i+lane];
    out[i]=gl_canon(gl_sum8(state));
}
__kernel void external_matrix(__global const ulong *input, __global ulong *out) {
    uint i=get_global_id(0); ulong state[8];
    for(uint lane=0;lane<8;lane++)state[lane]=input[8*i+lane];
    extl(state);
    for(uint lane=0;lane<8;lane++)out[8*i+lane]=gl_canon(state[lane]);
}
__kernel void field_bit_reverse(__global const ulong *input, __global ulong *out) {
    uint i=get_global_id(0);
    out[i]=(ulong)brev((uint)input[i/33u],i%33u);
}
__kernel void external_limb_reduction(__global const ulong *input, __global ulong *out) {
    uint i=get_global_id(0);
    out[i]=gl_canon(gl_reduce_matrix_limbs(input[2*i],input[2*i+1]));
}
__kernel void field_inverse(__global const ulong *input, __global ulong *out) {
    uint i=get_global_id(0);
    out[i]=gl_canon(gl_inverse(input[i]));
}
__kernel void extension_product(__global const ulong *a, __global const ulong *b,
                                __global ulong *out, uint degree) {
    uint i=get_global_id(0); ulong x[3], y[3], result[3];
    for(uint j=0;j<degree;j++){x[j]=a[degree*i+j];y[j]=b[degree*i+j];}
    if(degree==3)opening_cubic_mul(x,y,result);
    else opening_quadratic_mul(x,y,result);
    for(uint j=0;j<degree;j++)out[degree*i+j]=gl_canon(result[j]);
}
__kernel void extension_dot_product(__global const ulong *a, __global const ulong *b,
                                    __global ulong *out) {
    uint i=3*get_global_id(0);
#ifdef LATTICA_NVIDIA_FIELD_CARRY
    ulong result=opening_dot3(a[i],a[i+1],a[i+2],b[i],b[i+1],b[i+2]);
#else
    ulong result=gl_add(gl_add(gl_mul(a[i],b[i]),gl_mul(a[i+1],b[i+1])),gl_mul(a[i+2],b[i+2]));
#endif
    out[i/3]=gl_canon(result);
}
"#,
);

fn program(prefix: &str) -> ProQue {
    program_with_arithmetic(prefix, true)
}

fn program_with_arithmetic(prefix: &str, accelerated: bool) -> ProQue {
    let (platform, device, _) = crate::gpu_device::select().unwrap();
    let arithmetic = if accelerated {
        super::field::source_prefix(device)
    } else {
        ""
    };
    ProQue::builder()
        .platform(platform)
        .device(device)
        .src([arithmetic, prefix, KERNEL_SRC, ORACLE_KERNELS].concat())
        .dims(1)
        .build()
        .unwrap()
}

fn upload(pq: &ProQue, words: &[u64]) -> Buffer<u64> {
    pq.buffer_builder::<u64>()
        .len(words.len())
        .copy_host_slice(words)
        .build()
        .unwrap()
}

fn edges() -> [u64; 13] {
    let p = Goldilocks::ORDER_U64;
    [
        0,
        1,
        2,
        (1 << 32) - 2,
        (1 << 32) - 1,
        1 << 32,
        p - 2,
        p - 1,
        p,
        p + 1,
        p + 2,
        u64::MAX - 1,
        u64::MAX,
    ]
}

fn integer_power(mut base: u64, mut exponent: u64) -> u64 {
    let p = Goldilocks::ORDER_U64 as u128;
    base = (base as u128 % p) as u64;
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = (result as u128 * base as u128 % p) as u64;
        }
        base = (base as u128 * base as u128 % p) as u64;
        exponent >>= 1;
    }
    result
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_inverse_chain_matches_full_u64_integer_oracle() {
    let mut values = edges().to_vec();
    for bit in 0..64 {
        values.extend([1u64 << bit, u64::MAX ^ (1u64 << bit)]);
    }
    let mut rng = ChaCha20Rng::from_seed([205; 32]);
    values.extend((0..65536).map(|_| rng.random::<u64>()));
    let pq = program("");
    let input = upload(&pq, &values);
    let output = pq
        .buffer_builder::<u64>()
        .len(values.len())
        .build()
        .unwrap();
    let kernel = pq
        .kernel_builder("field_inverse")
        .arg(&input)
        .arg(&output)
        .global_work_size(values.len())
        .build()
        .unwrap();
    // SAFETY: one output per input, and both buffers cover every work item.
    unsafe { kernel.enq().unwrap() };
    let mut actual = vec![0; values.len()];
    output.read(&mut actual).enq().unwrap();
    pq.queue().finish().unwrap();
    let p = Goldilocks::ORDER_U64;
    for (&value, inverse) in values.iter().zip(actual) {
        assert_eq!(inverse, integer_power(value, p - 2), "input {value}");
        let product = (value as u128 * inverse as u128 % p as u128) as u64;
        assert_eq!(product, u64::from(value % p != 0), "input {value}");
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_quotient_selectors_match_integer_oracle_and_preserve_domain_rejection() {
    let p = Goldilocks::ORDER_U64;
    let (platform, device, _) = crate::gpu_device::select().unwrap();
    for degree in [2usize, 3] {
        // Exercise the actual quotient kernel, using selectors as constraints.
        // The final multiplication by inverse_z remains in the production source.
        let prefix = format!(
            "#define QUOTIENT_DEGREE {degree}\n\
             #define QUOTIENT_MUL opening_{}_mul\n\
             #define QUOTIENT_ALPHA selector_alpha\n\
             #define QUOTIENT_EVALUATE selector_oracle\n\
             #define QUOTIENT_SPECIALIZED(input,width,parameters,weights,scratch,rows,row,first,last,transition,accumulator) {}\n",
            if degree == 2 { "quadratic" } else { "cubic" },
            if degree == 2 {
                "accumulator[0]=first; accumulator[1]=transition"
            } else {
                "accumulator[0]=first; accumulator[1]=last; accumulator[2]=transition"
            }
        );
        let source = [
            super::field::source_prefix(device),
            KERNEL_SRC,
            include_str!("../block_v2/gpu_hash/engine/extension_multiply.cl"),
            &prefix,
            include_str!("../block_v2/gpu_hash/engine/quotient_kernels.cl"),
        ]
        .concat();
        let pq = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(source)
            .dims(1)
            .build()
            .unwrap();
        for (rows, first_row, log_trace, shift, log_domain) in [
            (1024u32, 0u32, 6u32, 7u64, 10u32),
            (4096, 8192, 8, 7, 16),
            (257, 0, 4, 1, 8),
            (257, 0, 4, 0, 8),
            (257, 0, 4, p, 8),
            (1024, 0, 0, 1, 10),
            (1024, 12345, 12, p + 7, 16),
        ] {
            let root = integer_power(7, (p - 1) >> log_domain);
            let last = integer_power(7, (p - 1) - ((p - 1) >> log_trace));
            let prefix_rows = 5u32;
            let marker = 0x1234_5678_9abc_def0;
            let dummy = upload(&pq, &[0]);
            let mut actual = vec![marker; (rows + prefix_rows + 1) as usize * degree];
            let output = upload(&pq, &actual);
            let kernel = pq
                .kernel_builder("selector_oracle")
                .arg(&dummy)
                .arg(0u32)
                .arg(&dummy)
                .arg(0u32)
                .arg(&dummy)
                .arg(&dummy)
                .arg(&dummy)
                .arg(&output)
                .arg(rows)
                .arg(first_row)
                .arg(prefix_rows)
                .arg(log_trace)
                .arg(shift)
                .arg(root)
                .arg(last)
                .global_work_size((rows as usize).div_ceil(64) * 64)
                .build()
                .unwrap();
            // SAFETY: dummy inputs are unused; the row guard and output prefix
            // bound all writes. Extra work items exercise that guard.
            unsafe { kernel.enq().unwrap() };
            output.read(&mut actual).enq().unwrap();
            pq.queue().finish().unwrap();
            assert!(actual[..prefix_rows as usize * degree]
                .iter()
                .all(|&x| x == marker));
            assert!(actual[(prefix_rows + rows) as usize * degree..]
                .iter()
                .all(|&x| x == marker));
            for row in 0..rows {
                let x = (shift as u128 * integer_power(root, (first_row + row) as u64) as u128
                    % p as u128) as u64;
                let z = ((integer_power(x, 1u64 << log_trace) as u128 + p as u128 - 1) % p as u128)
                    as u64;
                let first_denominator = ((x as u128 + p as u128 - 1) % p as u128) as u64;
                let transition = ((x as u128 + p as u128 - last as u128) % p as u128) as u64;
                let expected = if z == 0 || first_denominator == 0 || transition == 0 {
                    vec![p; degree]
                } else {
                    let scaled_transition =
                        (transition as u128 * integer_power(z, p - 2) as u128 % p as u128) as u64;
                    if degree == 2 {
                        vec![integer_power(first_denominator, p - 2), scaled_transition]
                    } else {
                        vec![
                            integer_power(first_denominator, p - 2),
                            integer_power(transition, p - 2),
                            scaled_transition,
                        ]
                    }
                };
                let offset = (prefix_rows + row) as usize * degree;
                assert_eq!(
                    &actual[offset..offset + degree],
                    &expected,
                    "degree {degree}, shift {shift}, row {row}"
                );
            }
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_external_matrix_matches_full_u64_integer_oracle() {
    let mut states: Vec<[u64; 8]> = edges().into_iter().map(|edge| [edge; 8]).collect();
    for a in edges() {
        for b in edges() {
            for split in 1..8 {
                states.push(std::array::from_fn(|i| if i < split { a } else { b }));
            }
        }
        for lane in 0..8 {
            states.push(std::array::from_fn(|i| if i == lane { a } else { 0 }));
        }
    }
    let mut rng = ChaCha20Rng::from_seed([201; 32]);
    states.extend((0..65536).map(|_| std::array::from_fn(|_| rng.random::<u64>())));
    let pq = program("");
    let input = upload(&pq, &states.iter().flatten().copied().collect::<Vec<_>>());
    let output = pq
        .buffer_builder::<u64>()
        .len(states.len() * 8)
        .build()
        .unwrap();
    let kernel = pq
        .kernel_builder("external_matrix")
        .arg(&input)
        .arg(&output)
        .global_work_size(states.len())
        .build()
        .unwrap();
    // SAFETY: each item owns eight input and eight output words.
    unsafe { kernel.enq().unwrap() };
    let mut actual = vec![0; states.len() * 8];
    output.read(&mut actual).enq().unwrap();
    pq.queue().finish().unwrap();
    let matrix: [[u128; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    let p = Goldilocks::ORDER_U64 as u128;
    for (state, actual) in states.iter().zip(actual.chunks_exact(8)) {
        let inner: [u128; 8] = std::array::from_fn(|i| {
            (0..4)
                .map(|j| matrix[i % 4][j] * state[(i / 4) * 4 + j] as u128)
                .sum()
        });
        let expected: [u64; 8] =
            std::array::from_fn(|i| ((2 * inner[i] + inner[i ^ 4]) % p) as u64);
        assert_eq!(actual, expected, "state: {state:x?}");
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_external_limb_reduction_matches_bounded_integer_oracle() {
    let limit = 21 * u32::MAX as u64;
    let mut limbs = vec![0, 1, 2, limit - 1, limit];
    for high in 0..=20 {
        for low in [0, 1, u32::MAX as u64 - 1, u32::MAX as u64] {
            limbs.push((high << 32) | low);
        }
    }
    limbs.retain(|&limb| limb <= limit);
    let mut pairs: Vec<_> = limbs
        .iter()
        .flat_map(|&a| limbs.iter().map(move |&b| (a, b)))
        .collect();
    let mut rng = ChaCha20Rng::from_seed([202; 32]);
    pairs.extend((0..65536).map(|_| (rng.random_range(0..=limit), rng.random_range(0..=limit))));
    // Both reconstruction and modular-fold carries occur in these edge pairs.
    let mut carries = [[false; 2]; 2];
    for &(low, high) in &pairs {
        let lo = low.wrapping_add(high << 32);
        let reconstruction_carry = lo < low;
        let hi = (high >> 32) + u64::from(reconstruction_carry);
        assert!(hi <= 20);
        let fold_carry = lo.overflowing_add(hi * u32::MAX as u64).1;
        carries[usize::from(reconstruction_carry)][usize::from(fold_carry)] = true;
    }
    assert!(carries[0][0] && carries[0][1] && carries[1][0]);
    for accelerated in [false, true] {
        let pq = program_with_arithmetic("", accelerated);
        let input = upload(
            &pq,
            &pairs.iter().flat_map(|&(a, b)| [a, b]).collect::<Vec<_>>(),
        );
        let output = pq.buffer_builder::<u64>().len(pairs.len()).build().unwrap();
        let kernel = pq
            .kernel_builder("external_limb_reduction")
            .arg(&input)
            .arg(&output)
            .global_work_size(pairs.len())
            .build()
            .unwrap();
        // SAFETY: each item reads its two bounded limbs and writes one result.
        unsafe { kernel.enq().unwrap() };
        let mut actual = vec![0; pairs.len()];
        output.read(&mut actual).enq().unwrap();
        pq.queue().finish().unwrap();
        let p = Goldilocks::ORDER_U64 as u128;
        for ((low, high), actual) in pairs.iter().copied().zip(actual) {
            let expected = ((low as u128 + ((high as u128) << 32)) % p) as u64;
            assert_eq!(
                actual, expected,
                "limbs: {low:#x}, {high:#x}, accelerated={accelerated}"
            );
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_bit_reverse_matches_integer_oracle_for_all_bit_counts() {
    let mut values: Vec<u64> = edges().into_iter().map(|x| x as u32 as u64).collect();
    values.extend(
        (0..32)
            .flat_map(|i| [1u32 << i, !(1u32 << i)])
            .map(u64::from),
    );
    let mut rng = ChaCha20Rng::from_seed([203; 32]);
    values.extend((0..65536).map(|_| rng.random::<u32>() as u64));
    let pq = program("");
    let input = upload(&pq, &values);
    let output = pq
        .buffer_builder::<u64>()
        .len(values.len() * 33)
        .build()
        .unwrap();
    let kernel = pq
        .kernel_builder("field_bit_reverse")
        .arg(&input)
        .arg(&output)
        .global_work_size(values.len() * 33)
        .build()
        .unwrap();
    // SAFETY: all 33 legal bit counts write a disjoint word for each input.
    unsafe { kernel.enq().unwrap() };
    let mut actual = vec![0; values.len() * 33];
    output.read(&mut actual).enq().unwrap();
    pq.queue().finish().unwrap();
    for (value, actual) in values.into_iter().zip(actual.chunks_exact(33)) {
        for (bits, &actual) in actual.iter().enumerate() {
            let expected = if bits == 0 {
                0
            } else {
                (value as u32).reverse_bits() >> (32 - bits)
            };
            assert_eq!(actual, expected as u64, "input: {value:#x}, bits: {bits}");
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_lazy_field_arithmetic_matches_full_u64_integer_oracle() {
    // Cross low/high limb boundaries, both carry/borrow folds, and lazy
    // representatives around p. Reduction also accepts every 128-bit integer.
    let limbs = [
        0u64,
        1,
        2,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_fffd,
        0xffff_fffe,
        0xffff_ffff,
    ];
    let mut values: std::collections::BTreeSet<u64> = limbs
        .into_iter()
        .flat_map(|hi| limbs.into_iter().map(move |lo| (hi << 32) | lo))
        .collect();
    values.extend(edges());
    let mut pairs: Vec<_> = values
        .iter()
        .flat_map(|&a| values.iter().map(move |&b| (a, b)))
        .collect();
    let mut rng = ChaCha20Rng::from_seed([197; 32]);
    pairs.extend((0..262144).map(|_| (rng.random::<u64>(), rng.random::<u64>())));
    for accelerated in [false, true] {
        let pq =
            program_with_arithmetic(crate::gpu_constants::opencl_poseidon2_prefix(), accelerated);
        let a = upload(&pq, &pairs.iter().map(|&(a, _)| a).collect::<Vec<_>>());
        let b = upload(&pq, &pairs.iter().map(|&(_, b)| b).collect::<Vec<_>>());
        let output = pq
            .buffer_builder::<u64>()
            .len(pairs.len() * 4)
            .build()
            .unwrap();
        let kernel = pq
            .kernel_builder("field_arithmetic")
            .arg(&a)
            .arg(&b)
            .arg(&output)
            .global_work_size(pairs.len())
            .build()
            .unwrap();
        // SAFETY: one work item per pair; all inputs and four-word outputs fit.
        unsafe { kernel.enq().unwrap() };
        let mut actual = vec![0; pairs.len() * 4];
        output.read(&mut actual).enq().unwrap();
        pq.queue().finish().unwrap();
        let p = Goldilocks::ORDER_U64 as u128;
        for (&(a, b), actual) in pairs.iter().zip(actual.chunks_exact(4)) {
            let (a, b) = (a as u128, b as u128);
            let expected = [
                ((a % p + p - b % p) % p) as u64,
                ((a + b) % p) as u64,
                ((a * b) % p) as u64,
                (((b << 64) | a) % p) as u64,
            ];
            assert_eq!(actual, expected, "inputs: {a:#x}, {b:#x}");
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_sum8_matches_full_u64_integer_oracle() {
    let mut states: Vec<[u64; 8]> = edges().into_iter().map(|edge| [edge; 8]).collect();
    // Exercise both limb accumulators and the carry between the reconstructed
    // low/high words, including sums with high words zero through seven.
    for a in edges() {
        for b in edges() {
            for split in 1..8 {
                states.push(std::array::from_fn(|i| if i < split { a } else { b }));
            }
        }
    }
    let mut rng = ChaCha20Rng::from_seed([199; 32]);
    states.extend((0..65536).map(|_| std::array::from_fn(|_| rng.random::<u64>())));
    let pq = program("");
    let input = upload(&pq, &states.iter().flatten().copied().collect::<Vec<_>>());
    let output = pq
        .buffer_builder::<u64>()
        .len(states.len())
        .build()
        .unwrap();
    let kernel = pq
        .kernel_builder("field_sum8")
        .arg(&input)
        .arg(&output)
        .global_work_size(states.len())
        .build()
        .unwrap();
    // SAFETY: each item reads its own eight words and writes one result.
    unsafe { kernel.enq().unwrap() };
    let mut actual = vec![0; states.len()];
    output.read(&mut actual).enq().unwrap();
    pq.queue().finish().unwrap();
    let p = Goldilocks::ORDER_U64 as u128;
    for (state, actual) in states.iter().zip(actual) {
        let sum = state.iter().map(|&value| value as u128).sum::<u128>();
        assert_eq!(actual, (sum % p) as u64, "state: {state:x?}");
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_poseidon2_diagonal_and_generic_fallback_match_integer_oracle() {
    let mut states: Vec<[u64; 8]> = edges().into_iter().map(|edge| [edge; 8]).collect();
    for a in edges() {
        for b in edges() {
            for split in 1..8 {
                states.push(std::array::from_fn(|lane| if lane < split { a } else { b }));
            }
        }
        for lane in 0..8 {
            let mut state = [0; 8];
            state[lane] = a;
            states.push(state);
        }
    }
    let mut rng = ChaCha20Rng::from_seed([198; 32]);
    states.extend((0..65536).map(|_| std::array::from_fn(|_| rng.random::<u64>())));
    let (_, _, _, diagonal) = crate::gpu_constants::poseidon2_consts();
    let mut custom = diagonal.clone();
    for (index, value) in custom.iter_mut().enumerate() {
        *value ^= 0x1234_5678_9abc_def0u64.rotate_left(index as u32);
    }
    let fast = crate::gpu_constants::opencl_poseidon2_prefix();
    assert!(!fast.is_empty());
    for (label, prefix, diagonal) in [
        ("generic default", "", &diagonal),
        ("specialized default", fast, &diagonal),
        ("generic custom", "", &custom),
    ] {
        let pq = program(prefix);
        let input = upload(&pq, &states.iter().flatten().copied().collect::<Vec<_>>());
        let diag = upload(&pq, diagonal);
        let output = pq
            .buffer_builder::<u64>()
            .len(states.len() * 8)
            .build()
            .unwrap();
        let kernel = pq
            .kernel_builder("internal_diagonal")
            .arg(&input)
            .arg(&output)
            .arg(&diag)
            .global_work_size(states.len())
            .build()
            .unwrap();
        // SAFETY: each work item owns eight words; all buffers cover every state.
        unsafe { kernel.enq().unwrap() };
        let mut actual = vec![0; states.len() * 8];
        output.read(&mut actual).enq().unwrap();
        pq.queue().finish().unwrap();
        let p = Goldilocks::ORDER_U64 as u128;
        for (state, actual) in states.iter().zip(actual.chunks_exact(8)) {
            let sum = state.iter().map(|&value| value as u128).sum::<u128>() % p;
            for lane in 0..8 {
                // Reduce the product first so the independent u128 oracle cannot overflow.
                let product = state[lane] as u128 * diagonal[lane] as u128 % p;
                assert_eq!(
                    actual[lane],
                    ((product + sum) % p) as u64,
                    "{label}, lane {lane}"
                );
            }
        }
    }
}

fn extension_limb_edges() -> Vec<u64> {
    let limbs = [
        0u64,
        1,
        2,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_fffd,
        0xffff_fffe,
        0xffff_ffff,
    ];
    let mut values: std::collections::BTreeSet<u64> = limbs
        .iter()
        .flat_map(|&hi| limbs.iter().map(move |&lo| (hi << 32) | lo))
        .collect();
    values.extend(edges());
    values.into_iter().collect()
}

fn integer_extension_product(a: &[u64], b: &[u64]) -> Vec<u64> {
    let p = Goldilocks::ORDER_U64 as u128;
    let degree = a.len();
    let mut coefficients = vec![0u128; 2 * degree - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            coefficients[i + j] = (coefficients[i + j] + x as u128 * y as u128 % p) % p;
        }
    }
    if degree == 3 {
        // Polynomial long division by X^3-X-1, independent of the GPU formulas.
        for k in (3..=4).rev() {
            coefficients[k - 3] = (coefficients[k - 3] + coefficients[k]) % p;
            coefficients[k - 2] = (coefficients[k - 2] + coefficients[k]) % p;
        }
    } else {
        coefficients[0] = (coefficients[0] + 7 * coefficients[2]) % p;
    }
    coefficients[..degree].iter().map(|&x| x as u64).collect()
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_extension_products_match_full_u64_polynomial_oracle() {
    let edges = extension_limb_edges();
    let mut rng = ChaCha20Rng::from_seed([217; 32]);
    for degree in [2usize, 3] {
        let mut cases = Vec::new();
        for &x in &edges {
            for &y in &edges {
                cases.push((vec![x; degree], vec![y; degree]));
                for i in 0..degree {
                    for j in 0..degree {
                        let mut a = vec![0; degree];
                        let mut b = vec![0; degree];
                        a[i] = x;
                        b[j] = y;
                        cases.push((a, b));
                    }
                }
            }
        }
        for _ in 0..65536 {
            cases.push((
                (0..degree).map(|_| rng.random::<u64>()).collect(),
                (0..degree).map(|_| rng.random::<u64>()).collect(),
            ));
        }
        let expected: Vec<_> = cases
            .iter()
            .flat_map(|(a, b)| integer_extension_product(a, b))
            .collect();
        let a: Vec<_> = cases.iter().flat_map(|(a, _)| a.iter().copied()).collect();
        let b: Vec<_> = cases.iter().flat_map(|(_, b)| b.iter().copied()).collect();
        for accelerated in [false, true] {
            let pq = program_with_arithmetic("", accelerated);
            let input_a = upload(&pq, &a);
            let input_b = upload(&pq, &b);
            let output = pq
                .buffer_builder::<u64>()
                .len(expected.len())
                .build()
                .unwrap();
            let kernel = pq
                .kernel_builder("extension_product")
                .arg(&input_a)
                .arg(&input_b)
                .arg(&output)
                .arg(degree as u32)
                .global_work_size(cases.len())
                .build()
                .unwrap();
            // SAFETY: buffers have degree words per work item; degree is 2 or 3.
            unsafe { kernel.enq().unwrap() };
            let mut actual = vec![0; expected.len()];
            output.read(&mut actual).enq().unwrap();
            pq.queue().finish().unwrap();
            assert_eq!(
                actual, expected,
                "degree {degree}, accelerated {accelerated}"
            );
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded zero-swap service"]
fn gpu_extension_dot_product_matches_full_u64_integer_oracle() {
    let edges = extension_limb_edges();
    let mut cases = Vec::new();
    for &x in &edges {
        for &y in &edges {
            // Includes all possible top carries (0, 1, 2) and low/high carry chains.
            for terms in 1..=3 {
                let mut a = [0; 3];
                let mut b = [0; 3];
                a[..terms].fill(x);
                b[..terms].fill(y);
                cases.push((a, b));
            }
        }
    }
    let mut rng = ChaCha20Rng::from_seed([218; 32]);
    cases.extend((0..131072).map(|_| (rng.random::<[u64; 3]>(), rng.random::<[u64; 3]>())));
    let p = Goldilocks::ORDER_U64 as u128;
    let expected: Vec<_> = cases
        .iter()
        .map(|(a, b)| {
            a.iter()
                .zip(b)
                .fold(0u128, |sum, (&x, &y)| (sum + x as u128 * y as u128 % p) % p)
                as u64
        })
        .collect();
    let a: Vec<_> = cases.iter().flat_map(|(a, _)| a.iter().copied()).collect();
    let b: Vec<_> = cases.iter().flat_map(|(_, b)| b.iter().copied()).collect();
    for accelerated in [false, true] {
        let pq = program_with_arithmetic("", accelerated);
        let input_a = upload(&pq, &a);
        let input_b = upload(&pq, &b);
        let output = pq
            .buffer_builder::<u64>()
            .len(expected.len())
            .build()
            .unwrap();
        let kernel = pq
            .kernel_builder("extension_dot_product")
            .arg(&input_a)
            .arg(&input_b)
            .arg(&output)
            .global_work_size(cases.len())
            .build()
            .unwrap();
        // SAFETY: each work item reads three input words and writes one output word.
        unsafe { kernel.enq().unwrap() };
        let mut actual = vec![0; expected.len()];
        output.read(&mut actual).enq().unwrap();
        pq.queue().finish().unwrap();
        assert_eq!(actual, expected, "accelerated {accelerated}");
    }
}
