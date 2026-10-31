use super::*;
use crate::{
    block_v2::quotient_program::{specialize, Program},
    gpu_matrix::Extension,
    spill_alloc::allocation_requests::measure,
};
use p3_air::symbolic::AirLayout;
use std::{collections::BTreeMap, hint::black_box};

#[test]
fn outer_ocl_census_is_pure_checked_and_additive() {
    let (census, requests) = measure(FixedOuterOclStorage::fixed);
    let census = census.unwrap();
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
    assert_eq!(
        source_liveness_bytes(MAX_INSTRUCTIONS, MAX_REGISTERS),
        Some(129 * 64)
    );
    assert_eq!(source_copy_requests(usize::MAX), None);
    assert_eq!(source_liveness_bytes(usize::MAX, MAX_REGISTERS), None);
    assert_eq!(source_liveness_bytes(64, 513), None);
    assert!(census.required_host_bytes() > 10 << 20);
    assert!(census.required_host_bytes() < 11 << 20);
    println!(
        "outer_ocl_additive_host_bytes={}",
        census.required_host_bytes()
    );
}

#[test]
fn borrowed_specialization_source_and_real_builder_fit_original_claim() {
    // Real ocl ProgramBuilder handling, matching prepare's borrowed source and
    // compiler option. No Context/Program is created and no driver is called.
    let (lengths, requests) = measure(|| {
        let source = "x".repeat(MAX_SOURCE_BYTES);
        let mut builder = ocl::Program::builder();
        builder.src(&source).cmplr_opt("-cl-std=CL1.2");
        let strings = builder.get_src_strings().unwrap();
        let options = builder.get_compiler_options().unwrap();
        black_box((&source, &builder, &strings, &options));
        (
            strings.iter().map(|s| s.as_bytes().len()).sum::<usize>(),
            options.as_bytes().len(),
        )
    });
    assert_eq!(lengths, (MAX_SOURCE_BYTES + 2, "-cl-std=CL1.2".len()));
    assert!(!requests.overflow && requests.calls > 0);
    assert!(
        requests.bytes <= source_copy_requests(MAX_SOURCE_BYTES).unwrap() + PROGRAM_DESCRIPTORS
    );
    println!("outer_specialized_program_builder_requests={requests:?}");
}

fn program(extension: Extension, instructions: usize) -> Program {
    let mut words = Vec::with_capacity(instructions * 5);
    words.extend_from_slice(&[0, 0, 7, 0, 0]);
    for _ in 1..instructions - 1 {
        words.extend_from_slice(&[10, 0, 0, 0, 0]);
    }
    words.extend_from_slice(&[16, 0, 0, 0, 0]);
    Program {
        extension,
        instructions: words,
        registers: 1,
        constraints: 1,
        layout: AirLayout::default(),
        row_words: 0,
        parameter_words: 0,
    }
}

#[test]
fn actual_specialization_liveness_and_source_emission_fit_fixed_bound() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        for instructions in [2, 64, 65, MAX_INSTRUCTIONS] {
            let program = program(extension, instructions);
            let (source, requests) =
                measure(|| specialize::source(&program, specialize::Backend::OpenCl).unwrap());
            if let Some(source) = source {
                assert!(source.len() <= MAX_SOURCE_BYTES);
                assert!(source.capacity() <= MAX_SOURCE_BYTES);
            } else {
                assert_eq!(instructions, MAX_INSTRUCTIONS);
            }
            assert!(!requests.overflow && requests.calls > 0);
            assert!(
                requests.bytes
                    <= MAX_SOURCE_BYTES
                        + source_liveness_bytes(MAX_INSTRUCTIONS, MAX_REGISTERS).unwrap()
                        + SOURCE_SMALL_FORMATTING
            );
        }
    }
    let mut invalid = program(Extension::Cubic, 2);
    invalid.instructions[0] = u64::MAX;
    let (result, requests) = measure(|| specialize::source(&invalid, specialize::Backend::OpenCl));
    assert!(result.is_err());
    assert!(!requests.overflow && requests.bytes < SOURCE_SMALL_FORMATTING);
}

#[test]
fn outer_kernel_argument_maps_and_builder_fit_fixed_pair_allowance() {
    assert_eq!(size_of::<ocl::core::Mem>(), size_of::<u64>());
    assert_eq!(
        core::mem::align_of::<ocl::core::Mem>(),
        core::mem::align_of::<u64>()
    );
    for reverse in [false, true] {
        let (_, requests) = measure(|| {
            let mut builder = ocl::Kernel::builder();
            builder.name("device_quotient_gather");
            for value in 0..SUPPLIED_ARGUMENTS - 2 {
                builder.arg(value as u64);
            }
            // Match the NTT's two local descriptors. These describe device
            // local memory and do not allocate that many host words.
            builder.arg_local::<u64>(2048).arg_local::<u64>(2048);
            // MemCore and u64 have the same pinned size/alignment. These maps
            // exercise std's actual nodes and clone overlap without a driver.
            let mut memory = BTreeMap::<u32, u64>::new();
            for slot in 0..SUPPLIED_ARGUMENTS {
                let key = if reverse {
                    SUPPLIED_ARGUMENTS - slot - 1
                } else {
                    slot
                };
                memory.insert(key as u32, slot as u64);
            }
            let copied = memory.clone();
            black_box((&builder, &memory, &copied));
        });
        assert!(!requests.overflow && requests.calls > 0);
        assert!(requests.bytes <= PER_BUILDER_KERNEL_PAIR);
    }
}

#[test]
fn outer_checkpoint_command_fits_source_wrapper_allowance() {
    let (_, requests) = measure(|| {
        let mut command = std::process::Command::new("/usr/bin/nvidia-smi");
        command
            .args([
                "--query-compute-apps=pid,gpu_uuid,used_memory",
                "--format=csv,noheader,nounits",
            ])
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        black_box(command);
    });
    assert!(!requests.overflow && requests.calls > 0);
    assert!(requests.bytes <= SAMPLER_COMMAND_BACKING);
    // The helper process and opaque driver storage remain guard obligations.
}
