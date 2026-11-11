//! Fixed-note Rust wrapper requested-backing census. Pure arithmetic only;
//! the caller must retain a real same-ledger reservation across these owners.
//! This is not a constructor, dispatch token, measured peak or driver bound.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info"
))]

use super::*;

pub(crate) const KERNEL_ARGUMENTS: usize = 16;
pub(crate) const LIVE_BUILDER_KERNEL_PAIRS: usize = 2;
pub(crate) const PER_BUILDER_KERNEL_PAIR: usize = 16 * 1024;
pub(crate) const CONSTRUCTOR_DESCRIPTORS: usize = 64 * 1024;
pub(crate) const SAMPLER_COMMAND_BACKING: usize = 4096;
pub(crate) const SAMPLER_READ_BUFFER: usize = 8193;
const REPLY_BYTES: usize = 64 * 1024;
const METADATA_AND_ERROR_BACKING: usize = 8 * REPLY_BYTES + 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Census {
    pub(crate) joined_source_bytes: usize,
    pub(crate) tuning_source_bytes: usize,
    pub(crate) joined_source_parts: usize,
    pub(crate) source_construction_requests: usize,
    pub(crate) constructor_descriptors: usize,
    pub(crate) metadata_and_error_backing: usize,
    pub(crate) kernel_wrapper_backing: usize,
    pub(crate) sampler_command_backing: usize,
    pub(crate) sampler_read_buffer: usize,
    // Conservatively add constructor and proving storage despite their separate
    // phases. Holding this token for the complete guarded runtime is permitted.
    pub(crate) total_requested_backing: usize,
}

fn source_requests(joined: usize, tuning: usize) -> Option<usize> {
    // Joined source allocation + cloned source + CString terminator growth +
    // final CString clone: 4*(S+1) bounds their cumulative requests, not just
    // simultaneous payload. Geometric tuning String growth is <4*(T+8).
    let joined = joined.checked_add(1)?.checked_mul(4)?;
    let tuning = if tuning == 0 {
        0
    } else {
        tuning.checked_add(8)?.checked_mul(4)?
    };
    joined.checked_add(tuning)
}

/// Requires the sealed fixed note profile: one device/context/program, no
/// source-file inputs/compiler options/source specialization, <=16 supplied
/// arguments, no named arguments/retained kernel cache, and at most two live
/// builder+kernel pairs. Source controlled requested backing only. Opaque
/// runtime/allocator storage remains under the existing trusted reserve.
/// `source_specialization_allowed` comes from the pre-context NoteQuotientPlan
/// retained by the real plan/lease. That owner pins and checks the fresh Session
/// before preparation; a report flag does not establish this contract.
pub(super) fn inventory(
    nvidia: bool,
    tuning: tuning::Tuning,
    source_specialization_allowed: bool,
) -> Option<Census> {
    if tuning != tuning::Tuning::default()
        || source_specialization_allowed
        || std::mem::size_of::<usize>() != 8
        || ocl::core::bounded_info::MAX_REPLY_BYTES != REPLY_BYTES
        || ocl::core::bounded_info::MAX_DEVICES != 64
        || ocl::core::bounded_info::MAX_KERNEL_ARGUMENTS != 128
    {
        return None;
    }
    let source = kernel_bundle::census(
        false,
        if nvidia {
            "#define LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE 1\n"
        } else {
            ""
        },
        tuning.poseidon_schedule,
    )?;
    let tuning_source_bytes = source.tuning_bytes;
    let joined_source_parts = source.parts;
    let joined_source_bytes = source.bytes;
    let source_construction_requests = source_requests(joined_source_bytes, tuning_source_bytes)?;
    let kernel_wrapper_backing = LIVE_BUILDER_KERNEL_PAIRS.checked_mul(PER_BUILDER_KERNEL_PAIR)?;
    let mut total_requested_backing = source_construction_requests;
    for bytes in [
        CONSTRUCTOR_DESCRIPTORS,
        METADATA_AND_ERROR_BACKING,
        kernel_wrapper_backing,
        SAMPLER_COMMAND_BACKING,
        SAMPLER_READ_BUFFER,
    ] {
        total_requested_backing = total_requested_backing.checked_add(bytes)?;
    }
    Some(Census {
        joined_source_bytes,
        tuning_source_bytes,
        joined_source_parts,
        source_construction_requests,
        constructor_descriptors: CONSTRUCTOR_DESCRIPTORS,
        metadata_and_error_backing: METADATA_AND_ERROR_BACKING,
        kernel_wrapper_backing,
        sampler_command_backing: SAMPLER_COMMAND_BACKING,
        sampler_read_buffer: SAMPLER_READ_BUFFER,
        total_requested_backing,
    })
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;
    use std::{collections::BTreeMap, hint::black_box};

    #[test]
    fn note_ocl_wrapper_inventory_is_pure_and_checked() {
        let (census, requests) = measure(|| inventory(true, tuning::Tuning::default(), false));
        assert!(census.is_some());
        assert_eq!(requests.calls, 0);
        assert!(!requests.overflow);
        assert_eq!(source_requests(usize::MAX, 0), None);
        assert_eq!(source_requests(1, usize::MAX), None);
        assert_eq!(inventory(true, tuning::Tuning::default(), true), None);
        for tuning in [
            tuning::Tuning {
                events: true,
                ..Default::default()
            },
            tuning::Tuning {
                commitment: true,
                ..Default::default()
            },
            tuning::Tuning {
                scale: true,
                ..Default::default()
            },
            tuning::Tuning {
                ntt: true,
                ..Default::default()
            },
        ] {
            assert_eq!(inventory(true, tuning, false), None);
        }
        for nvidia in [false, true] {
            let planned = inventory(nvidia, tuning::Tuning::default(), false).unwrap();
            assert_eq!(
                planned.tuning_source_bytes,
                tuning::kernel_source(nvidia).len()
            );
        }
        println!(
            "\nNOTE_OCL_WRAPPER_CENSUS {}",
            serde_json::to_string(&census.unwrap()).unwrap()
        );
    }

    #[test]
    fn note_ocl_program_builder_copy_requests_fit_source_census() {
        let census = inventory(true, tuning::Tuning::default(), false).unwrap();
        // Exercise actual third-party ProgramBuilder source/option handling;
        // no Context, Program or driver call is made. Synthetic bytes have the
        // exact source length, so this is an allocation canary, not a compiler test.
        let (lengths, requests) = measure(|| {
            let text = "x".repeat(census.joined_source_bytes);
            let mut builder = ocl::Program::builder();
            builder.src(text);
            let strings = builder.get_src_strings().unwrap();
            let options = builder.get_compiler_options().unwrap();
            black_box((&strings, &options, &builder));
            (
                strings.iter().map(|s| s.as_bytes().len()).sum::<usize>(),
                options.as_bytes().len(),
            )
        });
        assert_eq!(lengths, (census.joined_source_bytes + 2, 0));
        assert!(!requests.overflow);
        assert!(requests.calls > 0);
        assert!(requests.bytes <= census.source_construction_requests + CONSTRUCTOR_DESCRIPTORS);
        println!("note_program_builder_requests={requests:?}");
    }

    #[test]
    fn note_ocl_argument_maps_and_context_tables_fit_fixed_allowances() {
        assert_eq!(
            std::mem::size_of::<ocl::core::Mem>(),
            std::mem::size_of::<u64>()
        );
        assert_eq!(
            std::mem::align_of::<ocl::core::Mem>(),
            std::mem::align_of::<u64>()
        );
        for reverse in [false, true] {
            let (_, requests) = measure(|| {
                let mut builder = ocl::Kernel::builder();
                builder.name("fixed_note_census_kernel");
                for value in 0..KERNEL_ARGUMENTS {
                    builder.arg(value as u64);
                }
                // u64 has the exact pinned MemCore size/alignment; cloning it
                // avoids invoking clRetainMemObject while exercising std's
                // identical BTree node allocations and clone overlap.
                let mut memory = BTreeMap::<u32, u64>::new();
                for slot in 0..KERNEL_ARGUMENTS {
                    let key = if reverse {
                        KERNEL_ARGUMENTS - slot - 1
                    } else {
                        slot
                    };
                    memory.insert(key as u32, slot as u64);
                }
                let copied = memory.clone();
                black_box((&builder, &memory, &copied));
            });
            assert!(!requests.overflow);
            assert!(requests.calls > 0);
            assert!(requests.bytes <= PER_BUILDER_KERNEL_PAIR);
            println!("note_argument_maps_reverse={reverse} requests={requests:?}");
        }
        let (_, requests) = measure(|| {
            let original = ocl::core::ContextProperties::new().interop_user_sync(true);
            let copy = original.clone();
            let raw = copy.to_raw();
            black_box((&original, &copy, &raw));
        });
        assert!(!requests.overflow);
        assert!(requests.calls > 0);
        assert!(requests.bytes <= CONSTRUCTOR_DESCRIPTORS);
        println!("note_context_properties_requests={requests:?}");
    }

    #[test]
    fn note_sampler_command_construction_fits_pinned_request_allowance() {
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
        assert!(!requests.overflow);
        assert!(requests.calls > 0);
        assert!(requests.bytes <= SAMPLER_COMMAND_BACKING);
        println!("note_sampler_command_requests={requests:?}");
        // This canary does not spawn, measure libc or claim a helper-process bound.
    }
}

pub(crate) fn fixed_inventory(nvidia: bool, source_specialization_allowed: bool) -> Option<Census> {
    inventory(nvidia, Default::default(), source_specialization_allowed)
}
