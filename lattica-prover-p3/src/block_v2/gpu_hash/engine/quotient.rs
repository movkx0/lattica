//! Bounded cubic constraint evaluation on OpenCL. Inputs are staged in row
//! tiles; selectors, alpha powers, constraints and division by Z_H run on GPU.
//! Returning host quotient values is a temporary PCS boundary, not residency.
//! The owned-device adapter reuses these kernels and the memory planner.
use super::*;
use crate::block_v2::gpu_quotient_prover::program::{Program, ProgramShape};
use crate::block_v2::profile::Challenge;
use p3_field::BasedVectorSpace;

const MAX_OUTPUT_BYTES: usize = 1 << 30;
const MAX_TILE_ROWS: usize = 1024;
// Device-owned inputs need no larger host staging buffers. Admit more parallel
// rows when the existing aggregate, tile-byte and allocation limits allow it.
const MAX_DEVICE_TILE_ROWS: usize = 16 * 1024;
// The owned-quotient reservation in block_v2_resources.py includes this
// allowance beside live matrices. Charge parameters/status and row storage
// together; a larger row cap must not borrow another component's allowance.
pub(super) const DEVICE_WORKSPACE_BYTES: usize = 128 << 20;

#[cfg(feature = "gpu")]
pub(super) mod specialized;

/// Small admitted tiles need more independently scheduled workgroups on NVIDIA.
/// Keep other devices on their driver's default and preserve exact row bounds.
#[cfg(feature = "gpu")]
pub(super) fn row_workgroup(device: compute::Device, rows: usize) -> Option<usize> {
    use compute::core::{DeviceInfo, DeviceInfoResult};
    (rows.is_power_of_two()
        && matches!(
            device.info(DeviceInfo::VendorId),
            Ok(DeviceInfoResult::VendorId(0x10de))
        ))
    .then_some(rows.min(32))
}

pub(super) const KERNEL_SRC: &str = concat!(
    "#define QUOTIENT_DEGREE 3\n#define QUOTIENT_ALPHA cubic_quotient_alpha\n#define QUOTIENT_EVALUATE cubic_quotient\n#define QUOTIENT_MUL opening_cubic_mul\n",
    include_str!("quotient_kernels.cl"),
    "#define QUOTIENT_DEGREE 2\n#define QUOTIENT_ALPHA quadratic_quotient_alpha\n#define QUOTIENT_EVALUATE quadratic_quotient\n#define QUOTIENT_MUL opening_quadratic_mul\n",
    include_str!("quotient_kernels.cl"),
);

#[derive(Debug)]
pub(super) struct Plan {
    pub(super) rows: usize,
    pub(super) static_words: [usize; 4],
    pub(super) tile_words: [usize; 3],
    pub(super) peak: usize,
}
impl Plan {
    fn new(
        program: &Program,
        height: usize,
        live: usize,
        limits: Limits,
        max_alloc: usize,
    ) -> Result<Self, String> {
        Self::with_storage(program.shape(), height, live, limits, max_alloc, false)
    }

    /// `live` already includes the prepared program and the full device output.
    pub(super) fn for_device(
        program: &Program,
        height: usize,
        live: usize,
        limits: Limits,
        max_alloc: usize,
    ) -> Result<Self, String> {
        Self::for_shape(program.shape(), height, live, limits, max_alloc)
    }

    /// Reuse the runtime planner with bounded metadata and no instruction allocation.
    pub(super) fn for_shape(
        shape: ProgramShape,
        height: usize,
        live: usize,
        limits: Limits,
        max_alloc: usize,
    ) -> Result<Self, String> {
        Self::with_storage(shape, height, live, limits, max_alloc, true)
    }

    fn with_storage(
        program: ProgramShape,
        height: usize,
        live: usize,
        limits: Limits,
        max_alloc: usize,
        resident: bool,
    ) -> Result<Self, String> {
        let static_words = [
            if resident {
                0
            } else {
                program.instruction_words
            },
            program.parameter_words.max(1),
            program.constraints * program.extension.degree(),
            usize::from(resident), // GPU domain-validation status.
        ];
        if static_words
            .iter()
            .any(|words| words.checked_mul(8).is_none_or(|n| n > max_alloc))
        {
            return Err("GPU quotient program exceeds per-allocation limit".into());
        }
        let static_bytes = static_words.iter().sum::<usize>() * 8;
        let free = limits
            .managed_bytes
            .checked_sub(live)
            .and_then(|n| n.checked_sub(static_bytes))
            .ok_or("GPU quotient program exceeds aggregate budget")?;
        let row_words = program
            .row_words
            .checked_add(program.registers * program.extension.degree())
            .and_then(|n| {
                n.checked_add(if resident {
                    0
                } else {
                    program.extension.degree()
                })
            })
            .ok_or("GPU quotient row size overflow")?;
        let workspace_rows = if resident {
            DEVICE_WORKSPACE_BYTES
                .checked_sub(static_bytes)
                .ok_or("GPU quotient parameters exceed admitted device workspace")?
        } else {
            usize::MAX
        };
        let capacity = (free
            .min(limits.tile_bytes)
            .min(max_alloc)
            .min(workspace_rows)
            / 8
            / row_words)
            .min(if resident {
                MAX_DEVICE_TILE_ROWS
            } else {
                MAX_TILE_ROWS
            })
            .min(height);
        if capacity == 0 {
            return Err("GPU quotient workspace cannot fit one row".into());
        }
        let rows = 1usize << capacity.ilog2();
        let tile_words = [
            rows * program.row_words,
            rows * program.registers * program.extension.degree(),
            if resident {
                0
            } else {
                rows * program.extension.degree()
            },
        ];
        let peak = live + static_bytes + tile_words.iter().sum::<usize>() * 8;
        Ok(Self {
            rows,
            static_words,
            tile_words,
            peak,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::symbolic::AirLayout;

    // A constant and a fold: 112 static bytes, then 64 bytes per row
    // (two input words, three scratch words and three output words).
    pub(super) fn program() -> Program {
        Program {
            extension: device::Extension::Cubic,
            instructions: vec![0, 0, 7, 0, 0, 16, 0, 0, 0, 0],
            registers: 1,
            constraints: 1,
            layout: AirLayout::default(),
            row_words: 2,
            parameter_words: 0,
        }
    }

    #[test]
    fn quotient_plan_respects_live_allocations_and_one_row_boundary() {
        let limits = |managed_bytes| Limits {
            managed_bytes,
            tile_bytes: 4096,
            staging_bytes: 64,
        };
        for budget in [299, 300, 411, 412, 475] {
            assert!(Plan::new(&program(), 1024, 300, limits(budget), 4096).is_err());
        }
        let exact = Plan::new(&program(), 1024, 300, limits(476), 4096).unwrap();
        assert_eq!(exact.rows, 1);
        assert_eq!(exact.peak, 476);
        assert_eq!(
            Plan::new(&program(), 1024, 300, limits(539), 4096)
                .unwrap()
                .rows,
            1
        );
        assert_eq!(
            Plan::new(&program(), 1024, 300, limits(540), 4096)
                .unwrap()
                .rows,
            2
        );
    }

    #[test]
    fn quadratic_plan_accounts_for_two_coefficient_weights_registers_and_output() {
        let mut p = program();
        p.extension = device::Extension::Quadratic;
        let limits = |managed_bytes| Limits {
            managed_bytes,
            tile_bytes: 4096,
            staging_bytes: 64,
        };
        assert!(Plan::new(&p, 1024, 300, limits(451), 4096).is_err());
        let one = Plan::new(&p, 1024, 300, limits(452), 4096).unwrap();
        assert_eq!((one.rows, one.peak), (1, 452));
        assert_eq!(one.static_words, [10, 1, 2, 0]);
        assert_eq!(one.tile_words, [2, 2, 2]);
    }

    #[test]
    fn quotient_plan_enforces_static_allocation_tile_and_height_limits() {
        let limits = Limits {
            managed_bytes: 1 << 20,
            tile_bytes: 1 << 20,
            staging_bytes: 64,
        };
        assert!(Plan::new(&program(), 4096, 0, limits, 79).is_err());
        let allocation_bound = Plan::new(&program(), 4096, 0, limits, 80).unwrap();
        assert_eq!(allocation_bound.rows, 1);
        let tile_bound = Limits {
            tile_bytes: 255,
            ..limits
        };
        assert_eq!(
            Plan::new(&program(), 4096, 0, tile_bound, 1 << 20)
                .unwrap()
                .rows,
            2
        );
        assert_eq!(
            Plan::new(&program(), 8, 0, limits, 1 << 20).unwrap().rows,
            8
        );
        assert_eq!(
            Plan::new(&program(), 4096, 0, limits, 1 << 20)
                .unwrap()
                .rows,
            1024
        );
        assert!(Plan::new(&program(), 0, 0, limits, 1 << 20).is_err());
    }

    #[test]
    fn device_quotient_plan_counts_resident_output_without_reallocating_code_or_readback() {
        let limits = |managed_bytes| Limits {
            managed_bytes,
            tile_bytes: 4096,
            staging_bytes: 64,
        };
        // Cached code and full output are already in the 300 live bytes.
        // Parameters, weights and status add 40; one input/scratch row adds 40.
        for budget in [299, 300, 339, 340, 379] {
            assert!(Plan::for_device(&program(), 1024, 300, limits(budget), 4096).is_err());
        }
        let exact = Plan::for_device(&program(), 1024, 300, limits(380), 4096).unwrap();
        assert_eq!((exact.rows, exact.peak), (1, 380));
        assert_eq!(exact.static_words[0], 0);
        assert_eq!(exact.tile_words[2], 0);
        assert!(Plan::for_device(&program(), 1024, 300, limits(4096), 23).is_err());
    }

    #[test]
    fn larger_device_tiles_keep_aggregate_scratch_allocation_and_height_bounds() {
        for extension in [device::Extension::Quadratic, device::Extension::Cubic] {
            let mut program = program();
            program.extension = extension;
            let live = 300;
            let fixed = (2 + extension.degree()) * 8;
            let per_row = (program.row_words + program.registers * extension.degree()) * 8;
            let limits = Limits {
                managed_bytes: 1 << 20,
                tile_bytes: 1 << 20,
                staging_bytes: 64,
            };
            for (height, budget, max_alloc, expected_rows) in [
                (65536, limits, 1 << 20, 16384),
                (4096, limits, 1 << 20, 4096),
                (
                    65536,
                    Limits {
                        tile_bytes: per_row * 8192 - 1,
                        ..limits
                    },
                    1 << 20,
                    4096,
                ),
                (
                    65536,
                    Limits {
                        managed_bytes: live + fixed + per_row * 4096 - 1,
                        ..limits
                    },
                    1 << 20,
                    2048,
                ),
                (65536, limits, per_row * 2048 - 1, 1024),
            ] {
                let plan = Plan::for_device(&program, height, live, budget, max_alloc).unwrap();
                assert_eq!(plan.rows, expected_rows);
                let scratch_bytes = plan.tile_words.iter().sum::<usize>() * 8;
                assert!(scratch_bytes <= budget.tile_bytes);
                assert!(plan.peak <= budget.managed_bytes);
                assert!(plan
                    .static_words
                    .iter()
                    .chain(&plan.tile_words)
                    .all(|words| words * 8 <= max_alloc));
                assert!(plan.rows.is_power_of_two() && plan.rows <= height);
                assert_eq!(plan.tile_words[2], 0);
            }
            assert!(Plan::for_device(&program, 0, live, limits, 1 << 20).is_err());
            // Plenty of aggregate/driver space does not authorize borrowing
            // from live matrix reservations for a large register file.
            program.registers = 1024;
            let large = Limits {
                managed_bytes: 1 << 30,
                tile_bytes: 128 << 20,
                staging_bytes: 64,
            };
            let plan = Plan::for_device(&program, 65536, live, large, 1 << 30).unwrap();
            let workspace = (plan.static_words.iter().sum::<usize>()
                + plan.tile_words.iter().sum::<usize>())
                * 8;
            assert!(workspace <= 128 << 20);
            assert_eq!(plan.rows, 4096);
        }
    }

    #[test]
    fn wide_device_quotients_use_more_rows_only_with_admitted_tile_space() {
        let mut program = program();
        program.row_words = 800;
        program.registers = 128;
        let limits = Limits {
            managed_bytes: 512 << 20,
            tile_bytes: 128 << 20,
            staging_bytes: 64,
        };
        let wide = Plan::for_device(&program, 1 << 19, 256 << 20, limits, 256 << 20).unwrap();
        assert_eq!(wide.rows, 8192);
        assert!(wide.peak <= (256 + 128) << 20);
        let narrow = Plan::for_device(&program, 1 << 19, 256 << 20,
            Limits { tile_bytes: 64 << 20, ..limits }, 256 << 20).unwrap();
        assert_eq!(narrow.rows, 4096);
        let pressured = Plan::for_device(&program, 1 << 19, (512 - 64) << 20,
            limits, 256 << 20).unwrap();
        assert_eq!(pressured.rows, 4096);
        assert!(pressured.peak <= limits.managed_bytes);
    }
}

pub(crate) fn evaluate(
    program: &Program,
    log_trace: u32,
    log_quotient: u32,
    quotient_shift: u64,
    alpha: [u64; 3],
    parameters: &[u64],
    fill_row: impl Fn(usize, &mut [u64]) -> Result<(), String>,
) -> Result<Vec<Challenge>, String> {
    if program.extension != device::Extension::Cubic {
        return Err("cubic host quotient adapter received another extension".into());
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = (
            program,
            log_trace,
            log_quotient,
            quotient_shift,
            alpha,
            parameters,
            fill_row,
        );
        Err("cubic GPU quotient evaluation is not implemented for Metal".into())
    }
    #[cfg(feature = "gpu")]
    {
        const P: u64 = 0xffff_ffff_0000_0001;
        if log_trace > log_quotient
            || log_quotient > 32
            || quotient_shift == 0
            || quotient_shift >= P
            || alpha.iter().chain(parameters).any(|n| *n >= P)
            || parameters.len() != program.parameter_words
        {
            return Err("invalid GPU quotient domain or parameters".into());
        }
        let height = 1usize
            .checked_shl(log_quotient)
            .ok_or("GPU quotient height overflow")?;
        let output_bytes = height
            .checked_mul(24)
            .filter(|n| *n <= MAX_OUTPUT_BYTES)
            .ok_or("GPU quotient host output exceeds allowance")?;
        let mut slot = ENGINE
            .get()
            .ok_or("GPU quotient engine not initialized")?
            .lock()
            .map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_mut().ok_or("GPU quotient engine shut down")?;
        let cached = engine.lde_workspace.as_ref().map_or(0, |w| w.bytes());
        let live = engine
            .accounting
            .lock()
            .unwrap()
            .live
            .checked_sub(cached)
            .ok_or("GPU quotient cache accounting underflow")?;
        let plan = Plan::new(program, height, live, engine.limits, engine.max_alloc)?;
        let host_bytes = output_bytes + (plan.tile_words[0] + plan.tile_words[2]) * 8;
        let host_limit = env_bytes("LATTICA_V2_HOST_OUTPUT_BYTES", MAX_OUTPUT_BYTES)?;
        if host_bytes > host_limit {
            return Err("GPU quotient staging/output exceeds host allowance".into());
        }
        engine.fence().finish()?;
        engine.lde_workspace = None;
        let alloc = |words| {
            allocation(
                &engine.pq,
                &engine.accounting,
                engine.limits,
                engine.max_alloc,
                words,
                compute::flags::MEM_READ_WRITE,
            )
        };
        let code = alloc(plan.static_words[0])?;
        let params = alloc(plan.static_words[1])?;
        let weights = alloc(plan.static_words[2])?;
        let input = alloc(plan.tile_words[0])?;
        let scratch = alloc(plan.tile_words[1])?;
        let output = alloc(plan.tile_words[2])?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(height)
            .map_err(|_| "GPU quotient host allocation failed")?;
        let mut upload = vec![0u64; plan.tile_words[0]];
        let mut download = vec![0u64; plan.tile_words[2]];
        let empty_parameter = [0u64];
        // The fence outlives all DMA and drops before every temporary above.
        let fence = engine.fence();
        let started = Instant::now();
        code.buffer
            .write(&program.instructions)
            .enq()
            .map_err(|e| e.to_string())?;
        params
            .buffer
            .write(if parameters.is_empty() {
                &empty_parameter[..]
            } else {
                parameters
            })
            .enq()
            .map_err(|e| e.to_string())?;
        let mut event = Event::empty();
        // SAFETY: the compiler bounds instruction/constraint counts; the plan
        // covers all alpha coefficients and the queue fence retains storage.
        unsafe {
            engine
                .pq
                .kernel_builder("cubic_quotient_alpha")
                .arg(&weights.buffer)
                .arg(program.constraints as u32)
                .arg(alpha[0])
                .arg(alpha[1])
                .arg(alpha[2])
                .global_work_size(1usize)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let mut device_ns = engine.timeline.record("quotient_alpha", &event)?;
        let mut uploaded = (program.instructions.len() + plan.static_words[1]) * 8;
        for first in (0..height).step_by(plan.rows) {
            let rows = (height - first).min(plan.rows);
            for (offset, row) in upload[..rows * program.row_words]
                .chunks_exact_mut(program.row_words)
                .enumerate()
            {
                fill_row(first + offset, row)?;
            }
            if upload[..rows * program.row_words].iter().any(|n| *n >= P) {
                return Err("GPU quotient input is not canonical".into());
            }
            input
                .buffer
                .write(&upload[..rows * program.row_words])
                .enq()
                .map_err(|e| e.to_string())?;
            uploaded += rows * program.row_words * 8;
            let mut event = Event::empty();
            let mut kernel = engine.pq.kernel_builder("cubic_quotient");
            if let Some(local) = row_workgroup(engine.pq.device(), rows) {
                kernel.local_work_size(local);
            }
            // SAFETY: compiler validates all row, parameter and register
            // indices; each work item owns one disjoint scratch column.
            unsafe {
                kernel
                    .arg(&code.buffer)
                    .arg(program.instruction_count() as u32)
                    .arg(&input.buffer)
                    .arg(program.row_words as u32)
                    .arg(&params.buffer)
                    .arg(&weights.buffer)
                    .arg(&scratch.buffer)
                    .arg(&output.buffer)
                    .arg(rows as u32)
                    .arg(first as u32)
                    .arg(0u32)
                    .arg(log_trace)
                    .arg(quotient_shift)
                    .arg(super::fri_fold::root(log_quotient))
                    .arg(super::fri_fold::inverse_root(log_trace))
                    .global_work_size(rows)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            device_ns += engine.timeline.record("cubic_quotient", &event)?;
            output
                .buffer
                .read(&mut download[..rows * 3])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            if download[..rows * 3].iter().any(|n| *n >= P) {
                return Err("GPU quotient domain overlaps the trace subgroup".into());
            }
            result.extend(
                download[..rows * 3]
                    .chunks_exact(3)
                    .map(|c| Challenge::from_basis_coefficients_fn(|i| Val::from_u64(c[i]))),
            );
        }
        engine.stats.uploaded_bytes += uploaded as u64;
        engine.stats.downloaded_bytes += output_bytes as u64;
        eprintln!("bounded_gpu_quotient rows={height} instructions={} registers={} constraints={} tile_rows={} managed_peak_plan_bytes={} uploaded_bytes={uploaded} downloaded_bytes={output_bytes} device_ns={device_ns} wall_ns={}",
            program.instruction_count(), program.registers, program.constraints, plan.rows, plan.peak, started.elapsed().as_nanos());
        Ok(result)
    }
}
