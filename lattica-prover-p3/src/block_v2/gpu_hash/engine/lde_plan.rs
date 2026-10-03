//! Snapshot planning for the experimental resident coset-LDE/commitment pipeline.
//! No kernels or reservations: execution must replan under the engine mutex.
//! Column tiles preserve whole transforms; arbitrary row chunks do not.
//! Host readback is counted until quotient/opening consumers move to the GPU.
use super::{plan_slots, retained_layout, Limits, CONSTANT_BYTES, GIB, QUERY_ELEMENTS};

const MAX_MATRICES: usize = 256;
const MAX_HOST_OUTPUT_BYTES: usize = 48 * GIB;
const SALT_COLUMNS: usize = 4;
const SPONGE_COLUMNS: usize = 8;
const RATE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputShape {
    pub height: usize,
    pub width: usize,
    pub added_bits: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnTile {
    pub matrix: usize,
    pub first_column: usize,
    pub columns: usize,
    pub input_elements: usize,
    pub output_elements: usize,
    /// Position in the unbroken matrix/then-salt sponge stream.
    pub sponge_rate_offset: usize,
}
#[derive(Clone, Debug)]
#[must_use = "a plan is a snapshot, not a reservation or completed GPU operation"]
pub struct LdeCommitPlan {
    inputs: Vec<InputShape>,
    prefixes: Vec<usize>,
    output_height: usize,
    columns_per_tile: usize,
    pub transform_buffer_bytes: usize,
    pub sponge_state_bytes: usize,
    pub hash_workspace_bytes: usize,
    pub retained_tree_bytes: usize,
    pub twiddle_bytes: usize,
    pub query_reserve_bytes: usize,
    pub predicted_managed_peak_bytes: usize,
    pub host_output_bytes: usize,
    /// Only one matrix is reordered at a time; all other admitted outputs stay live.
    pub host_reorder_workspace_bytes: usize,
    pub predicted_host_peak_bytes: usize,
    pub projected_input_upload_bytes: usize,
    pub projected_salt_upload_bytes: usize,
    pub projected_host_readback_bytes: usize,
}
fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "LDE plan addition overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b)
        .ok_or_else(|| "LDE plan multiplication overflow".into())
}
fn bytes(elements: usize) -> Result<usize, String> {
    mul(elements, 8)
}

impl LdeCommitPlan {
    /// Live bytes include constants, staging, retained trees, any query buffer
    /// and the old workspace. Only that workspace may be released/replaced.
    /// Host allowance is a caller budget, not RSS; whole-job host admission and
    /// the external cgroup remain mandatory.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        inputs: &[InputShape],
        cap_height: usize,
        limits: Limits,
        max_alloc: usize,
        slots: usize,
        live_bytes: usize,
        old_workspace_bytes: usize,
        host_output_budget_bytes: usize,
    ) -> Result<Self, String> {
        limits.validate()?;
        if inputs.is_empty() || inputs.len() > MAX_MATRICES {
            return Err("LDE plan matrix count".into());
        }
        if host_output_budget_bytes == 0 || host_output_budget_bytes > MAX_HOST_OUTPUT_BYTES {
            return Err("LDE plan host-output allowance".into());
        }
        let persistent_minimum = add(CONSTANT_BYTES, limits.staging_bytes)?;
        let base_live = live_bytes
            .checked_sub(old_workspace_bytes)
            .ok_or("old workspace exceeds observed live allocation")?;
        if base_live < persistent_minimum || live_bytes > limits.managed_bytes {
            return Err("LDE plan inconsistent live-allocation snapshot".into());
        }
        let mut output_height = 0;
        let mut total_row_width = 0;
        let mut max_width = 0;
        let mut input_upload = 0;
        let mut host_output = 0;
        let mut prefixes = Vec::with_capacity(inputs.len());
        for input in inputs {
            // Current tiled kernel requires at least one butterfly stage.
            if input.height < 2
                || !input.height.is_power_of_two()
                || input.width == 0
                || input.height > u32::MAX as usize
                || input.width > u32::MAX as usize
                || input.added_bits >= 32
            {
                return Err("unsupported LDE input geometry".into());
            }
            let height = input
                .height
                .checked_shl(input.added_bits as u32)
                .ok_or("LDE output-height overflow")?;
            if height > u32::MAX as usize || height < input.height {
                return Err("LDE output exceeds kernel indexing".into());
            }
            if output_height != 0 && output_height != height {
                return Err("resident commitment requires equal output heights".into());
            }
            output_height = height;
            prefixes.push(total_row_width);
            total_row_width = add(total_row_width, add(input.width, SALT_COLUMNS)?)?;
            max_width = max_width.max(input.width);
            input_upload = add(input_upload, bytes(mul(input.height, input.width)?)?)?;
            host_output = add(host_output, bytes(mul(height, input.width)?)?)?;
        }
        if host_output > host_output_budget_bytes {
            return Err("LDE host readback exceeds caller allowance".into());
        }
        let hash = plan_slots(output_height, total_row_width, limits, max_alloc, slots)?;
        let hash_workspace_bytes = hash
            .bytes
            .checked_sub(persistent_minimum)
            .ok_or("hash workspace accounting underflow")?;
        let retained_tree_bytes =
            bytes(retained_layout(output_height, cap_height, max_alloc)?.elements)?;
        let sponge_state_bytes = bytes(mul(output_height, SPONGE_COLUMNS)?)?;
        if sponge_state_bytes > max_alloc {
            return Err("resident sponge state exceeds device allocation limit".into());
        }
        // Inverse and forward root tables, both conservatively sized to log(output).
        let twiddle_bytes = bytes(mul(2, output_height.trailing_zeros() as usize)?)?;
        if twiddle_bytes / 2 > max_alloc {
            return Err("twiddle table exceeds device allocation limit".into());
        }
        let query_reserve_bytes = bytes(QUERY_ELEMENTS)?;
        let mut fixed = base_live;
        for amount in [
            hash_workspace_bytes,
            retained_tree_bytes,
            sponge_state_bytes,
            twiddle_bytes,
            query_reserve_bytes,
        ] {
            fixed = add(fixed, amount)?;
        }
        let remaining = limits
            .managed_bytes
            .checked_sub(fixed)
            .ok_or("resident LDE fixed allocations exceed managed budget")?;
        let per_column_bytes = bytes(output_height)?;
        let maximum = max_width
            .min((remaining / 2) / per_column_bytes)
            .min(max_alloc / per_column_bytes)
            .min((u32::MAX as usize) / output_height);
        if maximum == 0 {
            return Err("no complete transform column fits remaining device budget".into());
        }
        let columns_per_tile = 1usize << maximum.ilog2();
        let mut host_reorder_workspace_bytes = 0;
        for input in inputs {
            if input.width > columns_per_tile {
                host_reorder_workspace_bytes =
                    host_reorder_workspace_bytes.max(bytes(mul(output_height, input.width)?)?);
            }
        }
        let predicted_host_peak_bytes = add(host_output, host_reorder_workspace_bytes)?;
        if predicted_host_peak_bytes > host_output_budget_bytes {
            return Err("LDE host output plus reorder workspace exceeds caller allowance".into());
        }
        let transform_buffer_bytes = mul(per_column_bytes, columns_per_tile)?;
        let predicted_managed_peak_bytes = add(fixed, mul(2, transform_buffer_bytes)?)?;
        if predicted_managed_peak_bytes > limits.managed_bytes {
            return Err("LDE plan exceeds managed budget".into());
        }
        let projected_salt_upload_bytes =
            bytes(mul(mul(output_height, SALT_COLUMNS)?, inputs.len())?)?;
        Ok(Self {
            inputs: inputs.to_vec(),
            prefixes,
            output_height,
            columns_per_tile,
            transform_buffer_bytes,
            sponge_state_bytes,
            hash_workspace_bytes,
            retained_tree_bytes,
            twiddle_bytes,
            query_reserve_bytes,
            predicted_managed_peak_bytes,
            host_output_bytes: host_output,
            host_reorder_workspace_bytes,
            predicted_host_peak_bytes,
            projected_input_upload_bytes: input_upload,
            projected_salt_upload_bytes,
            projected_host_readback_bytes: host_output,
        })
    }
    pub fn output_height(&self) -> usize {
        self.output_height
    }
    pub fn columns_per_tile(&self) -> usize {
        self.columns_per_tile
    }

    pub fn tiles(&self) -> impl Iterator<Item = ColumnTile> + '_ {
        self.inputs
            .iter()
            .enumerate()
            .flat_map(move |(matrix, shape)| {
                (0..shape.width)
                    .step_by(self.columns_per_tile)
                    .map(move |first_column| {
                        let columns = self.columns_per_tile.min(shape.width - first_column);
                        ColumnTile {
                            matrix,
                            first_column,
                            columns,
                            input_elements: shape.height * columns,
                            output_elements: self.output_height * columns,
                            sponge_rate_offset: (self.prefixes[matrix] + first_column) % RATE,
                        }
                    })
            })
    }
    pub fn salt_rate_offset(&self, matrix: usize) -> Option<usize> {
        self.inputs
            .get(matrix)
            .map(|input| (self.prefixes[matrix] + input.width) % RATE)
    }
}
#[cfg(test)]
mod tests {
    use super::super::{MAX_MANAGED_BYTES, MIB};
    use super::*;
    fn plan(
        shapes: &[InputShape],
        max_alloc: usize,
        retained: usize,
        host: usize,
    ) -> Result<LdeCommitPlan, String> {
        let limits = Limits::default();
        let old_workspace = 256 * MIB;
        LdeCommitPlan::new(
            shapes,
            6,
            limits,
            max_alloc,
            1,
            CONSTANT_BYTES + limits.staging_bytes + retained + old_workspace,
            old_workspace,
            host,
        )
    }
    fn wide() -> [InputShape; 2] {
        [
            InputShape {
                height: 1 << 19,
                width: 98,
                added_bits: 4,
            },
            InputShape {
                height: 1 << 19,
                width: 204,
                added_bits: 4,
            },
        ]
    }
    #[test]
    fn wide_geometry_requires_column_tiles_under_existing_budget() {
        let p = plan(&wide(), 4 * GIB, 2 * GIB, 32 * GIB).unwrap();
        assert_eq!(p.output_height(), 1 << 23);
        assert_eq!(p.columns_per_tile(), 32);
        assert_eq!(p.transform_buffer_bytes, 2 * GIB);
        assert!(p.predicted_managed_peak_bytes <= MAX_MANAGED_BYTES);
        assert_eq!(p.host_output_bytes, 302usize * (1 << 23) * 8);
        assert_eq!(p.host_reorder_workspace_bytes, 204usize * (1 << 23) * 8);
        assert_eq!(p.predicted_host_peak_bytes, 506usize * (1 << 23) * 8);
        assert_eq!(p.projected_host_readback_bytes, p.host_output_bytes);
        assert_eq!(p.projected_input_upload_bytes, 302usize * (1 << 19) * 8);
        assert_eq!(p.projected_salt_upload_bytes, 2usize * (1 << 23) * 4 * 8);
        assert!(p.host_output_bytes > MAX_MANAGED_BYTES);
    }
    #[test]
    fn every_column_and_partial_tile_preserve_unbroken_sponge_stream() {
        let shapes = [
            InputShape {
                height: 128,
                width: 35,
                added_bits: 4,
            },
            InputShape {
                height: 128,
                width: 7,
                added_bits: 4,
            },
        ];
        let p = plan(&shapes, 512 * MIB, 0, GIB).unwrap();
        let mut seen = vec![Vec::new(); shapes.len()];
        for tile in p.tiles() {
            assert!(tile.columns <= p.columns_per_tile);
            assert!(tile.output_elements * 8 <= p.transform_buffer_bytes);
            assert_eq!(
                tile.input_elements,
                shapes[tile.matrix].height * tile.columns
            );
            let prefix: usize = shapes[..tile.matrix].iter().map(|s| s.width + 4).sum();
            assert_eq!(tile.sponge_rate_offset, (prefix + tile.first_column) % 4);
            seen[tile.matrix].extend(tile.first_column..tile.first_column + tile.columns);
        }
        for (i, shape) in shapes.iter().enumerate() {
            assert_eq!(seen[i], (0..shape.width).collect::<Vec<_>>());
        }
        assert_eq!(p.salt_rate_offset(0), Some(3));
        assert_eq!(p.salt_rate_offset(1), Some(2));
        assert_eq!(p.salt_rate_offset(2), None);
    }
    #[test]
    fn retained_allocations_reduce_tile_capacity_and_can_reject_admission() {
        let low = plan(&wide(), 4 * GIB, 0, 32 * GIB).unwrap();
        let high = plan(&wide(), 4 * GIB, 5 * GIB, 32 * GIB).unwrap();
        assert!(high.columns_per_tile < low.columns_per_tile);
        assert!(high.predicted_managed_peak_bytes <= MAX_MANAGED_BYTES);
        assert!(plan(&wide(), 4 * GIB, 7 * GIB, 32 * GIB).is_err());
    }
    #[test]
    fn allocation_and_host_bounds_are_independent() {
        assert!(plan(&wide(), 256 * MIB, 0, 32 * GIB).is_err());
        assert!(plan(&wide(), 4 * GIB, 0, GIB).is_err());
        assert!(plan(&wide(), 4 * GIB, 0, 49 * GIB).is_err());
        let p = plan(&wide(), 512 * MIB, 0, 32 * GIB).unwrap();
        assert!(p.transform_buffer_bytes <= 512 * MIB);
        assert!(p.sponge_state_bytes <= 512 * MIB);
    }

    #[test]
    fn readback_workspace_is_admitted_before_execution_and_single_bands_need_none() {
        let p = plan(&wide(), 4 * GIB, 2 * GIB, 32 * GIB).unwrap();
        assert!(plan(&wide(), 4 * GIB, 2 * GIB, p.host_output_bytes).is_err());
        assert!(plan(&wide(), 4 * GIB, 2 * GIB, p.predicted_host_peak_bytes - 1).is_err());
        assert!(plan(&wide(), 4 * GIB, 2 * GIB, p.predicted_host_peak_bytes).is_ok());
        let shape = [InputShape {
            height: 128,
            width: 16,
            added_bits: 4,
        }];
        let bytes = 128 * 16 * 16 * 8;
        let direct = plan(&shape, 4 * GIB, 0, bytes).unwrap();
        assert_eq!(direct.columns_per_tile(), 16);
        assert_eq!(direct.host_reorder_workspace_bytes, 0);
        assert_eq!(direct.host_output_bytes, bytes);
        assert_eq!(direct.predicted_host_peak_bytes, bytes);
    }
    #[test]
    fn malformed_overflow_and_unequal_output_shapes_fail_closed() {
        for shapes in [
            vec![],
            vec![InputShape {
                height: 1,
                width: 1,
                added_bits: 4,
            }],
            vec![InputShape {
                height: 3,
                width: 1,
                added_bits: 4,
            }],
            vec![InputShape {
                height: 2,
                width: 0,
                added_bits: 4,
            }],
            vec![InputShape {
                height: 2,
                width: usize::MAX,
                added_bits: 4,
            }],
            vec![InputShape {
                height: 2,
                width: 1,
                added_bits: usize::MAX,
            }],
            vec![InputShape {
                height: 1 << 31,
                width: 1,
                added_bits: 1,
            }],
            vec![
                InputShape {
                    height: 2,
                    width: 1,
                    added_bits: 0
                };
                257
            ],
            vec![
                InputShape {
                    height: 2,
                    width: 1,
                    added_bits: 0,
                },
                InputShape {
                    height: 4,
                    width: 1,
                    added_bits: 0,
                },
            ],
        ] {
            assert!(plan(&shapes, 4 * GIB, 0, 32 * GIB).is_err());
        }
    }
    #[test]
    fn inconsistent_snapshot_and_invalid_staging_slots_reject() {
        let shapes = [InputShape {
            height: 128,
            width: 1,
            added_bits: 4,
        }];
        let limits = Limits::default();
        assert!(LdeCommitPlan::new(&shapes, 6, limits, 4 * GIB, 1, 1, 2, GIB).is_err());
        assert!(LdeCommitPlan::new(&shapes, 6, limits, 4 * GIB, 1, 0, 0, GIB).is_err());
        let live = CONSTANT_BYTES + limits.staging_bytes;
        assert!(LdeCommitPlan::new(&shapes, 6, limits, 4 * GIB, 3, live, 0, GIB).is_err());
        assert!(LdeCommitPlan::new(&shapes, 6, limits, 4 * GIB, 1, live, 0, 0).is_err());
    }
}
