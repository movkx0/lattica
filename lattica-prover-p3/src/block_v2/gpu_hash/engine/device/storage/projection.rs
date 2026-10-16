//! Quotient projection admission, including a possible later domain expansion.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectionShape {
    pub projected: MatrixSpec,
    pub output: MatrixSpec,
    pub alias: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectionStorage {
    pub peak_bytes: usize,
    pub max_allocation_bytes: usize,
    pub copies: bool,
    pub expands: bool,
}

impl ProjectionShape {
    pub(crate) fn new(
        input: MatrixSpec,
        log_rows: u32,
        shift: u64,
        columns: usize,
        extension: Extension,
    ) -> Result<Self, String> {
        let width = columns
            .checked_mul(extension.degree())
            .ok_or("quotient input width overflow")?;
        if input.extension != Extension::Base
            || input.order != RowOrder::BitReversed
            || input.shift != shift
            || width == 0
            || width > input.columns
            || log_rows > 31
        {
            return Err("device quotient projection has unsupported geometry".into());
        }
        let projected = MatrixSpec::new(
            input.log_rows.min(log_rows),
            columns,
            extension,
            RowOrder::BitReversed,
            shift,
        )?;
        let output = MatrixSpec::new(log_rows, columns, extension, RowOrder::BitReversed, shift)?;
        Ok(Self {
            projected,
            output,
            alias: projected == input && output == projected,
        })
    }

    pub(crate) fn storage_plan(
        self,
        live: usize,
        cache: usize,
        limits: super::super::super::Limits,
        max_allocation: usize,
    ) -> Result<ProjectionStorage, String> {
        let without_cache = live
            .checked_sub(cache)
            .ok_or("projection cache exceeds live storage")?;
        if live > limits.managed_bytes {
            return Err("projection exceeds managed capacity".into());
        }
        if self.alias {
            return Ok(ProjectionStorage {
                peak_bytes: live,
                max_allocation_bytes: 0,
                copies: false,
                expands: false,
            });
        }
        let copy = MemoryPlan::new(
            &[self.projected],
            live,
            limits.managed_bytes,
            max_allocation,
        )?;
        let mut peak_bytes = copy.peak_bytes;
        let expands = self.projected.log_rows != self.output.log_rows;
        let mut largest = self.projected.bytes();
        if expands {
            // Runtime copies with the old cache live, then lde() drains and
            // releases that cache before allocating its output and scratch.
            let transform_live = without_cache
                .checked_add(self.projected.bytes())
                .ok_or("projection storage overflow")?;
            let transform = super::super::transform::storage_plan(
                self.projected,
                self.output.log_rows,
                transform_live,
                limits,
                max_allocation,
            )?;
            peak_bytes = peak_bytes.max(transform.peak_bytes);
            largest = largest
                .max(self.output.bytes())
                .max(self.output.log_rows.max(2) as usize * 8);
        }
        Ok(ProjectionStorage {
            peak_bytes,
            max_allocation_bytes: largest,
            copies: true,
            expands,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_admits_alias_copy_and_later_expansion_before_work() {
        let input = MatrixSpec::new(3, 12, Extension::Base, RowOrder::BitReversed, 7).unwrap();
        let limits = super::super::super::super::Limits {
            managed_bytes: 1 << 20,
            tile_bytes: 4096,
            staging_bytes: 0,
        };
        let alias = ProjectionShape::new(input, 3, 7, 12, Extension::Base).unwrap();
        let plan = alias
            .storage_plan(input.bytes(), 0, limits, 1 << 20)
            .unwrap();
        assert_eq!(plan.peak_bytes, input.bytes());
        assert!(!plan.copies && !plan.expands);
        for extension in [Extension::Base, Extension::Quadratic, Extension::Cubic] {
            for log_rows in [2, 3, 5] {
                let shape = ProjectionShape::new(input, log_rows, 7, 3, extension).unwrap();
                let live = input.bytes() + 256;
                let p = shape.storage_plan(live, 256, limits, 1 << 20).unwrap();
                assert!(p.copies);
                assert_eq!(p.expands, log_rows > 3);
                assert!(shape
                    .storage_plan(
                        live,
                        256,
                        super::super::super::super::Limits {
                            managed_bytes: p.peak_bytes - 1,
                            ..limits
                        },
                        1 << 20
                    )
                    .is_err());
                assert!(shape
                    .storage_plan(live, 256, limits, p.max_allocation_bytes - 1)
                    .is_err());
                assert!(shape
                    .storage_plan(
                        live,
                        256,
                        super::super::super::super::Limits {
                            managed_bytes: p.peak_bytes,
                            ..limits
                        },
                        p.max_allocation_bytes
                    )
                    .is_ok());
            }
        }
        assert!(alias.storage_plan(1, 2, limits, 1 << 20).is_err());
        assert!(ProjectionShape::new(input, 3, 11, 3, Extension::Base).is_err());
        assert!(ProjectionShape::new(input, 3, 7, 5, Extension::Cubic).is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires selected OpenCL GPU and bounded zero-swap service"]
    fn gpu_projection_rejects_expansion_before_copy_and_preserves_packed_columns() {
        let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
        crate::block_v2::gpu_hash::initialize_from_env().unwrap();
        let session = DeviceSession::new().unwrap();
        let spec = MatrixSpec::new(3, 12, Extension::Base, RowOrder::BitReversed, 7).unwrap();
        let words: Vec<_> = (0..spec.words() as u64).collect();
        let input = session.upload(spec, &words).unwrap();
        let before = session.stats();
        let allocations = crate::block_v2::gpu_hash::report("projection_rejection_before")
            .unwrap()
            .allocations;
        assert!(session
            .quotient_input(&input, 31, 7, 3, Extension::Cubic)
            .is_err());
        assert_eq!(session.stats(), before);
        assert_eq!(
            crate::block_v2::gpu_hash::report("projection_rejection_after")
                .unwrap()
                .allocations,
            allocations
        );
        let alias = session
            .quotient_input(&input, 3, 7, 12, Extension::Base)
            .unwrap();
        assert_eq!(session.stats(), before);
        assert_eq!(
            crate::block_v2::gpu_hash::report("projection_alias")
                .unwrap()
                .allocations,
            allocations
        );
        drop(alias);
        for extension in [Extension::Base, Extension::Quadratic, Extension::Cubic] {
            let projected = session.quotient_input(&input, 2, 7, 3, extension).unwrap();
            let expected: Vec<_> = words
                .chunks_exact(12)
                .take(4)
                .flat_map(|row| row[..3 * extension.degree()].iter().copied())
                .collect();
            assert_eq!(session.read(&projected, 4096).unwrap(), expected);
        }
        eprintln!("gpu_projection_expansion_rejected_before_copy=true packed_columns_match=true");
    }
}
