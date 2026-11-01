//! Immutable program storage after builder tables, compaction overlap and
//! packing scratch retire. This is a checked acceptance ceiling, not a promise
//! about allocator capacity or permission to reduce live construction claims.
use super::{storage::add, CompileError, OperationCounts, Program, MAX_WIRES};
use crate::block_v2::machine::program::{Op, Row, Wire};
use std::{alloc::Layout, mem::size_of, sync::atomic::AtomicUsize};

fn bytes<T>(count: usize) -> Result<usize, CompileError> {
    count
        .checked_mul(size_of::<T>())
        .filter(|&n| n <= isize::MAX as usize)
        .ok_or(CompileError::ResourceAdmission(
            "retained program size overflow",
        ))
}

impl OperationCounts {
    /// Requested packed backing from independently established source bounds.
    /// Includes the Arc/Program header, operations, actual row records and their
    /// indices, wire references, and selection-hint entries/bits. Trace padding
    /// has no retained row records. No witness values or compiler scratch enter
    /// this bound. Callers MUST check Program::retained_host_bytes (which counts
    /// spare capacities) before releasing their full construction allowance.
    pub fn retained_program_host_ceiling(
        self,
        public_values: usize,
        wires: usize,
        hint_words: usize,
    ) -> Result<usize, CompileError> {
        if wires > MAX_WIRES || wires < public_values {
            return Err(CompileError::Shape("retained program wire bound"));
        }
        let rows = self.active_rows(public_values)?;
        let indexed = add(self.scalar, self.cubic)?;
        let operations = add(indexed, self.poseidon)?;
        let header = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<Program>())
            .map_err(|_| CompileError::ResourceAdmission("retained program Arc layout"))?
            .0
            .pad_to_align()
            .size();
        [
            bytes::<Op>(operations)?,
            bytes::<Row>(rows)?,
            bytes::<u32>(indexed)?,
            bytes::<u32>(wires)?,
            bytes::<Wire>(hint_words)?,
        ]
        .into_iter()
        .try_fold(header, add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::machine::program::{ProgramBuilder, Val};
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn retained_ceiling_matches_packed_buffers_and_detects_spare_capacity() {
        let mut builder = ProgramBuilder::new(1).unwrap();
        let public = builder.public(0).unwrap();
        let input = builder.input();
        let constant = builder.constant(Val::from_u64(3));
        let sum = builder.add(input, constant);
        builder.assert_equal(public, sum);
        let entries = (0..8)
            .map(|index| builder.constant(Val::from_u64(index)))
            .collect();
        let bits = [builder.input(), builder.input(), builder.input()];
        builder.select_hint(entries, &bits);
        let mut program = builder.finish(Some(1024)).unwrap();
        let counts = OperationCounts::from_program(&program);
        let hints = super::super::selection_hint_words(&program).unwrap();
        assert_eq!(hints, 11);
        let bound = counts
            .retained_program_host_ceiling(1, program.wire_count(), hints)
            .unwrap();
        assert_eq!(program.retained_host_bytes().unwrap(), bound);
        // The constructor's larger fixed trace height adds no packed row data.
        assert!(program.height() > program.active_rows());
        program.references.reserve_exact(7);
        assert!(program.retained_host_bytes().unwrap() > bound);
    }

    #[test]
    fn retained_ceiling_charges_hint_words_and_checks_overflow() {
        let counts = OperationCounts {
            scalar: 10,
            cubic: 2,
            poseidon: 1,
        };
        let plain = counts.retained_program_host_ceiling(1, 64, 0).unwrap();
        assert_eq!(
            counts.retained_program_host_ceiling(1, 64, 13).unwrap(),
            plain + 13 * size_of::<Wire>()
        );
        assert!(counts.retained_program_host_ceiling(1, 0, 0).is_err());
        assert!(counts
            .retained_program_host_ceiling(1, MAX_WIRES + 1, 0)
            .is_err());
        assert!(counts
            .retained_program_host_ceiling(1, 64, usize::MAX)
            .is_err());
        assert!(OperationCounts {
            scalar: usize::MAX,
            ..counts
        }
        .retained_program_host_ceiling(1, 64, 0)
        .is_err());
    }
}
