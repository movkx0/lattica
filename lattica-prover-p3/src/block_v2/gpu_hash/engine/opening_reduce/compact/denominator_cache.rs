//! Reuse immutable denominator slices within one opening call.
//!
//! A group retains the existing row/point/coefficient layout, so the existing
//! reduction kernel can consume its full prefix in one dispatch. No field
//! arithmetic, transcript ordering, or cross-proof cache is introduced.

use super::OpeningMatrix;

#[derive(Clone, Debug)]
pub(super) struct Group {
    /// An input with the largest required prefix for this ordered set of slices.
    pub source: usize,
    pub rows: usize,
    pub words: usize,
    pub saved_bytes: usize,
}

#[derive(Debug)]
pub(super) struct Plan {
    pub groups: Vec<Group>,
    pub input_groups: Vec<Option<usize>>,
    pub bytes: usize,
    pub saved_bytes: usize,
    pub skipped_groups: usize,
}

fn same_denominators(left: &OpeningMatrix<'_>, right: &OpeningMatrix<'_>) -> bool {
    left.terms.len() == right.terms.len()
        && left.terms.iter().zip(&right.terms).all(|(left, right)| {
            left.inverse_denominators.len() == right.inverse_denominators.len()
                && left.inverse_denominators.as_ptr() == right.inverse_denominators.as_ptr()
        })
}

impl Plan {
    /// Called after the opening shape validator. Cache allocations fit within
    /// the space left by the original workspace and the device allocation cap.
    pub fn new(
        inputs: &[OpeningMatrix<'_>],
        allowance: usize,
        max_allocation: usize,
    ) -> Result<Self, String> {
        let mut groups = Vec::<Group>::new();
        let mut input_groups = Vec::with_capacity(inputs.len());
        let mut repeated_bytes = Vec::<usize>::new();
        for (input_index, input) in inputs.iter().enumerate() {
            let words = input
                .height
                .checked_mul(input.terms.len())
                .and_then(|words| words.checked_mul(3))
                .ok_or("opening denominator cache dimensions overflow")?;
            let bytes = words
                .checked_mul(8)
                .ok_or("opening denominator cache byte size overflow")?;
            let index = groups
                .iter()
                .position(|group| same_denominators(input, &inputs[group.source]));
            let index = match index {
                Some(index) => {
                    repeated_bytes[index] = repeated_bytes[index]
                        .checked_add(bytes)
                        .ok_or("opening denominator transfer count overflow")?;
                    if input.height > groups[index].rows {
                        groups[index].source = input_index;
                        groups[index].rows = input.height;
                        groups[index].words = words;
                    }
                    index
                }
                None => {
                    groups.push(Group {
                        source: input_index,
                        rows: input.height,
                        words,
                        saved_bytes: 0,
                    });
                    repeated_bytes.push(bytes);
                    groups.len() - 1
                }
            };
            input_groups.push(index);
        }
        for (group, repeated) in groups.iter_mut().zip(repeated_bytes) {
            group.saved_bytes = repeated - group.words * 8;
        }

        // A bounded, deterministic policy: retain groups that save the most
        // transfer bytes first, with encounter order breaking equal scores.
        let mut order: Vec<_> = (0..groups.len()).collect();
        order.sort_by_key(|&index| (std::cmp::Reverse(groups[index].saved_bytes), index));
        let mut result = Self {
            groups: Vec::new(),
            input_groups: vec![None; inputs.len()],
            bytes: 0,
            saved_bytes: 0,
            skipped_groups: 0,
        };
        for index in order {
            let group = &groups[index];
            if group.saved_bytes == 0 {
                continue;
            }
            let bytes = group.words * 8;
            if bytes > max_allocation || bytes > allowance - result.bytes {
                result.skipped_groups += 1;
                continue;
            }
            result.bytes += bytes;
            result.saved_bytes = result
                .saved_bytes
                .checked_add(group.saved_bytes)
                .ok_or("opening denominator cache savings overflow")?;
            for (input_index, &original_group) in input_groups.iter().enumerate() {
                if original_group == index {
                    result.input_groups[input_index] = Some(result.groups.len());
                }
            }
            result.groups.push(group.clone());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::gpu_hash::OpeningTerm;
    use crate::block_v2::profile::Challenge;
    use p3_field::PrimeCharacteristicRing;

    fn input(height: usize, denominators: &[Challenge]) -> OpeningMatrix<'_> {
        OpeningMatrix {
            values: &[],
            width: 1,
            height,
            terms: vec![OpeningTerm {
                inverse_denominators: denominators,
                alpha_offset: Challenge::ONE,
                opened: Challenge::ZERO,
            }],
        }
    }

    #[test]
    fn shared_prefixes_use_one_upload_of_the_largest_prefix() {
        let denominators = vec![Challenge::ONE; 128];
        let inputs = [
            input(32, &denominators),
            input(128, &denominators),
            input(64, &denominators),
        ];
        let plan = Plan::new(&inputs, 128 * 24, 128 * 24).unwrap();
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].source, 1);
        assert_eq!(plan.groups[0].rows, 128);
        assert_eq!(plan.bytes, 128 * 24);
        assert_eq!(plan.saved_bytes, (32 + 64) * 24);
        assert_eq!(plan.input_groups, [Some(0), Some(0), Some(0)]);
    }

    #[test]
    fn cache_groups_preserve_point_order_and_slice_identity() {
        let first = vec![Challenge::ONE; 128];
        let second = first.clone();
        let mut inputs = [input(128, &first), input(128, &first), input(128, &second)];
        inputs[0]
            .terms
            .push(input(128, &second).terms.pop().unwrap());
        inputs[1]
            .terms
            .insert(0, input(128, &second).terms.pop().unwrap());
        let plan = Plan::new(&inputs, usize::MAX, usize::MAX).unwrap();
        assert!(plan.groups.is_empty());
        assert_eq!(plan.saved_bytes, 0);
    }

    #[test]
    fn cache_respects_both_aggregate_and_per_allocation_limits() {
        let denominators = vec![Challenge::ONE; 128];
        let inputs = [input(128, &denominators), input(128, &denominators)];
        for (allowance, max_allocation) in [(0, usize::MAX), (3071, usize::MAX), (usize::MAX, 3071)]
        {
            let plan = Plan::new(&inputs, allowance, max_allocation).unwrap();
            assert!(plan.groups.is_empty());
            assert_eq!(plan.input_groups, [None, None]);
            assert_eq!(plan.skipped_groups, 1);
        }
    }

    #[test]
    fn limited_capacity_retains_the_group_with_more_reuse() {
        let first = vec![Challenge::ONE; 64];
        let second = first.clone();
        let inputs = [
            input(64, &first),
            input(64, &first),
            input(64, &second),
            input(64, &second),
            input(64, &second),
        ];
        let plan = Plan::new(&inputs, 64 * 24, usize::MAX).unwrap();
        assert_eq!(plan.input_groups, [None, None, Some(0), Some(0), Some(0)]);
        assert_eq!(plan.saved_bytes, 2 * 64 * 24);
        assert_eq!(plan.skipped_groups, 1);
    }

    #[test]
    fn cache_rejects_dimension_overflow() {
        let denominators = [Challenge::ONE];
        assert!(Plan::new(&[input(usize::MAX, &denominators)], usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn cache_metadata_fits_the_host_admission_reservation() {
        // Conservative bound for both temporary plans and allocation handles,
        // even though at most half of 256 inputs can form reused groups.
        let per_input = 2 * std::mem::size_of::<Group>()
            + 3 * std::mem::size_of::<usize>()
            + std::mem::size_of::<Option<usize>>()
            + std::mem::size_of::<super::super::Allocation>();
        assert!(256 * per_input + 1024 <= 64 << 10);
    }
}
