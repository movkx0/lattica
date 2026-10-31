//! Checked readiness for the existing adjacent-pair tree. These intervals
//! carry no source identity, proof owner, admission or dispatch authority.
use super::{add, interval, mul, ClosureError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pair {
    pub(super) left: (usize, usize),
    pub(super) right: (usize, usize),
    pub(super) parent: (usize, usize),
}

pub(super) fn count(leaves: usize, level: usize) -> Result<usize> {
    if leaves == 0 { return Err(ClosureError::Coverage); }
    let block = 1usize.checked_shl(u32::try_from(level).map_err(|_| ClosureError::Overflow)?)
        .ok_or(ClosureError::Overflow)?;
    Ok(add(leaves / block, usize::from(leaves % block != 0))? / 2)
}

pub(super) fn pair(leaves: usize, level: usize, ordinal: usize, ready_leaves: usize)
    -> Result<Option<Pair>>
{
    if ready_leaves > leaves || ordinal >= count(leaves, level)? {
        return Err(ClosureError::Coverage);
    }
    let first = mul(ordinal, 2)?;
    let left = interval(leaves, level, first)?;
    let right = interval(leaves, level, add(first, 1)?)?;
    let parent = (left.0, add(left.1, right.1)?);
    Ok((add(parent.0, parent.1)? <= ready_leaves).then_some(Pair { left, right, parent }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_odd_tail_waits_for_its_actual_final_leaf() {
        assert_eq!(pair(5, 2, 0, 4), Ok(None));
        assert_eq!(pair(5, 2, 0, 5), Ok(Some(Pair {
            left: (0, 4), right: (4, 1), parent: (0, 5),
        })));
        assert_eq!(pair(9, 3, 0, 8), Ok(None));
        assert_eq!(pair(9, 3, 0, 9), Ok(Some(Pair {
            left: (0, 8), right: (8, 1), parent: (0, 9),
        })));
    }

    #[test]
    fn original_parent_level_counts_preserve_member_table_offsets() {
        assert_eq!((0..4).map(|level| count(5, level).unwrap()).collect::<Vec<_>>(), vec![2, 1, 1, 0]);
        assert_eq!((0..4).map(|level| count(4, level).unwrap()).collect::<Vec<_>>(), vec![2, 1, 0, 0]);
        assert_eq!((0..4).map(|level| count(9, level).unwrap()).collect::<Vec<_>>(), vec![4, 2, 1, 1]);
        // Members retain their original per-level table positions even when
        // higher-level work for an earlier member runs before later leaves.
        assert_eq!((0..4).map(|level|
            count(5, level).unwrap() + count(4, level).unwrap()).collect::<Vec<_>>(),
            vec![4, 2, 1, 0]);
    }

    #[test]
    fn prefix_stream_retains_exactly_the_original_tree_and_final_root() {
        // Test-only logical graph frontier; no proof binding is forged. This
        // omits compiler slots, crypto roots, historical byte maxima, verifier
        // scratch and metadata originals, so it is not a memory admission bound.
        for leaves in 3..=129 {
            let mut next = [0usize; 8];
            let mut live = Vec::new();
            let mut parents = 0;
            let mut peak = 0;
            for prefix in 1..=leaves {
                live.push((prefix - 1, 1));
                peak = peak.max(live.len());
                for level in 0..next.len() {
                    while next[level] < count(leaves, level).unwrap() {
                        let Some(node) = pair(leaves, level, next[level], prefix).unwrap() else { break; };
                        for child in [node.left, node.right] {
                            let index = live.iter().position(|value| *value == child)
                                .expect("original ready child must still be live");
                            live.remove(index);
                        }
                        live.push(node.parent);
                        next[level] += 1;
                        parents += 1;
                    }
                }
            }
            assert_eq!(parents, leaves - 1);
            assert_eq!(live, vec![(0, leaves)]);
            assert!(peak <= leaves.ilog2() as usize + 1);
            for level in 0..next.len() { assert_eq!(next[level], count(leaves, level).unwrap()); }
        }
    }

    #[test]
    fn invalid_prefix_pair_and_shift_are_refused_without_a_partial_pair() {
        assert_eq!(pair(5, 0, 0, 1), Ok(None));
        assert_eq!(pair(5, 0, 2, 5), Err(ClosureError::Coverage));
        assert_eq!(pair(5, 0, 0, 6), Err(ClosureError::Coverage));
        assert_eq!(count(0, 0), Err(ClosureError::Coverage));
        assert_eq!(count(5, usize::BITS as usize), Err(ClosureError::Overflow));
        assert_eq!(pair(5, usize::BITS as usize, 0, 5), Err(ClosureError::Overflow));
    }
}
