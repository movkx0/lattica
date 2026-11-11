//! Freeze a cost-minimizing contiguous layout before any proof in the layer.
//! Singleton compiler facts give conservative additive bounds. Every resulting
//! group is still compiled with hard limits and checked before registration.
use super::*;
#[derive(Clone, Copy, Debug)]
pub(super) struct Facts {
    pub rows: usize,
    pub program_bytes: usize,
}
pub(super) fn partition(facts: &[Facts], costs: &[(usize, f64)]) -> Result<Vec<(usize, usize)>> {
    partition_bounded(facts, costs, MAX_RECURSIVE_ROWS, 1)
}
pub(super) fn partition_bounded(
    facts: &[Facts],
    costs: &[(usize, f64)],
    max_rows: usize,
    baseline_width: usize,
) -> Result<Vec<(usize, usize)>> {
    ensure(
        !facts.is_empty() && facts.len() <= 4096 && costs.len() <= 4,
        "graph layout capacity",
    )?;
    ensure(
        costs
            .iter()
            .all(|(w, c)| matches!(w, 1 | 2 | 4 | 8) && c.is_finite() && *c > 0.0)
            && costs.iter().any(|(w, _)| *w == 1),
        "invalid measured graph costs",
    )?;
    let mut best = vec![None; facts.len() + 1];
    best[facts.len()] = Some((0.0, 0));
    for first in (0..facts.len()).rev() {
        for &(width, unit_cost) in costs {
            if first + width > facts.len() {
                continue;
            }
            let Some((rest, _)) = best[first + width] else {
                continue;
            };
            let (mut rows, mut bytes) = (0usize, 0usize);
            for fact in &facts[first..first + width] {
                rows = rows
                    .checked_add(fact.rows)
                    .ok_or("graph row sum overflow")?;
                bytes = bytes
                    .checked_add(fact.program_bytes)
                    .ok_or("graph program sum overflow")?;
            }
            if rows > max_rows || bytes > policy::current().program_bytes {
                continue;
            }
            let cost = rest + unit_cost * width as f64;
            if best[first].is_none_or(|(old, w)| {
                cost < old
                    || (cost == old
                        && ((width == baseline_width && w != baseline_width)
                            || (w != baseline_width && width < w)))
            }) {
                best[first] = Some((cost, width));
            }
        }
    }
    let mut first = 0;
    let mut groups = Vec::new();
    while first < facts.len() {
        let (_, width) = best[first].ok_or("no admitted complete graph partition")?;
        groups.push((first, width));
        first += width;
    }
    Ok(groups)
}
/// Compile/check every contraction before the first proof; a refusal can only
/// split its original contiguous range. No proof is retried after dispatch.
pub(crate) fn admit_groups(
    groups: &[(usize, usize)],
    mut check: impl FnMut(usize, usize) -> Result<()>,
) -> Result<Vec<(usize, usize)>> {
    let mut pending: std::collections::VecDeque<_> = groups.iter().copied().collect();
    let mut accepted = Vec::new();
    while let Some((first, count)) = pending.pop_front() {
        ensure(
            (1..=8).contains(&count) && first.checked_add(count).is_some(),
            "preflight group geometry",
        )?;
        match check(first, count) {
            Ok(()) => accepted.push((first, count)),
            Err(reason) if count > 1 => {
                let left = count.div_ceil(2);
                eprintln!("gpu_aggregation_group_preflight refused_first={first} refused_count={count} reason={reason:?} proofs_started=false");
                pending.push_front((first + left, count - left));
                pending.push_front((first, left));
            }
            Err(reason) => return Err(format!("singleton aggregation preflight: {reason}")),
        }
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    #[test]
    fn preflight_splits_before_proving_preserves_odd_coverage_and_refuses_bad_singletons() {
        let mut attempts = Vec::new();
        let groups = super::admit_groups(&[(0, 8), (8, 3)], |first, count| {
            attempts.push((first, count));
            if count > 2 {
                Err("phase allowance".into())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(
            groups,
            vec![(0, 2), (2, 2), (4, 2), (6, 2), (8, 2), (10, 1)]
        );
        assert_eq!(attempts[0], (0, 8));
        assert!(super::admit_groups(&[(0, 4)], |_, _| Err("invalid singleton".into())).is_err());
        assert!(super::admit_groups(&[(usize::MAX, 2)], |_, _| Ok(())).is_err());
    }

    use super::*;
    #[test]
    fn consuming_layout_keeps_pairs_unless_wider_groups_are_profitable_and_fit() {
        let facts = vec![
            Facts {
                rows: MAX_CONSUMING_ROWS / 4,
                program_bytes: 1 << 24
            };
            9
        ];
        assert_eq!(
            partition_bounded(&facts, &[(1, 1.0), (2, 1.0)], MAX_CONSUMING_ROWS, 2).unwrap(),
            vec![(0, 2), (2, 2), (4, 2), (6, 2), (8, 1)]
        );
        assert_eq!(
            partition_bounded(
                &facts,
                &[(1, 1.0), (2, 1.0), (4, 0.8)],
                MAX_CONSUMING_ROWS,
                2
            )
            .unwrap(),
            vec![(0, 1), (1, 4), (5, 4)]
        );
        assert_eq!(
            partition_bounded(
                &facts,
                &[(1, 1.0), (2, 1.0), (4, 0.8)],
                MAX_RECURSIVE_ROWS,
                2
            )
            .unwrap(),
            vec![(0, 2), (2, 2), (4, 2), (6, 2), (8, 1)]
        );
    }
    #[test]
    fn costs_and_heights_choose_contiguous_groups_without_skipping_large_leaves() {
        let mut facts = vec![
            Facts {
                rows: MAX_RECURSIVE_ROWS / 8,
                program_bytes: 1 << 24
            };
            9
        ];
        facts[0].rows = MAX_RECURSIVE_ROWS;
        assert_eq!(
            partition(&facts, &[(1, 1.0), (4, 0.8), (8, 0.7)]).unwrap(),
            vec![(0, 1), (1, 8)]
        );
        assert_eq!(
            partition(&facts, &[(1, 1.0), (4, 0.7), (8, 0.8)]).unwrap(),
            vec![(0, 1), (1, 4), (5, 4)]
        );
        facts[0].rows += 1;
        assert!(partition(&facts, &[(1, 1.0), (8, 0.7)]).is_err());
        assert!(partition(&facts, &[(1, f64::NAN)]).is_err());
    }
    #[test]
    fn unprofitable_contractions_and_odd_tails_keep_singletons() {
        let facts = vec![
            Facts {
                rows: 8,
                program_bytes: 1024
            };
            7
        ];
        assert_eq!(partition(&facts, &[(1, 1.0), (4, 1.1)]).unwrap().len(), 7);
        let spans = partition(&facts, &[(1, 1.0), (4, 0.8)]).unwrap();
        assert_eq!(spans.iter().map(|s| s.1).sum::<usize>(), 7);
        assert_eq!(spans.len(), 4);
        assert!(spans.windows(2).all(|p| p[0].0 + p[0].1 == p[1].0));
    }
}
