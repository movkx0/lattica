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
            if rows > 1 << 20 || bytes > 2 << 30 {
                continue;
            }
            let cost = rest + unit_cost * width as f64;
            if best[first].is_none_or(|(old, w)| cost < old || (cost == old && width < w)) {
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn costs_and_heights_choose_contiguous_groups_without_skipping_large_leaves() {
        let mut facts = vec![
            Facts {
                rows: 1 << 17,
                program_bytes: 1 << 24
            };
            9
        ];
        facts[0].rows = 1 << 20;
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
