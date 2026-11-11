//! Choose all table splits together: a hash table uses twice the quotient
//! matrices of the other tables. The trusted source fixes every candidate.
use super::*;

pub(super) const MAX_QUOTIENT_MATRICES: usize = super::super::verifier::pcs::MAX_MATRICES;
const MAX_TABLES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TableSpan {
    pub kind: usize,
    pub first_row: usize,
    pub active_rows: usize,
    pub height: usize,
}

struct Candidate {
    tables: Vec<TableSpan>,
    fields_per_lde_row: u64,
    quotient_matrices: usize,
}

fn candidate(
    kind: usize,
    parts: Vec<(usize, usize, usize)>,
    cost: (u64, usize),
) -> Result<Candidate, String> {
    let mut tables = Vec::new();
    for (first, active, height) in parts {
        let limit = match kind {
            0 => air::SCALAR_TABLE_MAX_ROWS,
            2 => air::HASH_TABLE_MAX_ROWS,
            _ => height,
        };
        for offset in (0..height).step_by(limit) {
            let height = (height - offset).min(limit);
            tables.push(TableSpan {
                kind,
                first_row: first + offset,
                active_rows: active.saturating_sub(offset).min(height),
                height,
            });
        }
    }
    let fields_per_lde_row = tables
        .iter()
        .try_fold(0u64, |sum, t| {
            (t.height as u64)
                .checked_mul(cost.0)
                .and_then(|v| sum.checked_add(v))
        })
        .ok_or("recursion layout cost overflow")?;
    let quotient_matrices = tables
        .len()
        .checked_mul(cost.1)
        .ok_or("recursion layout quotient overflow")?;
    Ok(Candidate {
        tables,
        fields_per_lde_row,
        quotient_matrices,
    })
}

fn choose(choices: &[Vec<Candidate>]) -> Option<Vec<TableSpan>> {
    fn visit(
        choices: &[Vec<Candidate>],
        tables: &mut Vec<TableSpan>,
        matrices: usize,
        cost: u64,
        best: &mut Option<(u64, usize, Vec<TableSpan>)>,
    ) {
        if choices.is_empty() {
            if best
                .as_ref()
                .is_none_or(|b| (cost, tables.len()) < (b.0, b.1))
            {
                *best = Some((cost, tables.len(), tables.clone()));
            }
            return;
        }
        for c in &choices[0] {
            if tables.len() + c.tables.len() > MAX_TABLES
                || matrices + c.quotient_matrices > MAX_QUOTIENT_MATRICES
            {
                continue;
            }
            let Some(next_cost) = cost.checked_add(c.fields_per_lde_row) else {
                continue;
            };
            if best.as_ref().is_some_and(|b| next_cost > b.0) {
                continue;
            }
            let len = tables.len();
            tables.extend(c.tables.iter().cloned());
            visit(
                &choices[1..],
                tables,
                matrices + c.quotient_matrices,
                next_cost,
                best,
            );
            tables.truncate(len);
        }
    }
    let mut best = None;
    visit(choices, &mut Vec::new(), 0, 0, &mut best);
    best.map(|b| b.2)
}

pub(super) fn plan(template: &RecursionTemplate) -> Result<Vec<TableSpan>, String> {
    let mut choices = Vec::new();
    for kind in 0..5 {
        let count = template.active_rows(kind);
        if kind == 4 && count == 0 {
            continue;
        }
        let descriptor = air::VerifierAir {
            kind,
            height: 8,
            publics: template.program.publics,
            id: template.id,
            hash_input_count_bound: template.typed.stats().hash_input_count_bound.max(1),
        };
        let cost = geometry::row_cost(&descriptor)?;
        let unsplit = vec![(0, count, count.max(8).next_power_of_two())];
        let split = if kind == 4 {
            template.typed.reduction_parts(2)
        } else {
            partition_rows(count)
        };
        let mut candidates = vec![candidate(kind, unsplit, cost)?];
        let split = candidate(kind, split, cost)?;
        if split.tables != candidates[0].tables {
            candidates.push(split);
        }
        choices.push(candidates);
    }
    choose(&choices)
        .ok_or_else(|| "recursion layout exceeds eight tables or 64 quotient matrices".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_budget_spends_the_last_matrices_on_the_larger_padding_saving() {
        let cost = |kind| {
            geometry::row_cost(&air::VerifierAir {
                kind,
                height: 8,
                publics: 1,
                id: [0; 32],
                hash_input_count_bound: 1,
            })
            .unwrap()
        };
        let mut choices = Vec::new();
        for (kind, count) in [(0, 12288usize), (1, 8), (2, 17408), (3, 1), (4, 8)] {
            choices.push(vec![
                candidate(
                    kind,
                    vec![(0, count, count.max(8).next_power_of_two())],
                    cost(kind),
                )
                .unwrap(),
                candidate(kind, partition_rows(count), cost(kind)).unwrap(),
            ]);
        }
        let selected = choose(&choices).unwrap();
        // Splitting both would use 72 matrices. Keep the arithmetic together
        // and spend the shared budget on the much larger hash padding saving.
        assert_eq!(selected.iter().filter(|t| t.kind == 0).count(), 1);
        assert_eq!(
            selected
                .iter()
                .filter(|t| t.kind == 2)
                .map(|t| t.height)
                .collect::<Vec<_>>(),
            [16384, 1024]
        );
        assert_eq!(
            selected.iter().map(|t| cost(t.kind).1).sum::<usize>(),
            MAX_QUOTIENT_MATRICES
        );
        assert!(selected.len() <= MAX_TABLES);
    }

    #[test]
    fn an_unrepresentable_quotient_round_is_rejected() {
        let hashes = candidate(
            2,
            vec![(
                0,
                4 * air::HASH_TABLE_MAX_ROWS,
                4 * air::HASH_TABLE_MAX_ROWS,
            )],
            (1, 16),
        )
        .unwrap();
        let public = candidate(3, vec![(0, 1, 8)], (1, 8)).unwrap();
        assert!(choose(&[vec![hashes], vec![public]]).is_none());
    }
}
