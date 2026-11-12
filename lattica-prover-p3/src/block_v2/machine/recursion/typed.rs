//! Immutable lowering of verifier reductions to a transition AIR. The source
//! program remains the independent witness oracle; no proof value drives fusion.
use super::super::program::Wire;
use super::*;

const NONE: u32 = u32::MAX;
const MIN_TERMS: usize = 4;
// Keep each chain's authenticated boundaries while amortizing row commitments
// over eight terms. Short chains still use the same four-term fusion threshold.
pub(super) const TERMS_PER_ROW: usize = 8;
pub(super) const PLANNING_BYTES: usize = 2 << 30;

#[derive(Clone, Debug)]
pub(super) struct DotRow {
    pub weights: [u32; 3],
    pub value: u32,
    pub acc: [u32; 3],
    pub start: bool,
    pub end: bool,
}
#[derive(Clone, Debug)]
pub(super) struct DotGroup {
    pub terms: [u32; TERMS_PER_ROW],
    // The source's final accumulator is carried by the last active group,
    // rather than a separate physical row. NONE denotes a continuing chain.
    pub end: u32,
}
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TypedVerifierStats {
    pub reduction_chains: usize,
    pub reduction_terms: usize,
    pub removed_scalar_operations: usize,
    pub merkle_swap_hashes: usize,
    pub removed_merkle_selections: usize,
    pub relocated_hash_inputs: usize,
    pub hash_input_count_bound: u32,
}
#[derive(Clone, Debug)]
pub struct TypedVerifierPlan {
    pub(super) rows: Arc<[DotRow]>,
    pub(super) groups: Arc<[DotGroup]>,
    pub(super) references: Arc<[u32]>,
    pub(super) removed: Arc<[bool]>,
    pub(super) swaps: Arc<[swaps::HashSwap]>,
    hash_input_owners: Arc<[(u32, u8)]>,
    stats: TypedVerifierStats,
}
#[derive(Clone)]
struct Step {
    weights: [u32; 3],
    value: u32,
    before: [u32; 3],
    after: [u32; 3],
    ops: [u32; 6],
    previous: u32,
    next: u32,
}
impl TypedVerifierPlan {
    pub fn stats(&self) -> &TypedVerifierStats {
        &self.stats
    }
    pub(super) fn hash_input_owners(&self, instruction: u32) -> u8 {
        self.hash_input_owners
            .binary_search_by_key(&instruction, |entry| entry.0)
            .ok()
            .map_or(0, |index| self.hash_input_owners[index].1)
    }
    pub(super) fn backing_bytes(&self) -> usize {
        self.groups.len() * core::mem::size_of::<DotGroup>()
            + self.rows.len() * core::mem::size_of::<DotRow>()
            + self.references.len() * 4
            + self.removed.len()
            + self.swaps.len() * core::mem::size_of::<swaps::HashSwap>()
            + self.hash_input_owners.len() * core::mem::size_of::<(u32, u8)>()
    }
    /// Partition only between complete chains, with at most two tables and
    /// only when doing so reduces total padded rows. No transition crosses a
    /// table boundary, including the cyclic last-to-first trace opening.
    pub(super) fn reduction_parts(&self, max_parts: usize) -> Vec<(usize, usize, usize)> {
        let count = self.groups.len();
        let height = count.max(8).next_power_of_two();
        let mut best = None;
        let mut best_cost = (height, height);
        if max_parts >= 2 {
            for (index, group) in self.groups.iter().enumerate().take(count.saturating_sub(1)) {
                if group.end == NONE {
                    continue;
                }
                let cut = index + 1;
                let prefix = cut.max(8).next_power_of_two();
                let tail = (count - cut).max(8).next_power_of_two();
                let cost = (prefix + tail, prefix.max(tail));
                if cost.0 < height && cost < best_cost {
                    best = Some((cut, prefix, tail));
                    best_cost = cost;
                }
            }
        }
        match best {
            Some((cut, prefix, tail)) => vec![(0, cut, prefix), (cut, count - cut, tail)],
            None => vec![(0, count, height)],
        }
    }
    pub(super) fn compile(program: &Program) -> Result<Self, String> {
        let n = program.operations.len();
        let wires = program.wire_count();
        // Includes writer/link maps, worst-case step/row capacity, growth overlap,
        // removal flags and final reference counts before allocating any of them.
        let needed = wires
            .checked_mul(16)
            .and_then(|v| n.checked_mul(64).and_then(|x| v.checked_add(x)))
            .ok_or("typed verifier planning overflow")?;
        if needed > PLANNING_BYTES {
            return Err("typed verifier planning allowance".into());
        }
        let mut writers = vec![NONE; wires];
        for (i, op) in program.operations.iter().enumerate() {
            for w in op.writes() {
                writers[w.0] = u32::try_from(i).map_err(|_| "typed instruction index")?;
            }
        }
        let mut steps = Vec::<Step>::new();
        let mut by_output = vec![NONE; wires];
        let mut i = 0;
        while i + 2 < n {
            if let Some(mut step) = recognize(program, &writers, i) {
                let previous = by_output[step.before[0] as usize];
                if previous != NONE
                    && steps[previous as usize].after == step.before
                    && step
                        .before
                        .iter()
                        .all(|w| program.references[*w as usize] == 1)
                {
                    step.previous = previous;
                    steps[previous as usize].next = steps.len() as u32;
                }
                by_output[step.after[0] as usize] = steps.len() as u32;
                steps.push(step);
                i += 3;
            } else {
                i += 1;
            }
        }
        drop(by_output);
        let mut rows = Vec::new();
        let mut removed = vec![false; n];
        let mut stats = TypedVerifierStats::default();
        for start in 0..steps.len() {
            if steps[start].previous != NONE {
                continue;
            }
            let mut at = start as u32;
            let mut count = 0;
            while at != NONE {
                count += 1;
                at = steps[at as usize].next;
            }
            if count < MIN_TERMS {
                continue;
            }
            stats.reduction_chains += 1;
            stats.reduction_terms += count;
            at = start as u32;
            while at != NONE {
                let step = &steps[at as usize];
                for &index in &step.ops {
                    if index == NONE {
                        continue;
                    }
                    if core::mem::replace(&mut removed[index as usize], true) {
                        return Err("overlapping typed reduction".into());
                    }
                }
                rows.push(DotRow {
                    weights: step.weights,
                    value: step.value,
                    acc: step.before,
                    start: at == start as u32,
                    end: false,
                });
                if step.next == NONE {
                    rows.push(DotRow {
                        weights: [0; 3],
                        value: 0,
                        acc: step.after,
                        start: false,
                        end: true,
                    });
                }
                at = step.next;
            }
        }
        drop(steps);
        let swaps = swaps::lower(program, &writers, &mut removed)?;
        stats.merkle_swap_hashes = swaps.len();
        stats.removed_merkle_selections = swaps.len() * 8;
        let mut references = vec![0u32; wires];
        let mut read = |w: usize| -> Result<(), String> {
            references[w] = references[w]
                .checked_add(1)
                .ok_or("typed reference overflow")?;
            Ok(())
        };
        for (i, op) in program.operations.iter().enumerate() {
            if !removed[i] {
                let swap = if matches!(op, Op::Poseidon { .. }) {
                    swaps::find(&swaps, i)
                } else {
                    None
                };
                if let Some(swap) = swap {
                    for wire in swap.input {
                        read(wire as usize)?;
                    }
                    read(swap.bit as usize)?;
                } else {
                    for w in op.reads() {
                        read(w.0)?;
                    }
                }
            }
        }
        for row in &rows {
            if row.start {
                for w in row.acc {
                    read(w as usize)?;
                }
            }
            if !row.end {
                for w in row.weights {
                    read(w as usize)?;
                }
                read(row.value as usize)?;
            }
        }
        let (hash_input_owners, relocated, bound) =
            swaps::input_providers(program, &writers, &swaps, &references, &mut removed)?;
        drop(writers);
        stats.relocated_hash_inputs = relocated;
        stats.hash_input_count_bound = bound;
        stats.removed_scalar_operations = removed.iter().filter(|v| **v).count();
        let mut groups = Vec::new();
        let mut index = 0;
        while index < rows.len() {
            let mut group = DotGroup {
                terms: [NONE; TERMS_PER_ROW],
                end: NONE,
            };
            for at in &mut group.terms {
                if index == rows.len() || rows[index].end {
                    break;
                }
                *at = index as u32;
                index += 1;
            }
            if index < rows.len() && rows[index].end {
                group.end = index as u32;
                index += 1;
            }
            groups.push(group);
        }
        Ok(Self {
            groups: Arc::from(groups),
            rows: Arc::from(rows),
            references: Arc::from(references),
            removed: Arc::from(removed),
            swaps: Arc::from(swaps),
            hash_input_owners: Arc::from(hash_input_owners),
            stats,
        })
    }
}

fn recognize(program: &Program, writers: &[u32], first: usize) -> Option<Step> {
    let adds = &program.operations[first..first + 3];
    let Op::Add { a, b, .. } = adds[0] else {
        return None;
    };
    if let Some(step) = recognize_cubic_scale(program, writers, first, a, b) {
        return Some(step);
    }
    // Commutative CSE may reorder both inputs. Try a deterministic bounded set.
    for term in [a, b] {
        let index = writers[term.0];
        if index == NONE || program.references[term.0] != 1 {
            continue;
        }
        let Op::Mul { a: ma, b: mb, .. } = program.operations[index as usize] else {
            continue;
        };
        for shared in [ma, mb] {
            let mut result = Step {
                weights: [0; 3],
                value: shared.0 as u32,
                before: [0; 3],
                after: [0; 3],
                ops: [0; 6],
                previous: NONE,
                next: NONE,
            };
            let mut valid = true;
            for (lane, add) in adds.iter().enumerate() {
                let Op::Add { a, b, out } = *add else {
                    valid = false;
                    break;
                };
                let candidate = [(a, b), (b, a)].into_iter().find_map(|(term, acc)| {
                    let writer = writers[term.0];
                    if writer == NONE || program.references[term.0] != 1 {
                        return None;
                    }
                    let Op::Mul { a, b, .. } = program.operations[writer as usize] else {
                        return None;
                    };
                    let weight: Wire = if a == shared {
                        b
                    } else if b == shared {
                        a
                    } else {
                        return None;
                    };
                    Some((weight, acc, writer))
                });
                let Some((weight, acc, writer)) = candidate else {
                    valid = false;
                    break;
                };
                result.weights[lane] = weight.0 as u32;
                result.before[lane] = acc.0 as u32;
                result.after[lane] = out.0 as u32;
                result.ops[lane] = writer;
                result.ops[3 + lane] = (first + lane) as u32;
            }
            if valid
                && result.ops[..3]
                    .iter()
                    .enumerate()
                    .all(|(i, x)| !result.ops[..i].contains(x))
            {
                return Some(result);
            }
        }
    }
    None
}

/// A base-field operand is established only by immutable Constant operations,
/// never by witness values. All three product outputs must be consumed exactly
/// once by these adds before the whole cubic instruction can be removed.
fn recognize_cubic_scale(
    program: &Program,
    writers: &[u32],
    first: usize,
    left: Wire,
    right: Wire,
) -> Option<Step> {
    let is_zero = |wire: Wire| {
        let index = writers[wire.0];
        index != NONE
            && matches!(&program.operations[index as usize], Op::Constant { value, .. } if *value == Val::ZERO)
    };
    for term in [left, right] {
        let index = writers[term.0];
        if index == NONE {
            continue;
        }
        let Op::CubicMul { a, b, out } = &program.operations[index as usize] else {
            continue;
        };
        if out[0] != term || out.iter().any(|w| program.references[w.0] != 1) {
            continue;
        }
        let (weights, scalar) = if is_zero(b[1]) && is_zero(b[2]) {
            (*a, b[0])
        } else if is_zero(a[1]) && is_zero(a[2]) {
            (*b, a[0])
        } else {
            continue;
        };
        let mut step = Step {
            weights: weights.map(|w| w.0 as u32),
            value: scalar.0 as u32,
            before: [0; 3],
            after: [0; 3],
            ops: [
                index,
                NONE,
                NONE,
                first as u32,
                (first + 1) as u32,
                (first + 2) as u32,
            ],
            previous: NONE,
            next: NONE,
        };
        let mut valid = true;
        for (lane, add) in program.operations[first..first + 3].iter().enumerate() {
            let Op::Add { a, b, out: sum } = *add else {
                valid = false;
                break;
            };
            let accumulator = if a == out[lane] {
                b
            } else if b == out[lane] {
                a
            } else {
                valid = false;
                break;
            };
            step.before[lane] = accumulator.0 as u32;
            step.after[lane] = sum.0 as u32;
        }
        if valid {
            return Some(step);
        }
    }
    None
}
