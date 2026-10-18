//! Shared metadata-only bus assignment. No challenge arithmetic or device handles.
use crate::{config::Val, transcript_limits as limits};
use p3_lookup::{Kind, Lookup};

pub(super) fn exact<T>(count: usize) -> Result<Vec<T>, String> {
    let bytes = count
        .checked_mul(core::mem::size_of::<T>())
        .and_then(|n| n.checked_add(core::mem::size_of::<Vec<T>>()))
        .ok_or("lookup metadata storage overflow")?;
    if bytes > limits::HOST_BYTES || (count != 0 && core::mem::size_of::<T>() == 0) {
        return Err("lookup metadata exceeds host allowance".into());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| "lookup metadata allocation failed")?;
    if output.capacity() != count {
        return Err("lookup metadata capacity exceeds admission".into());
    }
    Ok(output)
}

fn lookup_count(lookups: &[&[Lookup<Val>]]) -> Result<usize, String> {
    if lookups.len() > limits::SCALAR_OUTPUTS {
        return Err("lookup host metadata exceeds admission".into());
    }
    lookups.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(row.len())
            .filter(|&n| n <= limits::SCALAR_OUTPUTS)
            .ok_or_else(|| "lookup host metadata exceeds admission".into())
    })
}

/// Host work is restricted to deterministic names, indices and tuple lengths.
pub(super) fn bus_layout(
    lookups: &[&[Lookup<Val>]],
) -> Result<(Vec<Vec<usize>>, usize, usize), String> {
    let count = lookup_count(lookups)?;
    let mut width = 1;
    for contexts in lookups {
        for lookup in *contexts {
            for tuple in &lookup.elements {
                width = width.max(tuple.len());
            }
        }
    }
    if width > u32::MAX as usize {
        return Err("GPU lookup message width exceeds admission".into());
    }
    // Sorted borrowed names give bounded storage and logarithmic lookup without
    // a growable hash table. IDs are still assigned in original encounter order.
    let mut globals = exact::<(&str, usize)>(count)?;
    for lookup in lookups.iter().flat_map(|contexts| contexts.iter()) {
        if let Kind::Global(name) = &lookup.kind {
            globals.push((name.as_str(), usize::MAX));
        }
    }
    globals.sort_unstable_by(|a, b| a.0.cmp(b.0));
    globals.dedup_by(|a, b| a.0 == b.0);
    let mut ids = exact(lookups.len())?;
    let mut next = 0;
    for contexts in lookups {
        let mut instance = exact(contexts.len())?;
        for lookup in *contexts {
            let id = match &lookup.kind {
                Kind::Global(name) => {
                    let index = globals
                        .binary_search_by(|entry| entry.0.cmp(name.as_str()))
                        .map_err(|_| "GPU lookup name missing from admitted table")?;
                    if globals[index].1 == usize::MAX {
                        globals[index].1 = next;
                        next += 1;
                    }
                    globals[index].1
                }
                Kind::Local => {
                    let id = next;
                    next += 1;
                    id
                }
            };
            instance.push(id);
        }
        ids.push(instance);
    }
    Ok((ids, width, next))
}
