//! Bounded packing of already normalized interactions. The pinned upstream
//! container takes the resulting arrays by ownership, without AIR replay.
use super::{
    normalize::{Map, Storage},
    BaseExpr, Val, MAX_NODES,
};
use crate::block_v2::machine::verifier::CompileError;
use p3_air::symbolic::SymbolicExpr;
use p3_lookup::{Kind, Lookup, Lookups};
use std::mem::size_of;

pub(super) const RETAINED_BYTES: usize = 64 << 20;
const _: () = assert!(
    super::recording::HOST_BYTES + super::normalize::HOST_BYTES + RETAINED_BYTES
        <= super::HOST_BYTES as usize
);

/// Count the returned backing capacities and each reachable child Arc once.
/// This includes storage inherited from normalization, not just new packing
/// arrays. Temporary census storage uses the packing quota and is then freed.
fn retained(
    lookups: &Vec<Lookup<Val>>,
    storage: &Storage,
    limit: usize,
) -> Result<usize, CompileError> {
    let mut bytes = 0usize;
    let mut add = |count: usize, size: usize| -> Result<(), CompileError> {
        bytes = count
            .checked_mul(size)
            .and_then(|n| bytes.checked_add(n))
            .filter(|&n| n <= limit)
            .ok_or(CompileError::Shape("symbolic lookup retained allowance"))?;
        Ok(())
    };
    add(lookups.capacity(), size_of::<Lookup<Val>>())?;
    let mut stack = Vec::new();
    for lookup in lookups {
        if let Kind::Global(name) = &lookup.kind {
            add(name.capacity(), 1)?;
        }
        add(lookup.elements.capacity(), size_of::<Vec<BaseExpr>>())?;
        add(lookup.multiplicities.capacity(), size_of::<BaseExpr>())?;
        for fields in &lookup.elements {
            add(fields.capacity(), size_of::<BaseExpr>())?;
            for expr in fields {
                storage.push(&mut stack, (false, expr))?;
            }
        }
        for expr in &lookup.multiplicities {
            storage.push(&mut stack, (false, expr))?;
        }
    }
    let mut seen = Map::new(storage);
    while let Some((arc, expr)) = stack.pop() {
        if arc {
            let pointer = expr as *const BaseExpr as usize;
            if seen.get(pointer).is_some() {
                continue;
            }
            seen.insert(pointer, ())?;
            add(1, size_of::<BaseExpr>() + 4 * size_of::<usize>())?;
        }
        match expr {
            SymbolicExpr::Leaf(_) => {}
            SymbolicExpr::Neg { x, .. } => storage.push(&mut stack, (true, x.as_ref()))?,
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                storage.push(&mut stack, (true, x.as_ref()))?;
                storage.push(&mut stack, (true, y.as_ref()))?;
            }
        }
    }
    Ok(bytes)
}

/// Same LogUp fraction-pin degree as the pinned reference, without its
/// temporary degree vector. Checked integer metadata is not field arithmetic.
pub(super) fn degree(lookup: &Lookup<Val>) -> Result<usize, CompileError> {
    if lookup.elements.len() != lookup.multiplicities.len() {
        return Err(CompileError::Shape("symbolic lookup tuple/count lengths"));
    }
    let error = || CompileError::Shape("symbolic lookup degree overflow");
    let tuple_degree = |fields: &Vec<super::BaseExpr>| {
        fields
            .iter()
            .map(|e| e.degree_multiple())
            .max()
            .unwrap_or(0)
    };
    let sum = lookup.elements.iter().try_fold(0usize, |sum, fields| {
        sum.checked_add(tuple_degree(fields)).ok_or_else(error)
    })?;
    let mut result = sum.checked_add(1).ok_or_else(error)?;
    for (fields, count) in lookup.elements.iter().zip(&lookup.multiplicities) {
        result = result.max(
            count
                .degree_multiple()
                .checked_add(sum - tuple_degree(fields))
                .ok_or_else(error)?,
        );
    }
    Ok(result)
}

fn validate(unpacked: &[Lookup<Val>]) -> Result<(), CompileError> {
    let mut roots = 0usize;
    if unpacked.len() > MAX_NODES {
        return Err(CompileError::Shape("symbolic lookup count"));
    }
    for lookup in unpacked {
        if lookup.elements.len() != lookup.multiplicities.len()
            || (matches!(lookup.kind, Kind::Global(_)) && lookup.elements.len() != 1)
            || (matches!(lookup.kind, Kind::Local) && lookup.count_weight != 0)
        {
            return Err(CompileError::Shape(
                "symbolic lookup packing requires unpacked interactions",
            ));
        }
        for fields in &lookup.elements {
            roots = roots
                .checked_add(fields.len())
                .and_then(|n| n.checked_add(1))
                .filter(|&n| n <= MAX_NODES)
                .ok_or(CompileError::Shape("symbolic lookup roots"))?;
        }
        degree(lookup)?;
    }
    Ok(())
}

fn with_storage(
    unpacked: Vec<Lookup<Val>>,
    max_degree: usize,
    storage: &Storage,
) -> Result<(Lookups<Val>, usize), CompileError> {
    with_storage_and_retained(unpacked, max_degree, storage, RETAINED_BYTES)
}

fn with_storage_and_retained(
    unpacked: Vec<Lookup<Val>>,
    max_degree: usize,
    storage: &Storage,
    retained_limit: usize,
) -> Result<(Lookups<Val>, usize), CompileError> {
    validate(&unpacked)?;
    let mut packed = storage.capacity(unpacked.len())?;
    let mut buses: Vec<(String, Vec<Lookup<Val>>)> = Vec::new();
    // Preserve the pinned local-first and first-appearance bus order.
    for lookup in unpacked {
        match &lookup.kind {
            Kind::Local => packed.push(lookup),
            Kind::Global(name) => match buses.iter_mut().find(|(bus, _)| bus == name) {
                Some((_, members)) => storage.push(members, lookup)?,
                None => {
                    let name = storage.string(name)?;
                    let members = storage.single(lookup)?;
                    storage.push(&mut buses, (name, members))?;
                }
            },
        }
    }
    for (_, members) in buses {
        let mut current: Option<Lookup<Val>> = None;
        for member in members {
            match current.take() {
                None => current = Some(member),
                Some(mut cur) => {
                    let pivot = cur.elements.len();
                    for fields in &member.elements {
                        let fields = storage.vector(fields.len(), |i| Ok(fields[i].clone()))?;
                        storage.push(&mut cur.elements, fields)?;
                    }
                    for count in &member.multiplicities {
                        storage.push(&mut cur.multiplicities, count.clone())?;
                    }
                    if degree(&cur)? <= max_degree {
                        cur.count_weight = cur.count_weight.saturating_add(member.count_weight);
                        current = Some(cur);
                    } else {
                        cur.elements.truncate(pivot);
                        cur.multiplicities.truncate(pivot);
                        packed.push(cur);
                        current = Some(member);
                    }
                }
            }
        }
        if let Some(cur) = current {
            packed.push(cur);
        }
    }
    // At most one output per input; the exact pre-admitted array cannot grow.
    for (column, lookup) in packed.iter_mut().enumerate() {
        lookup.column = column;
    }
    let bytes = retained(&packed, storage, retained_limit)?;
    Ok((
        Lookups::try_from_ordered(packed).map_err(CompileError::Shape)?,
        bytes,
    ))
}

pub(super) fn pack(
    unpacked: Vec<Lookup<Val>>,
    max_degree: usize,
    report: bool,
) -> Result<Lookups<Val>, CompileError> {
    let count = unpacked.len();
    let storage = Storage::lookup(report);
    let (packed, bytes) = with_storage(unpacked, max_degree, &storage)?;
    if report {
        eprintln!("bounded_symbolic_lookup_layout unpacked={} packed={} max_degree={} retained_bytes={} retained_limit_bytes={}", count, packed.len(), max_degree, bytes, RETAINED_BYTES);
    }
    Ok(packed)
}

pub(super) fn pack_limited(
    unpacked: Vec<Lookup<Val>>,
    max_degree: usize,
    packing_limit: usize,
    retained_limit: usize,
) -> Result<(Lookups<Val>, usize), CompileError> {
    if packing_limit > super::normalize::HOST_BYTES || retained_limit > RETAINED_BYTES {
        return Err(CompileError::Shape(
            "verifier lookup allowance exceeds ceiling",
        ));
    }
    let storage = Storage::lookup_limited(packing_limit, false);
    with_storage_and_retained(unpacked, max_degree, &storage, retained_limit)
}

#[cfg(test)]
pub(super) mod tests;
