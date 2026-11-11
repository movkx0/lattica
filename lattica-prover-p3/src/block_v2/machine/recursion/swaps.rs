//! Fold Merkle swaps and private input providers into consuming Poseidon rows.
//! Recognition uses only the trusted SSA program and exact use counts.
use super::*;

#[derive(Clone, Debug)]
pub(super) struct HashSwap {
    pub instruction: u32,
    pub input: [u32; 8],
    pub bit: u32,
}

pub(super) fn find(swaps: &[HashSwap], instruction: usize) -> Option<&HashSwap> {
    let instruction = u32::try_from(instruction).ok()?;
    swaps
        .binary_search_by_key(&instruction, |swap| swap.instruction)
        .ok()
        .map(|index| &swaps[index])
}

pub(super) fn lower(
    program: &Program,
    writers: &[u32],
    removed: &mut [bool],
) -> Result<Vec<HashSwap>, String> {
    let mut swaps = Vec::new();
    for (index, op) in program.operations.iter().enumerate() {
        let Op::Poseidon { input, .. } = op else {
            continue;
        };
        let Some((raw, bit, selections)) = recognize(program, writers, input) else {
            continue;
        };
        for selection in selections {
            if core::mem::replace(&mut removed[selection as usize], true) {
                return Err("overlapping Merkle swap lowering".into());
            }
        }
        swaps.push(HashSwap {
            instruction: u32::try_from(index).map_err(|_| "Merkle swap instruction index")?,
            input: raw,
            bit,
        });
    }
    Ok(swaps)
}

/// A private Input has no defining constraint beyond being a shared value.
/// Move its unique provider to the first hash input that consumes it. Every
/// other use still queries that same wire, including earlier arithmetic uses.
pub(super) fn input_providers(
    program: &Program,
    writers: &[u32],
    swaps: &[HashSwap],
    references: &[u32],
    removed: &mut [bool],
) -> Result<(Vec<(u32, u8)>, usize, u32), String> {
    let mut owners = Vec::new();
    let mut count = 0;
    let mut bound = 1;
    for (index, op) in program.operations.iter().enumerate() {
        let Op::Poseidon { input, .. } = op else {
            continue;
        };
        let input = find(swaps, index).map_or(input, |swap| &swap.input);
        let mut mask = 0;
        for (slot, &wire) in input.iter().enumerate() {
            let writer = writers[wire as usize];
            // Public values, constrained computations and execution hints keep
            // their original providers. Only truly free private inputs move.
            if matches!(
                program.operations.get(writer as usize),
                Some(Op::Input { .. })
            ) && !removed[writer as usize]
            {
                let remaining = references[wire as usize]
                    .checked_sub(1)
                    .ok_or("hash input provider without a consumer")?;
                removed[writer as usize] = true;
                mask |= 1 << slot;
                count += 1;
                bound = bound.max(remaining);
            }
        }
        if mask != 0 {
            owners.push((
                u32::try_from(index).map_err(|_| "hash provider instruction index")?,
                mask,
            ));
        }
    }
    Ok((owners, count, bound))
}

fn recognize(
    program: &Program,
    writers: &[u32],
    input: &[u32; 8],
) -> Option<([u32; 8], u32, [u32; 8])> {
    let mut selections = [0; 8];
    let mut raw = [0; 8];
    let mut bit = None;
    for i in 0..8 {
        // An externally consumed selected word must keep its original gate.
        // This also excludes duplicate outputs within the same hash input.
        if program.references[input[i] as usize] != 1 {
            return None;
        }
        let writer = writers[input[i] as usize];
        let Op::Select {
            bit: selector,
            a,
            b,
            out,
        } = program.operations.get(writer as usize)?
        else {
            return None;
        };
        if out.0 != input[i] as usize || bit.is_some_and(|value| value != selector.0) {
            return None;
        }
        bit = Some(selector.0);
        if i < 4 {
            raw[i] = u32::try_from(a.0).ok()?;
            raw[i + 4] = u32::try_from(b.0).ok()?;
        } else if a.0 != raw[i] as usize || b.0 != raw[i - 4] as usize {
            return None;
        }
        selections[i] = writer;
    }
    Some((raw, u32::try_from(bit?).ok()?, selections))
}
