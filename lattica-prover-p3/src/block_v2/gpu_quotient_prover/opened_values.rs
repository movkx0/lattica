//! Move PCS openings into the upstream native proof containers. This admits
//! incoming vector capacities plus all new descriptors before assembling them.
//! It is a late host-output boundary, not a whole-proof memory reservation:
//! FRI proofs, commitments, driver storage and allocator overhead are separate.

use core::mem::{size_of, take};
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_commit::{OpenedValues as PcsValues, OpenedValuesForMatrix, OpenedValuesForRound};
use p3_uni_stark::OpenedValues;

#[derive(Clone, Copy, Debug)]
pub(super) struct Instance {
    pub main_next: bool,
    pub quotient_start: usize,
    pub quotient_end: usize,
    pub preprocessed: Option<(usize, bool)>,
    pub permutation: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Rounds {
    pub random: bool,
    pub preprocessed: bool,
    pub permutation: bool,
}

impl Rounds {
    fn main(self) -> usize {
        usize::from(self.random)
    }
    fn quotient(self) -> usize {
        self.main() + 1
    }
    fn preprocessed(self) -> usize {
        self.main() + 2
    }
    fn permutation(self) -> usize {
        self.preprocessed() + usize::from(self.preprocessed)
    }
    fn count(self) -> usize {
        self.permutation() + usize::from(self.permutation)
    }
}

#[derive(Debug)]
struct Storage {
    input_bytes: usize,
    descriptor_bytes: usize,
    total_bytes: usize,
    preprocessed_matrices: usize,
}

fn bytes<T>(count: usize) -> Result<usize, String> {
    count
        .checked_mul(size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or_else(|| "opened-value capacity overflow".into())
}

fn add(total: &mut usize, bytes: usize) -> Result<(), String> {
    *total = total
        .checked_add(bytes)
        .ok_or("opened-value storage overflow")?;
    Ok(())
}

fn exact_vec<T>(count: usize) -> Result<Vec<T>, String> {
    bytes::<T>(count)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| "opened-value descriptor allocation failed")?;
    if values.capacity() != count {
        return Err("opened-value descriptor capacity differs from admission".into());
    }
    Ok(values)
}

impl Storage {
    fn plan<T>(
        values: &PcsValues<T>,
        count: usize,
        rounds: Rounds,
        limit: usize,
    ) -> Result<Self, String> {
        if count == 0
            || size_of::<T>() == 0
            || limit > crate::block_v2::resident_pcs::HOST_OUTPUT_BUDGET
            || values.len() != rounds.count()
            || values[rounds.main()].len() != count
            || (rounds.random && values[0].len() != count)
        {
            return Err("opened-value round geometry or allowance".into());
        }
        // Account for spare capacity at every level, including descriptors
        // that remain live while their elements are moved out by IntoIter.
        let mut input_bytes = bytes::<OpenedValuesForRound<T>>(values.capacity())?;
        for round in values {
            add(
                &mut input_bytes,
                bytes::<OpenedValuesForMatrix<T>>(round.capacity())?,
            )?;
            for matrix in round {
                add(&mut input_bytes, bytes::<Vec<T>>(matrix.capacity())?)?;
                for point in matrix {
                    add(&mut input_bytes, bytes::<T>(point.capacity())?)?;
                }
            }
        }
        let preprocessed_matrices = if rounds.preprocessed {
            values[rounds.preprocessed()].len()
        } else {
            0
        };
        // Layout metadata, the one-to-one preprocessing check, native instance
        // descriptors and quotient-row descriptors conservatively coexist.
        let mut descriptor_bytes = bytes::<Instance>(count)?;
        add(&mut descriptor_bytes, bytes::<bool>(preprocessed_matrices)?)?;
        add(
            &mut descriptor_bytes,
            bytes::<OpenedValuesWithLookups<T>>(count)?,
        )?;
        add(
            &mut descriptor_bytes,
            bytes::<Vec<T>>(values[rounds.quotient()].len())?,
        )?;
        let total_bytes = input_bytes
            .checked_add(descriptor_bytes)
            .filter(|n| *n <= limit)
            .ok_or("opened-value handoff exceeds host-output allowance")?;
        Ok(Self {
            input_bytes,
            descriptor_bytes,
            total_bytes,
            preprocessed_matrices,
        })
    }
}

fn points<T>(matrix: &[Vec<T>], next: bool) -> Result<(), String> {
    if matrix.len() != 1 + usize::from(next) || (next && matrix[0].len() != matrix[1].len()) {
        return Err("opened-value point geometry".into());
    }
    Ok(())
}

/// The iterator supplies canonical per-instance quotient ranges and the
/// preprocessing matrix index (which may differ from the instance order).
/// No field Clone bound: successful assembly transfers each field allocation
/// exactly once. Rejection drops all owned inputs through normal Rust cleanup.
pub(super) fn assemble<T>(
    values: PcsValues<T>,
    instances: impl ExactSizeIterator<Item = Instance>,
    rounds: Rounds,
    limit: usize,
) -> Result<Vec<OpenedValuesWithLookups<T>>, String> {
    let count = instances.len();
    let storage = Storage::plan(&values, count, rounds, limit)?;
    let mut layout = exact_vec(count)?;
    for instance in instances {
        if layout.len() == count {
            return Err("opened-value instance count changed".into());
        }
        layout.push(instance);
    }
    if layout.len() != count {
        return Err("opened-value instance count changed".into());
    }
    let mut seen_preprocessed = exact_vec(storage.preprocessed_matrices)?;
    seen_preprocessed.resize(storage.preprocessed_matrices, false);
    let mut quotient_end = 0;
    let mut permutation_count = 0;
    for (i, instance) in layout.iter().enumerate() {
        points(&values[rounds.main()][i], instance.main_next)?;
        if rounds.random {
            points(&values[0][i], false)?;
        }
        if instance.quotient_start != quotient_end
            || instance.quotient_end <= instance.quotient_start
            || instance.quotient_end > values[rounds.quotient()].len()
        {
            return Err("opened-value quotient ranges must partition the round".into());
        }
        for matrix in &values[rounds.quotient()][instance.quotient_start..instance.quotient_end] {
            points(matrix, false)?;
        }
        quotient_end = instance.quotient_end;
        if let Some((index, next)) = instance.preprocessed {
            let seen = seen_preprocessed
                .get_mut(index)
                .ok_or("opened-value preprocessing index")?;
            if *seen {
                return Err("opened-value preprocessing matrix is shared".into());
            }
            *seen = true;
            points(&values[rounds.preprocessed()][index], next)?;
        }
        if instance.permutation {
            if !rounds.permutation {
                return Err("opened-value permutation round missing".into());
            }
            let matrix = values[rounds.permutation()]
                .get(permutation_count)
                .ok_or("opened-value permutation matrix missing")?;
            points(matrix, true)?;
            permutation_count += 1;
        }
    }
    if quotient_end != values[rounds.quotient()].len()
        || (rounds.preprocessed
            && (seen_preprocessed.is_empty() || seen_preprocessed.contains(&false)))
        || (rounds.permutation
            && (permutation_count == 0 || permutation_count != values[rounds.permutation()].len()))
    {
        return Err("opened-value matrices were not completely assigned".into());
    }

    let mut per_instance = exact_vec(count)?;
    let mut owned_rounds = values.into_iter();
    let mut random = if rounds.random {
        owned_rounds.next().unwrap()
    } else {
        Vec::new()
    }
    .into_iter();
    let mut main = owned_rounds.next().unwrap().into_iter();
    let mut quotient = owned_rounds.next().unwrap().into_iter();
    let mut preprocessed = if rounds.preprocessed {
        owned_rounds.next().unwrap()
    } else {
        Vec::new()
    };
    let mut permutation = if rounds.permutation {
        owned_rounds.next().unwrap()
    } else {
        Vec::new()
    }
    .into_iter();
    for instance in layout {
        let mut trace = main.next().unwrap().into_iter();
        let trace_local = trace.next().unwrap();
        let trace_next = trace.next();
        let mut quotient_chunks = exact_vec(instance.quotient_end - instance.quotient_start)?;
        for _ in instance.quotient_start..instance.quotient_end {
            quotient_chunks.push(quotient.next().unwrap().into_iter().next().unwrap());
        }
        let (preprocessed_local, preprocessed_next) =
            if let Some((index, _)) = instance.preprocessed {
                let mut rows = take(&mut preprocessed[index]).into_iter();
                (rows.next(), rows.next())
            } else {
                (None, None)
            };
        let (permutation_local, permutation_next) = if instance.permutation {
            let mut rows = permutation.next().unwrap().into_iter();
            (rows.next().unwrap(), rows.next().unwrap())
        } else {
            (Vec::new(), Vec::new())
        };
        per_instance.push(OpenedValuesWithLookups {
            base_opened_values: OpenedValues {
                trace_local,
                trace_next,
                preprocessed_local,
                preprocessed_next,
                quotient_chunks,
                random: random.next().map(|rows| rows.into_iter().next().unwrap()),
            },
            permutation_local,
            permutation_next,
        });
    }
    eprintln!("bounded_opening_handoff instances={} input_capacity_bytes={} descriptor_bytes={} planned_bytes={} limit_bytes={}",
        count, storage.input_bytes, storage.descriptor_bytes, storage.total_bytes, limit);
    Ok(per_instance)
}

#[cfg(test)]
mod tests;
