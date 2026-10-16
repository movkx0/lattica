//! Retained opening output, hiding split and adapter descriptors coexist with
//! FRI proof construction. This partition excludes borrowed prover data, engine/
//! transcript storage and allocator overhead; it is not whole-proof ownership.
use super::OpenedValues;
use crate::block_v2::gpu_hash::device::DeviceMatrix;
use core::mem::size_of;

const ERROR: &str = "retained opening storage exceeds host allowance";

struct Backing {
    bytes: usize,
    limit: usize,
}
impl Backing {
    fn new(limit: usize) -> Self {
        Self { bytes: 0, limit }
    }
    fn capacity<T>(&mut self, capacity: usize) -> Result<(), &'static str> {
        self.bytes = capacity
            .checked_mul(size_of::<T>())
            .and_then(|n| self.bytes.checked_add(n))
            .filter(|n| *n <= self.limit)
            .ok_or(ERROR)?;
        Ok(())
    }
    fn vector<T>(&mut self, values: &Vec<T>) -> Result<(), &'static str> {
        self.capacity::<T>(values.capacity())
    }
}

fn hiding_bytes<F>(
    values: &OpenedValues<F>,
    random_columns: usize,
    unhidden_round: Option<usize>,
    limit: usize,
) -> Result<usize, &'static str> {
    let mut output = Backing::new(limit);
    output.capacity::<Vec<Vec<Vec<F>>>>(values.len())?;
    for (round, matrices) in values.iter().enumerate() {
        let count = if unhidden_round == Some(round) {
            0
        } else {
            random_columns
        };
        output.capacity::<Vec<Vec<F>>>(matrices.len())?;
        for points in matrices {
            output.capacity::<Vec<F>>(points.len())?;
            for point in points {
                if point.len() < count {
                    return Err("hiding opening width");
                }
                output.capacity::<F>(count)?;
            }
        }
    }
    Ok(output.bytes)
}

#[derive(Debug)]
pub(super) struct Partition {
    pub opened_bytes: usize,
    pub rounds_bytes: usize,
    pub bridge_bytes: usize,
    pub hiding_bytes: usize,
    pub retained_bytes: usize,
    pub fri_allowance: usize,
    pub operation_allowance: usize,
}

impl Partition {
    pub(super) fn new<F, T>(
        values: &OpenedValues<F>,
        rounds: &Vec<(&T, Vec<Vec<F>>)>,
        device_input_capacity: usize,
        random_columns: usize,
        unhidden_round: Option<usize>,
        allowance: usize,
    ) -> Result<Self, &'static str> {
        if rounds.len() > 256 || values.len() != rounds.len() {
            return Err("opening storage round geometry");
        }
        let mut backing = Backing::new(allowance);
        backing.vector(values)?;
        for matrices in values {
            backing.vector(matrices)?;
            for points in matrices {
                backing.vector(points)?;
                for point in points {
                    backing.vector(point)?;
                }
            }
        }
        let opened_bytes = backing.bytes;
        backing.vector(rounds)?;
        for (_, matrices) in rounds {
            backing.vector(matrices)?;
            for points in matrices {
                backing.vector(points)?;
            }
        }
        let rounds_bytes = backing.bytes - opened_bytes;
        backing.capacity::<DeviceMatrix>(device_input_capacity)?;
        // The field adapter makes one exact pointer array for the FRI backend.
        backing.capacity::<&T>(rounds.len())?;
        let bridge_bytes = backing.bytes - opened_bytes - rounds_bytes;
        let hiding_bytes = hiding_bytes(
            values,
            random_columns,
            unhidden_round,
            allowance - backing.bytes,
        )?;
        backing.capacity::<u8>(hiding_bytes)?;
        let retained_bytes = backing.bytes;
        let fri_allowance = allowance
            .checked_sub(retained_bytes)
            .filter(|n| *n > 0)
            .ok_or(ERROR)?;
        Ok(Self {
            opened_bytes,
            rounds_bytes,
            bridge_bytes,
            hiding_bytes,
            retained_bytes,
            fri_allowance,
            operation_allowance: allowance,
        })
    }

    pub(super) fn report(&self) {
        eprintln!("bounded_opening_host_partition opened_bytes={} rounds_bytes={} bridge_bytes={} hiding_bytes={} retained_bytes={} fri_allowance_bytes={} operation_allowance_bytes={} whole_proof=false",
            self.opened_bytes, self.rounds_bytes, self.bridge_bytes, self.hiding_bytes,
            self.retained_bytes, self.fri_allowance, self.operation_allowance);
    }
}

fn exact<T>(count: usize) -> Result<Vec<T>, &'static str> {
    count
        .checked_mul(size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(ERROR)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| "hiding output allocation failed")?;
    if size_of::<T>() != 0 && values.capacity() != count {
        return Err("hiding output capacity exceeds plan");
    }
    Ok(values)
}

/// Recheck the exact split before mutating any value or allocating output. Drain
/// preserves the original value backing, which remains in the retained charge.
pub(super) fn split_hiding<F: Copy>(
    values: &mut OpenedValues<F>,
    random_columns: usize,
    unhidden_round: Option<usize>,
    allowance: usize,
) -> Result<OpenedValues<F>, &'static str> {
    hiding_bytes(values, random_columns, unhidden_round, allowance)?;
    let mut random = exact(values.len())?;
    for (index, matrices) in values.iter_mut().enumerate() {
        let count = if unhidden_round == Some(index) {
            0
        } else {
            random_columns
        };
        let mut round = exact(matrices.len())?;
        for points in matrices {
            let mut matrix = exact(points.len())?;
            for point in points {
                let split = point.len() - count;
                let mut tail = exact(count)?;
                tail.extend(point.drain(split..));
                matrix.push(tail);
            }
            round.push(matrix);
        }
        random.push(round);
    }
    Ok(random)
}

#[cfg(all(test, feature = "stream"))]
mod tests;
