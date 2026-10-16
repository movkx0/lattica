//! Allocation-free admission for opening construction and retained output.
//! Includes caller round backing; engine, transcript, borrowed commitment data,
//! allocator overhead and stack are outside this component's ownership.
use super::*;
use crate::block_v2::gpu_hash::device::DeviceOpening;
use core::mem::size_of;

const ERROR: &str = "opening construction exceeds host allowance";

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Shape {
    pub width: usize,
    pub points: usize,
    pub log_height: u32,
}

fn bytes<T>(count: usize) -> Result<usize, &'static str> {
    count
        .checked_mul(size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(ERROR)
}
fn add(total: &mut usize, value: usize) -> Result<(), &'static str> {
    *total = total.checked_add(value).ok_or(ERROR)?;
    Ok(())
}

#[derive(Debug)]
pub(super) struct Plan {
    pub rounds_bytes: usize,
    pub opened_bytes: usize,
    pub prepared_bytes: usize,
    pub fri_bytes: usize,
    pub readback_bytes: usize,
    pub total_bytes: usize,
    pub allowance: usize,
    pub raw_opening_bytes: usize,
    pub raw_fri_bytes: usize,
    pub heights: u32,
    pub height_count: usize,
}

impl Plan {
    pub(super) fn new<F: FriExtension, T>(
        rounds: &Vec<(&T, Vec<Vec<F>>)>,
        shapes: &[Shape],
        resident: bool,
        allowance: usize,
    ) -> Result<Self, &'static str> {
        if rounds.is_empty()
            || rounds.len() > 256
            || shapes.is_empty()
            || shapes.len() > 256
            || !matches!(F::DIMENSION, 2 | 3)
            || size_of::<F>() != F::DIMENSION * 8
        {
            return Err("opening construction geometry");
        }
        let mut rounds_bytes = bytes::<(&T, Vec<Vec<F>>)>(rounds.capacity())?;
        let mut opened_bytes = bytes::<Vec<Vec<Vec<F>>>>(rounds.len())?;
        let mut shape_index = 0;
        let mut heights = 0u32;
        let mut raw_opening_bytes = 0;
        for (_, matrices) in rounds {
            if matrices.is_empty() {
                return Err("opening construction empty round");
            }
            add(&mut rounds_bytes, bytes::<Vec<F>>(matrices.capacity())?)?;
            add(&mut opened_bytes, bytes::<Vec<Vec<F>>>(matrices.len())?)?;
            for points in matrices {
                let shape = shapes
                    .get(shape_index)
                    .ok_or("opening construction shape count")?;
                shape_index += 1;
                if shape.points != points.len()
                    || !(1..=32).contains(&shape.points)
                    || !(1..=4096).contains(&shape.width)
                    || shape.log_height > 25
                {
                    return Err("opening construction matrix geometry");
                }
                add(&mut rounds_bytes, bytes::<F>(points.capacity())?)?;
                add(&mut opened_bytes, bytes::<Vec<F>>(shape.points)?)?;
                let values = bytes::<F>(shape.points.checked_mul(shape.width).ok_or(ERROR)?)?;
                add(&mut opened_bytes, values)?;
                raw_opening_bytes = raw_opening_bytes.max(values);
                heights |= 1 << shape.log_height;
            }
        }
        if shape_index != shapes.len() {
            return Err("opening construction unused shapes");
        }
        let height_count = heights.count_ones() as usize;
        let prepared_bytes = bytes::<(u32, DeviceOpening)>(shapes.len())?;
        let mut raw_fri_bytes = 0;
        let mut fri_bytes = if resident {
            bytes::<DeviceMatrix>(height_count)?
        } else {
            bytes::<Vec<F>>(height_count)?
        };
        if !resident {
            for height in 0..26 {
                if heights & (1 << height) != 0 {
                    let values = bytes::<F>(1 << height)?;
                    add(&mut fri_bytes, values)?;
                    raw_fri_bytes = raw_fri_bytes.max(values);
                }
            }
        }
        // Opening and FRI readbacks occur in different phases. All retained
        // output and prepared descriptors are conservatively charged together.
        let readback_bytes = raw_opening_bytes.max(raw_fri_bytes);
        let mut total_bytes = 0;
        for value in [
            rounds_bytes,
            opened_bytes,
            prepared_bytes,
            fri_bytes,
            readback_bytes,
        ] {
            add(&mut total_bytes, value)?;
        }
        if total_bytes > allowance.min(HOST_ALLOWANCE) {
            return Err(ERROR);
        }
        Ok(Self {
            rounds_bytes,
            opened_bytes,
            prepared_bytes,
            fri_bytes,
            readback_bytes,
            total_bytes,
            allowance,
            raw_opening_bytes,
            raw_fri_bytes,
            heights,
            height_count,
        })
    }

    pub(super) fn report(&self) {
        eprintln!("bounded_opening_construction rounds_bytes={} opened_bytes={} prepared_bytes={} fri_bytes={} readback_bytes={} planned_bytes={} allowance_bytes={} resident_fri={} whole_proof=false",
            self.rounds_bytes, self.opened_bytes, self.prepared_bytes, self.fri_bytes,
            self.readback_bytes, self.total_bytes, self.allowance, self.raw_fri_bytes == 0);
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
