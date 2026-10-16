//! Validate the actual Linux stacks of every admitted Rayon thread. The parent
//! process still owns main-thread, allocator, cached-thread and driver storage.
use super::super::worker_budget::RAYON_STACK_BYTES;
#[cfg(test)]
use super::super::worker_budget::{RAYON_STACK_AUX_BYTES, RAYON_THREAD_HOST_BYTES};
use super::stack_backing::Stack;
use crate::block_v2::recursive::Error;

pub(super) fn validate_global(threads: usize, reserved: u64) -> Result<(), Error> {
    let stacks = rayon::broadcast(|_| Stack::current().map_err(|error| error.to_string()));
    if stacks.len() != threads {
        return Err("observed Rayon stack count differs from assignment".into());
    }
    let mut total = 0u64;
    for stack in stacks {
        total = total
            .checked_add(stack?.bytes(RAYON_STACK_BYTES)?)
            .ok_or("Rayon stack census overflow")?;
    }
    if total > reserved {
        return Err("Rayon stack census exceeds assigned host RAM".into());
    }
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!("bounded_rayon_stacks threads={threads} stack_bytes={RAYON_STACK_BYTES} observed_backing_bytes={total} reserved_host_bytes={reserved} allocator_main_and_driver_separate=true");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backing_census_bounds_stacks_guards_and_signal_stacks() {
        let boundary = Stack {
            stack: RAYON_STACK_BYTES,
            guard: RAYON_STACK_AUX_BYTES,
            alternate: RAYON_STACK_AUX_BYTES,
            page: RAYON_STACK_AUX_BYTES,
        };
        assert_eq!(
            boundary.bytes(RAYON_STACK_BYTES).unwrap(),
            RAYON_THREAD_HOST_BYTES
        );
        for invalid in [
            Stack {
                stack: 0,
                ..boundary
            },
            Stack {
                stack: RAYON_STACK_BYTES + 1,
                ..boundary
            },
            Stack {
                guard: RAYON_STACK_AUX_BYTES + 1,
                ..boundary
            },
            Stack {
                alternate: RAYON_STACK_AUX_BYTES + 1,
                ..boundary
            },
            Stack {
                page: 0,
                ..boundary
            },
            Stack {
                page: 3,
                ..boundary
            },
            Stack {
                page: 2 * RAYON_STACK_AUX_BYTES,
                ..boundary
            },
        ] {
            assert!(invalid.bytes(RAYON_STACK_BYTES).is_err());
        }
        let rounded = Stack {
            guard: 4096,
            alternate: 4097,
            page: 4096,
            ..boundary
        };
        assert_eq!(
            rounded.bytes(RAYON_STACK_BYTES).unwrap(),
            (RAYON_STACK_BYTES + 4 * 4096) as u64
        );
        assert_eq!(
            Stack {
                alternate: 0,
                ..rounded
            }
            .bytes(RAYON_STACK_BYTES)
            .unwrap(),
            (RAYON_STACK_BYTES + 4096) as u64
        );
    }
}
