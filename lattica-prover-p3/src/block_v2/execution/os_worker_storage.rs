//! Project-owned observation buffers. Child/Command internals, libc, allocator,
//! thread stacks and kernel descriptors/cgroup state are runtime components.

use super::*;
use crate::block_v2::execution::{
    io_storage,
    storage_bound::{add, btree, growing_vector, mul},
};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationStorage {
    pub identity_heap_bytes: usize,
    pub control_bytes: usize,
}

pub fn observation_storage() -> Result<ObservationStorage, Error> {
    let census = [
        mul(2, growing_vector::<u8>(MAX_CONTROL_BYTES)?)?, // stdout/stderr
        mul(5, MAX_CONTROL_BYTES)?, // service strings and identity/error copies
        growing_vector::<u8>(16385)?, // cmdline, including rejection sentinel
        growing_vector::<u8>(8193)?, // cgroup membership
        growing_vector::<u8>(4097)?, // process stat
        btree::<&str, &str>(7)?,
        io_storage::work_bytes()?,
        8192 + 8 * (size_of::<Vec<u8>>() + size_of::<String>()),
    ]
    .into_iter()
    .try_fold(0, add)?;
    let control_bytes = 1 << 20;
    if census > control_bytes {
        return Err("OS observation storage allowance".into());
    }
    Ok(ObservationStorage {
        identity_heap_bytes: MAX_CONTROL_BYTES,
        control_bytes,
    })
}

impl Identity {
    pub(in crate::block_v2::execution) fn storage_heap_bytes(&self) -> Result<usize, Error> {
        if self.group.capacity() > MAX_CONTROL_BYTES {
            return Err("OS identity backing allowance".into());
        }
        Ok(self.group.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn command_binding_stream_matches_bounded_reference_at_every_byte_boundary() {
        let reference = |args: &[u8], expected: &[OsString]| {
            let words: Vec<_> = args.split(|byte| *byte == 0).collect();
            args.len() <= 16384
                && words.len() == expected.len() + 2
                && !words[0].is_empty()
                && words.last().unwrap().is_empty()
                && expected
                    .iter()
                    .zip(&words[1..])
                    .all(|(a, b)| a.as_bytes() == *b)
        };
        let expected = [
            OsString::from("serve-process-gpu"),
            OsString::from(""),
            OsString::from("a path"),
        ];
        let original = b"/image\0serve-process-gpu\0\0a path\0";
        let mut cases = 0;
        for len in 0..=original.len() {
            let prefix = &original[..len];
            assert_eq!(
                check_arguments(prefix, &expected).is_ok(),
                reference(prefix, &expected)
            );
            cases += 1;
        }
        for position in 0..original.len() {
            let mut changed = original.to_vec();
            changed[position] ^= 1;
            assert_eq!(
                check_arguments(&changed, &expected).is_ok(),
                reference(&changed, &expected)
            );
            cases += 1;
        }
        for len in [16383, 16384, 16385] {
            let mut args = vec![b'x'; len];
            args[len - 1] = 0;
            assert_eq!(check_arguments(&args, &[]).is_ok(), reference(&args, &[]));
            cases += 1;
        }
        assert!(check_arguments(b"/image\0\0", &[]).is_err());
        eprintln!("bounded_os_arguments parity_cases={cases} maximum_bytes=16384 split_vector_allocations=0");
    }

    #[test]
    fn identity_census_checks_spare_capacity_without_weakening_process_binding() {
        let name = format!("lattica-v2-multi-persistent-{}.service", "12".repeat(32));
        let mut group = String::with_capacity(MAX_CONTROL_BYTES);
        group.push_str(&format!("/user.slice/{name}"));
        let mut identity = Identity {
            boot: [1; 16],
            invocation: [2; 16],
            pid: 123,
            start_ticks: 1,
            group,
            device: 1,
            inode: 1,
        };
        identity.validate(&name).unwrap();
        assert_eq!(identity.storage_heap_bytes().unwrap(), MAX_CONTROL_BYTES);
        let text = identity.group.clone();
        identity.group = String::with_capacity(MAX_CONTROL_BYTES + 1);
        identity.group.push_str(&text);
        assert!(identity.validate(&name).is_err());
        let plan = observation_storage().unwrap();
        eprintln!(
            "bounded_os_observation identity_heap_bytes={} control_bytes={}",
            plan.identity_heap_bytes, plan.control_bytes
        );
    }
}
