//! Read-only Linux thread stack observations shared by caller/Rayon admission.
use super::super::worker_budget::RAYON_STACK_AUX_BYTES;
use super::super::worker_budget::{CALLER_STACK_BYTES, CALLER_STACK_HOST_BYTES};
use crate::block_v2::recursive::Error;
use std::io::Read;

const MAPS_BYTES: usize = 64 << 10;

fn mapping_bytes(maps: &[u8], address: usize) -> Result<usize, Error> {
    let mut found = None;
    for line in maps
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let range = std::str::from_utf8(fields.next().ok_or("missing mapping range")?)?;
        let (start, end) = range.split_once('-').ok_or("invalid mapping range")?;
        let start = usize::from_str_radix(start, 16)?;
        let end = usize::from_str_radix(end, 16)?;
        if start >= end {
            return Err("invalid mapping extent".into());
        }
        let permissions = fields.next().ok_or("missing mapping permissions")?;
        if start <= address && address < end {
            if found.is_some() || permissions.len() != 4 || !permissions.starts_with(b"rw") {
                return Err("ambiguous or unwritable caller stack mapping".into());
            }
            found = Some(end - start);
        }
    }
    found.ok_or_else(|| "caller stack mapping not observed".into())
}

fn read_mapping(reader: impl Read, address: usize) -> Result<usize, Error> {
    let mut maps = Vec::new();
    maps.try_reserve_exact(MAPS_BYTES + 1)?;
    reader
        .take((MAPS_BYTES + 1) as u64)
        .read_to_end(&mut maps)?;
    if maps.len() > MAPS_BYTES {
        return Err("caller mappings exceed bounded startup observation".into());
    }
    mapping_bytes(&maps, address)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Stack {
    pub stack: usize,
    pub guard: usize,
    pub alternate: usize,
    pub page: usize,
}

impl Stack {
    pub(super) fn bytes(self, stack_limit: usize) -> Result<u64, Error> {
        if self.stack == 0
            || self.stack > stack_limit
            || self.guard > RAYON_STACK_AUX_BYTES
            || self.alternate > RAYON_STACK_AUX_BYTES
            || !self.page.is_power_of_two()
            || self.page > RAYON_STACK_AUX_BYTES
        {
            return Err("actual thread stack exceeds admitted backing".into());
        }
        let alternate = if self.alternate == 0 {
            0
        } else {
            self.alternate.div_ceil(self.page) * self.page + self.page
        };
        let bytes = self
            .stack
            .checked_add(self.guard)
            .and_then(|bytes| bytes.checked_add(alternate))
            .ok_or("thread stack backing overflow")?;
        Ok(u64::try_from(bytes)?)
    }

    pub(super) fn current() -> Result<Self, Error> {
        let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
        let mut address = std::ptr::null_mut();
        let mut stack = 0;
        let mut guard = 0;
        let mut alternate = std::mem::MaybeUninit::<libc::stack_t>::uninit();
        // SAFETY: each getter receives valid out-pointers. pthread_getattr_np
        // initializes attributes on success; destroy it on every later path.
        let (stack_rc, guard_rc, destroy_rc, alternate_rc, page) = unsafe {
            let rc = libc::pthread_getattr_np(libc::pthread_self(), attributes.as_mut_ptr());
            if rc != 0 {
                return Err(std::io::Error::from_raw_os_error(rc).into());
            }
            let stack_rc =
                libc::pthread_attr_getstack(attributes.as_ptr(), &mut address, &mut stack);
            let guard_rc = libc::pthread_attr_getguardsize(attributes.as_ptr(), &mut guard);
            let destroy_rc = libc::pthread_attr_destroy(attributes.as_mut_ptr());
            let alternate_rc = libc::sigaltstack(std::ptr::null(), alternate.as_mut_ptr());
            let page = libc::sysconf(libc::_SC_PAGESIZE);
            (stack_rc, guard_rc, destroy_rc, alternate_rc, page)
        };
        for rc in [stack_rc, guard_rc, destroy_rc] {
            if rc != 0 {
                return Err(std::io::Error::from_raw_os_error(rc).into());
            }
        }
        if alternate_rc != 0 || page <= 0 || address.is_null() {
            return Err("could not observe actual thread stack backing".into());
        }
        // SAFETY: sigaltstack succeeded and initialized the output structure.
        let alternate = unsafe { alternate.assume_init() };
        let value = Self {
            stack,
            guard,
            alternate: if alternate.ss_flags & libc::SS_DISABLE != 0 {
                0
            } else {
                if alternate.ss_sp.is_null() || alternate.ss_size == 0 {
                    return Err("invalid thread alternate stack".into());
                }
                alternate.ss_size
            },
            page: usize::try_from(page)?,
        };
        Ok(value)
    }
}

fn validate_main_limit(main: bool, soft_limit: u64) -> Result<(), Error> {
    if main && (soft_limit == 0 || soft_limit > CALLER_STACK_BYTES as u64) {
        return Err("main caller requires a bounded RLIMIT_STACK within 8 MiB".into());
    }
    Ok(())
}

fn charge_mapping(mut stack: Stack, main: bool, mapped: usize) -> Result<Stack, Error> {
    if main {
        if mapped > CALLER_STACK_BYTES {
            return Err("retained caller stack mapping exceeds reservation".into());
        }
        stack.stack = stack.stack.max(mapped);
    }
    // Fixed pthread stacks can share a coalesced VMA with unrelated owners.
    // pthread_getattr_np reports their actual fixed extent; the rest of that
    // VMA remains caller/allocator/driver storage, not this stack reservation.
    Ok(stack)
}

fn caller_bytes(stack: Stack, main: bool, soft_limit: u64) -> Result<u64, Error> {
    validate_main_limit(main, soft_limit)?;
    stack.bytes(CALLER_STACK_BYTES)?;
    let stack = if main {
        // The main mapping can grow after pthread_getattr_np. Charge its
        // enforced soft limit, not just the currently reported mapping.
        Stack {
            stack: stack.stack.max(usize::try_from(soft_limit)?),
            ..stack
        }
    } else {
        stack
    };
    let bytes = stack.bytes(CALLER_STACK_BYTES)?;
    if bytes > CALLER_STACK_HOST_BYTES {
        return Err("caller stack exceeds persistent host reservation".into());
    }
    Ok(bytes)
}

/// A startup check. The admitted caller must retain this stack and must not
/// increase its stack/alternate-stack bounds while the blocking worker runs.
pub(super) fn validate_caller(report: bool) -> Result<(), Error> {
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes a valid out-pointer; getpid/gettid only read
    // process identity. No process limit, signal stack or pthread state changes.
    let (rc, pid, tid) = unsafe {
        (
            libc::getrlimit(libc::RLIMIT_STACK, limits.as_mut_ptr()),
            libc::getpid(),
            libc::syscall(libc::SYS_gettid),
        )
    };
    if rc != 0 || pid <= 0 || tid <= 0 {
        return Err("could not observe caller stack limit/identity".into());
    }
    // SAFETY: getrlimit succeeded and initialized the structure.
    let limits = unsafe { limits.assume_init() };
    let main = i64::from(pid) == tid as i64;
    let soft = u64::try_from(limits.rlim_cur)?;
    validate_main_limit(main, soft)?;
    let stack = Stack::current()?;
    // A lowered rlimit does not unmap already-grown stack pages. Charge the
    // whole current mapping as well as pthread backing and future growth.
    let mut marker = 0u8;
    let address = std::hint::black_box(&mut marker) as *mut u8 as usize;
    let mapped = read_mapping(std::fs::File::open("/proc/self/maps")?, address)?;
    let pthread_bytes = stack.stack;
    let stack = charge_mapping(stack, main, mapped)?;
    let charged = caller_bytes(stack, main, soft)?;
    if report && std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!("bounded_caller_stack caller_is_main={main} pthread_stack_bytes={pthread_bytes} mapped_stack_bytes={mapped} main_soft_limit_bytes={soft} charged_backing_bytes={charged} reserved_host_bytes={CALLER_STACK_HOST_BYTES} other_caller_and_driver_storage_separate=true");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_mapping_census_handles_retained_backing_and_rejects_ambiguous_input() {
        let maps = b"1000-4000 rw-p 0 00:00 0 [stack]\n5000-6000 r--p 0 00:00 0 /arbitrary-\xff\n";
        assert_eq!(read_mapping(&maps[..], 0x2000).unwrap(), 0x3000);
        assert!(mapping_bytes(maps, 0x4000).is_err());
        for malformed in [
            &b""[..],
            &b"missing\n"[..],
            &b"1000-1000 rw-p\n"[..],
            &b"1000-2000 r--p\n"[..],
            &b"1000-2000\n"[..],
            &b"1000-3000 rw-p\n1800-2000 rw-p\n"[..],
            &b"1000-ffffffffffffffffffffffffffffffff rw-p\n"[..],
        ] {
            assert!(mapping_bytes(malformed, 0x1900).is_err());
        }
        let too_long = vec![b'x'; MAPS_BYTES + 1];
        assert!(read_mapping(&too_long[..], 0x1900).is_err());
        // Kernel probe: pthread reports ~8 MiB after lowering RLIMIT_STACK,
        // while the main mapping still owns more than 12 MiB.
        let retained = b"1000-c02000 rw-p 0 00:00 0 [stack]\n";
        let mapped = mapping_bytes(retained, 0xc00000).unwrap();
        assert!(mapped > CALLER_STACK_BYTES);
        let fixed = Stack {
            stack: 2 << 20,
            guard: 4096,
            alternate: 0,
            page: 4096,
        };
        assert!(charge_mapping(fixed, true, mapped).is_err());
        assert_eq!(
            charge_mapping(fixed, false, mapped).unwrap().stack,
            fixed.stack
        );
        assert_eq!(charge_mapping(fixed, true, 4 << 20).unwrap().stack, 4 << 20);
    }

    #[test]
    fn main_caller_charges_possible_growth_and_rejects_unbounded_limits() {
        let stack = Stack {
            stack: 2 << 20,
            guard: 0,
            alternate: 0,
            page: 4096,
        };
        assert_eq!(
            caller_bytes(stack, true, CALLER_STACK_BYTES as u64).unwrap(),
            CALLER_STACK_BYTES as u64
        );
        for invalid in [0, CALLER_STACK_BYTES as u64 + 1, u64::MAX] {
            assert!(caller_bytes(stack, true, invalid).is_err());
        }
        assert!(caller_bytes(Stack { stack: 0, ..stack }, true, 8 << 20).is_err());
        assert!(caller_bytes(
            Stack {
                stack: CALLER_STACK_BYTES + 1,
                ..stack
            },
            true,
            8 << 20
        )
        .is_err());
        let maximum = Stack {
            stack: CALLER_STACK_BYTES,
            guard: RAYON_STACK_AUX_BYTES,
            alternate: RAYON_STACK_AUX_BYTES,
            page: RAYON_STACK_AUX_BYTES,
        };
        assert_eq!(
            caller_bytes(maximum, true, 8 << 20).unwrap(),
            CALLER_STACK_HOST_BYTES
        );
    }

    #[test]
    fn nonmain_caller_uses_its_fixed_stack_and_signal_backing() {
        let stack = Stack {
            stack: 2 << 20,
            guard: 4096,
            alternate: 4097,
            page: 4096,
        };
        assert_eq!(
            caller_bytes(stack, false, u64::MAX).unwrap(),
            (2 << 20) + 4 * 4096
        );
        assert!(caller_bytes(
            Stack {
                alternate: RAYON_STACK_AUX_BYTES + 1,
                ..stack
            },
            false,
            8 << 20
        )
        .is_err());
        assert!(caller_bytes(
            Stack {
                stack: CALLER_STACK_BYTES + 1,
                ..stack
            },
            false,
            8 << 20
        )
        .is_err());
        validate_caller(false).unwrap();
    }
}
