//! Place worker-local compiler storage on allowed physical cores. Failure to
//! pin affects performance only and is reported; it never expands affinity.
use super::MAX_WORKERS;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    Scheduler,
    Packed,
    Spread,
}
fn policy() -> Policy {
    if std::env::var("LATTICA_CPU_SCALING_PROFILE").as_deref() == Ok("1") {
        match std::env::var("LATTICA_CPU_SCALING_PLACEMENT").as_deref() {
            Ok("scheduler") => return Policy::Scheduler,
            Ok("packed") => return Policy::Packed,
            _ => {}
        }
    }
    Policy::Spread
}

#[derive(Clone, Copy, Default)]
struct Core {
    cpu: usize,
    package: i32,
    core: i32,
    cache: i32,
}
fn order(cores: &mut [Core], width: usize, policy: Policy) -> [Option<usize>; MAX_WORKERS] {
    let mut result = [None; MAX_WORKERS];
    if policy == Policy::Scheduler {
        return result;
    }
    cores.sort_unstable_by_key(|c| (c.package, c.cache, c.core, c.cpu));
    if policy == Policy::Packed {
        for (out, core) in result.iter_mut().take(width).zip(cores) {
            *out = Some(core.cpu);
        }
        return result;
    }
    let mut used = 0;
    for rank in 0..cores.len() {
        let mut group = None;
        let mut position = 0;
        for core in cores.iter() {
            let key = (core.package, core.cache);
            if group != Some(key) {
                group = Some(key);
                position = 0;
            }
            if position == rank && used < width.min(MAX_WORKERS) {
                result[used] = Some(core.cpu);
                used += 1;
            }
            position += 1;
        }
        if used == width.min(MAX_WORKERS) {
            break;
        }
    }
    result
}

#[cfg(target_os = "linux")]
fn number(cpu: usize, field: &str) -> Option<i32> {
    use std::io::Read;
    let mut bytes = [0; 64];
    let n = std::fs::File::open(format!("/sys/devices/system/cpu/cpu{cpu}/{field}"))
        .ok()?
        .read(&mut bytes)
        .ok()?;
    std::str::from_utf8(&bytes[..n]).ok()?.trim().parse().ok()
}

pub(super) fn plan(width: usize) -> [Option<usize>; MAX_WORKERS] {
    #[cfg(target_os = "linux")]
    {
        let selected = policy();
        if selected == Policy::Scheduler {
            return [None; MAX_WORKERS];
        }
        let mut mask = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
        if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) } != 0 {
            return [None; MAX_WORKERS];
        }
        // Bounded stack control storage, covered by the existing coordinator.
        let mut cores = [Core::default(); libc::CPU_SETSIZE as usize];
        let mut count = 0;
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if !unsafe { libc::CPU_ISSET(cpu, &mask) } {
                continue;
            }
            let (Some(package), Some(core)) = (
                number(cpu, "topology/physical_package_id"),
                number(cpu, "topology/core_id"),
            ) else {
                continue;
            };
            if cores[..count]
                .iter()
                .any(|c| c.package == package && c.core == core)
            {
                continue;
            }
            let cache = number(cpu, "cache/index3/id").unwrap_or(package);
            cores[count] = Core {
                cpu,
                package,
                core,
                cache,
            };
            count += 1;
        }
        return order(&mut cores[..count], width, selected);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = width;
        [None; MAX_WORKERS]
    }
}

pub(super) fn pin(cpu: Option<usize>) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        cpu.map(|cpu| {
            let mut allowed = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            if cpu >= libc::CPU_SETSIZE as usize
                || unsafe {
                    libc::sched_getaffinity(0, std::mem::size_of_val(&allowed), &mut allowed)
                } != 0
                || !unsafe { libc::CPU_ISSET(cpu, &allowed) }
            {
                return false;
            }
            let mut mask = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            unsafe { libc::CPU_SET(cpu, &mut mask) };
            (unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) }) == 0
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpu;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn placement_spreads_cache_groups_without_duplicate_cpus() {
        let mut cores = core::array::from_fn::<_, 8, _>(|cpu| Core {
            cpu,
            package: 0,
            core: cpu as i32,
            cache: (cpu / 4) as i32,
        });
        assert_eq!(
            &order(&mut cores, 4, Policy::Spread)[..4],
            &[Some(0), Some(4), Some(1), Some(5)]
        );
        assert_eq!(
            &order(&mut cores, 4, Policy::Packed)[..4],
            &[Some(0), Some(1), Some(2), Some(3)]
        );
        assert_eq!(order(&mut cores, 4, Policy::Scheduler), [None; MAX_WORKERS]);
        assert_eq!(
            order(&mut cores[..3], 16, Policy::Spread)
                .iter()
                .flatten()
                .count(),
            3
        );
    }
}
