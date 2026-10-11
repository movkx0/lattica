//! Bind the public worker's per-buffer allowance to every shared-engine plan
//! and allocation, rather than using only the physical device's maximum.
//! This limit confers no worker/registry authority; startup admission is still
//! responsible for validating the complete assignment and its physical caps.
use std::{fs::File, io::Read};

const MAX_ASSIGNMENT_BYTES: u64 = 1 << 20;
const ENV: &str = "LATTICA_V2_WORKER_BUDGET";

fn read_limit(reader: impl Read) -> Result<usize, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_ASSIGNMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_ASSIGNMENT_BYTES {
        return Err("GPU allocation-limit assignment exceeds 1 MiB".into());
    }
    let assignment: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if assignment["gpu"]["version"].as_u64() != Some(1) {
        return Err("unsupported GPU allocation-limit assignment version".into());
    }
    let limit = assignment["gpu"]["max_allocation_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("GPU assignment requires a positive integer max_allocation_bytes")?;
    usize::try_from(limit).map_err(|_| "GPU assigned allocation limit overflow".into())
}

pub(super) fn from_env() -> Result<Option<usize>, String> {
    std::env::var_os(ENV)
        .map(|path| read_limit(File::open(path).map_err(|e| e.to_string())?))
        .transpose()
}

pub(super) fn effective(hardware: usize, assigned: Option<usize>) -> usize {
    assigned.map_or(hardware, |limit| hardware.min(limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_and_hardware_limits_both_constrain_buffers() {
        let bytes = br#"{"gpu":{"version":1,"max_allocation_bytes":1048576}}"#;
        let limit = read_limit(&bytes[..]).unwrap();
        assert_eq!(effective(4 << 30, Some(limit)), 1 << 20);
        assert_eq!(effective(512 << 10, Some(limit)), 512 << 10);
        assert_eq!(effective(4 << 30, None), 4 << 30);
    }

    #[test]
    fn invalid_assignment_limits_never_fall_back_to_hardware() {
        for value in [
            "null",
            "0",
            "-1",
            "1.5",
            "true",
            "\"1024\"",
            "18446744073709551616",
        ] {
            let json = format!(r#"{{"gpu":{{"version":1,"max_allocation_bytes":{value}}}}}"#);
            assert!(read_limit(json.as_bytes()).is_err(), "{value}");
        }
        for bytes in [
            b"".as_slice(),
            b"{}",
            b"[]",
            b"null",
            b"{\"gpu\":{\"version\":1}}",
            b"{\"gpu\":{\"version\":2,\"max_allocation_bytes\":1024}}",
        ] {
            assert!(read_limit(bytes).is_err());
        }
    }

    #[test]
    fn assignment_reader_enforces_its_byte_bound() {
        let mut bytes = br#"{"gpu":{"version":1,"max_allocation_bytes":1024}}"#.to_vec();
        bytes.resize(MAX_ASSIGNMENT_BYTES as usize, b' ');
        assert_eq!(read_limit(bytes.as_slice()).unwrap(), 1024);
        bytes.push(b' ');
        assert!(read_limit(bytes.as_slice())
            .unwrap_err()
            .contains("exceeds 1 MiB"));
    }

    #[test]
    #[cfg(feature = "gpu")]
    #[ignore = "requires a leased OpenCL GPU; tests actual buffer caps and immutable engine assignment"]
    fn gpu_assignment_limit_controls_buffers_plans_and_engine_reuse() {
        use super::super::{
            allocation, compute, initialize_mode_tracked, lde_plan::InputShape,
            plan_coset_lde_commit, shutdown, Limits, TestShutdownGuard, TransferMode, ENGINE, MIB,
        };
        use std::{ffi::OsString, path::PathBuf};

        struct Environment {
            values: Vec<(&'static str, Option<OsString>)>,
            path: PathBuf,
        }
        impl Drop for Environment {
            fn drop(&mut self) {
                for (name, value) in &self.values {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
                let _ = std::fs::remove_file(&self.path);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "lattica-allocation-limit-{}.json",
            std::process::id()
        ));
        let _file = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let _env = Environment {
            values: [ENV, "LATTICA_V2_GPU_RETAIN_TREES"]
                .map(|name| (name, std::env::var_os(name)))
                .to_vec(),
            path: path.clone(),
        };
        let write = |limit| {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "gpu": {"version":1, "max_allocation_bytes":limit}
                }))
                .unwrap(),
            )
            .unwrap()
        };
        write(8 * MIB);
        std::env::set_var(ENV, &path);
        std::env::set_var("LATTICA_V2_GPU_RETAIN_TREES", "1");
        let _shutdown = TestShutdownGuard;
        let limits = Limits {
            managed_bytes: 64 * MIB,
            tile_bytes: MIB,
            staging_bytes: 32768,
        };
        assert!(initialize_mode_tracked(limits, TransferMode::Serial).unwrap());
        let plan = plan_coset_lde_commit(
            &[InputShape {
                height: 4096,
                width: 64,
                added_bits: 4,
            }],
            6,
            128 * MIB,
        )
        .unwrap();
        assert_eq!(plan.columns_per_tile(), 16);
        assert_eq!(plan.transform_buffer_bytes, 8 * MIB);
        {
            let guard = ENGINE.get().unwrap().lock().unwrap();
            let e = guard.as_ref().unwrap();
            assert_eq!(e.max_alloc, 8 * MIB);
            let before = *e.accounting.lock().unwrap();
            assert!(allocation(
                &e.pq,
                &e.accounting,
                e.limits,
                e.max_alloc,
                MIB + 1,
                compute::flags::MEM_READ_WRITE
            )
            .is_err());
            let rejected = *e.accounting.lock().unwrap();
            assert_eq!(
                (rejected.live, rejected.allocations),
                (before.live, before.allocations)
            );
            let accepted = allocation(
                &e.pq,
                &e.accounting,
                e.limits,
                e.max_alloc,
                MIB,
                compute::flags::MEM_READ_WRITE,
            )
            .unwrap();
            assert_eq!(e.accounting.lock().unwrap().live, before.live + 8 * MIB);
            drop(accepted);
            assert_eq!(e.accounting.lock().unwrap().live, before.live);
        }
        write(16 * MIB);
        assert!(initialize_mode_tracked(limits, TransferMode::Serial).is_err());
        std::env::remove_var(ENV);
        assert!(initialize_mode_tracked(limits, TransferMode::Serial).is_err());
        std::env::set_var(ENV, &path);
        write(8 * MIB);
        assert!(!initialize_mode_tracked(limits, TransferMode::Serial).unwrap());
        shutdown().unwrap();
        write(8usize);
        assert!(initialize_mode_tracked(limits, TransferMode::Serial).is_err());
        assert!(ENGINE.get().unwrap().lock().unwrap().is_none());
    }
}
