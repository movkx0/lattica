//! Bind the allocator's process-lifetime configuration to worker admission.
//! Reading current environment variables alone cannot validate a OnceLock
//! initialized by an earlier caller. Do not change that caller's configuration.

use super::{cfg, is_armed, spill_stats};

pub(crate) fn admit(spill_bytes: u64, directory: &str) -> Result<(), &'static str> {
    if spill_bytes == 0
        || directory.is_empty()
        || directory.len() > 255
        || directory.as_bytes().contains(&0)
    {
        return Err("invalid admitted spill configuration");
    }
    let memory_backed = match std::env::var("LATTICA_SPILL_BACKING").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("file") => false,
        Ok("memory") => true,
        _ => return Err("invalid worker spill backing"),
    };
    let config = cfg();
    let armed = is_armed();
    let live_bytes = spill_stats().1;
    let directory_matches = &config.dir[..config.dir_len] == directory.as_bytes();
    let result = if armed {
        Err("worker startup requires quiescent spill scopes")
    } else if config.max_bytes != Some(spill_bytes)
        || !directory_matches
        || config.memory_backed != memory_backed
        || live_bytes > spill_bytes
    {
        Err("cached spill configuration differs from worker assignment")
    } else {
        Ok(())
    };
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_spill_configuration {}",
            serde_json::json!({
                "schema": "lattica-spill-worker-admission-v1", "pid": std::process::id(),
                "assigned_bytes": spill_bytes, "cached_limit_bytes": config.max_bytes,
                "live_bytes": live_bytes, "directory_matches": directory_matches,
                "cached_memory_backed": config.memory_backed, "expected_memory_backed": memory_backed,
                "armed": armed, "allowed": result.is_ok(), "error": result.as_ref().err(),
                "is_lifetime_rss_admission": false,
            })
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_admission_checks_cached_configuration_in_fresh_processes() {
        const CHILD: &str = "LATTICA_SPILL_CONFIG_CHILD";
        let Ok(mode) = std::env::var(CHILD) else {
            for mode in [
                "fresh",
                "memory",
                "missing_limit",
                "stale_limit",
                "stale_directory",
                "stale_backing",
                "invalid_backing",
                "active",
            ] {
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command.args(["--exact", "spill_alloc::config_admission::tests::worker_admission_checks_cached_configuration_in_fresh_processes",
                    "--test-threads=1", "--nocapture"])
                    .env(CHILD, mode).env("LATTICA_SPILL_DIR", "/tmp")
                    .env("LATTICA_SPILL_MAX_BYTES", (1u64 << 30).to_string())
                    .env("LATTICA_SPILL_BACKING", "file")
                    .env("LATTICA_PROVING_REPORT", "1");
                let output = command.output().unwrap();
                assert!(
                    output.status.success(),
                    "mode={mode} {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                eprintln!("{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            }
            return;
        };
        match mode.as_str() {
            "missing_limit" => std::env::remove_var("LATTICA_SPILL_MAX_BYTES"),
            "stale_limit" => std::env::set_var("LATTICA_SPILL_MAX_BYTES", (2u64 << 30).to_string()),
            "stale_directory" => {
                std::env::set_var("LATTICA_SPILL_DIR", "/tmp/previous-spill-directory")
            }
            "stale_backing" | "memory" => std::env::set_var("LATTICA_SPILL_BACKING", "memory"),
            _ => (),
        }
        if mode == "fresh" {
            admit(1 << 30, "/tmp").unwrap();
        }
        let scope = super::super::SpillScope::arm();
        let original_limit = cfg().max_bytes;
        // Current environment now matches the worker's assignment. An older
        // immutable configuration must still reject before that worker starts.
        std::env::set_var("LATTICA_SPILL_MAX_BYTES", (1u64 << 30).to_string());
        std::env::set_var("LATTICA_SPILL_DIR", "/tmp");
        if mode != "memory" {
            std::env::set_var("LATTICA_SPILL_BACKING", "file");
        }
        if mode == "invalid_backing" {
            std::env::set_var("LATTICA_SPILL_BACKING", "invalid");
        }
        if mode == "active" {
            assert_eq!(
                admit(1 << 30, "/tmp"),
                Err("worker startup requires quiescent spill scopes")
            );
            drop(scope);
        } else {
            drop(scope);
            assert_eq!(
                admit(1 << 30, "/tmp").is_ok(),
                mode == "fresh" || mode == "memory"
            );
        }
        assert_eq!(cfg().max_bytes, original_limit);
        assert_eq!(spill_stats(), (0, 0));
        assert!(admit(0, "/tmp").is_err());
        assert!(admit(1 << 30, &"x".repeat(256)).is_err());
        assert!(admit(1 << 30, "/tmp\0suffix").is_err());
        eprintln!("spill_configuration_verified mode={mode} cached_configuration_unchanged=true");
    }
}
