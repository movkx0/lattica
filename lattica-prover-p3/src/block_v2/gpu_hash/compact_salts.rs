//! GPU adapter for the shared, private salt replay implementation.
pub(super) use crate::block_v2::compact_salts::{generate, retain, Checkpoints, SaltMatrix};
pub(super) fn enabled() -> Result<bool, String> {
    return match std::env::var(crate::block_v2::worker_memory::env_name("COMPACT_SALTS")) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(v) if v == "0" => Ok(false),
        Ok(v) if v == "1" => Ok(true),
        _ => Err("compact salts must be 0 or 1".into()),
    };
}
