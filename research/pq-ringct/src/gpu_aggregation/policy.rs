//! Immutable research construction/window policy, installed before any workers.
use super::{ensure, Result};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Policy {
    pub name: &'static str,
    pub program_bytes: usize,
    pub input_values: usize,
    pub live_jobs: usize,
    pub symbolic_bytes: u64,
    pub backend_host_bytes: u64,
    pub tree_host_bytes: u64,
}
impl Policy {
    pub fn parse(name: &str) -> Result<Self> {
        let mut value = Self {
            name: "standard",
            program_bytes: 2 << 30,
            input_values: 1 << 20,
            live_jobs: 4,
            symbolic_bytes: 1 << 30,
            backend_host_bytes: 20 << 30,
            tree_host_bytes: 8 << 30,
        };
        match name {
            "standard" => (),
            "wide-inputs" => {
                value.name = "wide-inputs";
                value.input_values = 2 << 20;
            }
            "wide-memory" => {
                value.name = "wide-memory";
                value.input_values = 2 << 20;
                value.program_bytes = 3 << 30;
                value.live_jobs = 2;
                value.backend_host_bytes = 24 << 30;
                value.tree_host_bytes = 16 << 30;
            }
            "typed-batch" => {
                // One large compiler replaces the four-program lookahead window.
                // Shared weighted preparation window across typed requests.
                value.name = "typed-batch";
                value.program_bytes = 6 << 30;
                value.input_values = 8 << 20;
                value.live_jobs = 1;
                value.symbolic_bytes = 3 << 30;
                value.backend_host_bytes = 24 << 30;
                value.tree_host_bytes = 16 << 30;
            }
            _ => return Err("unknown aggregation compiler policy".into()),
        }
        Ok(value)
    }
    pub fn host_reservation(self) -> u64 {
        (3 << 30)
            + self.symbolic_bytes
            + (self.program_bytes * self.live_jobs) as u64
            + self.backend_host_bytes
    }
}
static SELECTED: OnceLock<Policy> = OnceLock::new();
pub(crate) fn current() -> Policy {
    SELECTED
        .get()
        .copied()
        .unwrap_or_else(|| Policy::parse("standard").unwrap())
}
pub(crate) fn install(name: &str, profile: &str, transactions: usize) -> Result<()> {
    let policy = Policy::parse(name)?;
    ensure(
        name == "standard" || (profile == "grouped-v5" && transactions == 4),
        "wide compilation requires grouped-v5 N4/36 GiB envelope",
    )?;
    ensure(
        std::env::var("LATTICA_V2_GPU_COMPILER_POLICY").unwrap_or_else(|_| "standard".into())
            == name,
        "compiler policy differs from guarded selection",
    )?;
    ensure(
        policy.host_reservation()
            <= if transactions == 4 {
                36 << 30
            } else {
                32 << 30
            },
        "compiler policy exceeds worker envelope",
    )?;
    SELECTED
        .set(policy)
        .map_err(|_| "aggregation policy already captured".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expanded_policy_trades_ready_programs_for_tree_storage() {
        let narrow = Policy::parse("standard").unwrap();
        let inputs = Policy::parse("wide-inputs").unwrap();
        let wide = Policy::parse("wide-memory").unwrap();
        assert_eq!(narrow.host_reservation(), 32 << 30);
        assert_eq!(inputs.host_reservation(), narrow.host_reservation());
        assert_eq!(wide.host_reservation(), 34 << 30);
        assert_eq!(wide.live_jobs, 2);
        assert_eq!(wide.backend_host_bytes - wide.tree_host_bytes, 8 << 30);
        let typed = Policy::parse("typed-batch").unwrap();
        assert_eq!(typed.host_reservation(), 36 << 30);
        assert_eq!(typed.live_jobs, 1);
        assert!(Policy::parse("unlimited").is_err());
    }
}
