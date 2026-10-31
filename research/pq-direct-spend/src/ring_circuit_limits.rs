//! Closed compiler memory experiments. These are logical backing allowances,
//! not process RSS bounds or cryptographic proof/dispatch authorization.
use super::{AUXILIARY_BYTES, MAX_INPUTS, MAX_ROWS, MAX_WIRES, PROGRAM_BYTES, WITNESS_BYTES};
use crate::Error;
use lattica_prover_p3::block_v2::machine::program::{
    ConstructionLimits, MAX_WIRES as CORE_MAX_WIRES,
};
use serde::Serialize;

const WORKER_HOST_BYTES: u64 = 32 << 30;

/// The default preserves historical screening. Larger profiles are explicit;
/// a refused compilation never retries with another profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum CompilerMemoryProfile {
    #[default]
    #[serde(rename = "256m")]
    Program256MiB,
    #[serde(rename = "2g")]
    Program2GiB,
    #[serde(rename = "8g")]
    Program8GiB,
    #[serde(rename = "24g")]
    Program24GiB,
}

impl core::str::FromStr for CompilerMemoryProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "256m" => Ok(Self::Program256MiB),
            "2g" => Ok(Self::Program2GiB),
            "8g" => Ok(Self::Program8GiB),
            "24g" => Ok(Self::Program24GiB),
            _ => Err("compiler memory profile must be 256m, 2g, 8g, or 24g"),
        }
    }
}

/// A separate compiler-capacity experiment. Increasing memory never selects
/// this profile implicitly, and the core's hard wire ceiling is not modified.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum CompilerWireProfile {
    #[default]
    #[serde(rename = "16m")]
    Research16M,
    #[serde(rename = "64m")]
    Core64M,
}

impl core::str::FromStr for CompilerWireProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "16m" => Ok(Self::Research16M),
            "64m" => Ok(Self::Core64M),
            _ => Err("compiler wire profile must be 16m or 64m"),
        }
    }
}

/// Closed, independent capacity selectors; no caller-defined numeric limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompilerCapacityProfile {
    memory: CompilerMemoryProfile,
    wires: CompilerWireProfile,
}

impl CompilerCapacityProfile {
    pub const fn new(memory: CompilerMemoryProfile, wires: CompilerWireProfile) -> Self {
        Self { memory, wires }
    }
}

impl From<CompilerMemoryProfile> for CompilerCapacityProfile {
    fn from(memory: CompilerMemoryProfile) -> Self {
        Self::new(memory, CompilerWireProfile::Research16M)
    }
}

/// Descriptive limits only; callers cannot pass this struct to the compiler.
/// Its selected enum is the only way to choose a program allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CompilerLimits {
    pub memory_profile: CompilerMemoryProfile,
    pub wire_profile: CompilerWireProfile,
    pub program_byte_limit: u64,
    pub witness_byte_limit: u64,
    pub auxiliary_byte_limit: u64,
    pub required_host_bytes: u64,
    pub worker_host_byte_limit: u64,
    pub wire_limit: usize,
    pub input_limit: usize,
    pub row_limit: usize,
}

impl CompilerMemoryProfile {
    pub const fn limits(self) -> CompilerLimits {
        CompilerCapacityProfile::new(self, CompilerWireProfile::Research16M).limits()
    }

    #[cfg(test)]
    fn admit(self, host_allowance: usize) -> Result<AdmittedLimits, Error> {
        CompilerCapacityProfile::from(self).admit(host_allowance)
    }
}

impl CompilerCapacityProfile {
    pub const fn limits(self) -> CompilerLimits {
        let program = match self.memory {
            CompilerMemoryProfile::Program256MiB => PROGRAM_BYTES as u64,
            CompilerMemoryProfile::Program2GiB => 2_u64 << 30,
            CompilerMemoryProfile::Program8GiB => 8_u64 << 30,
            CompilerMemoryProfile::Program24GiB => 24_u64 << 30,
        };
        let wire_limit = match self.wires {
            CompilerWireProfile::Research16M => MAX_WIRES,
            CompilerWireProfile::Core64M => 1 << 26,
        };
        CompilerLimits {
            memory_profile: self.memory,
            wire_profile: self.wires,
            program_byte_limit: program,
            witness_byte_limit: WITNESS_BYTES as u64,
            auxiliary_byte_limit: AUXILIARY_BYTES as u64,
            required_host_bytes: program + WITNESS_BYTES as u64 + AUXILIARY_BYTES as u64,
            worker_host_byte_limit: WORKER_HOST_BYTES,
            wire_limit,
            input_limit: MAX_INPUTS,
            row_limit: MAX_ROWS,
        }
    }

    /// This private admission must precede parameters, builder and witness
    /// allocation. The external process guard still covers allocator/stack
    /// overhead and pre-existing caller state; no RSS claim is made here.
    pub(super) fn admit(self, host_allowance: usize) -> Result<AdmittedLimits, Error> {
        let limits = self.limits();
        let host_allowance_bytes =
            u64::try_from(host_allowance).map_err(|_| Error::ResourceLimit)?;
        if host_allowance_bytes < limits.required_host_bytes
            || host_allowance_bytes > WORKER_HOST_BYTES
            || limits.wire_limit > CORE_MAX_WIRES
        {
            return Err(Error::ResourceLimit);
        }
        Ok(AdmittedLimits {
            limits,
            host_allowance_bytes,
            construction: ConstructionLimits {
                max_requested_program_bytes: usize::try_from(limits.program_byte_limit)
                    .map_err(|_| Error::ResourceLimit)?,
                max_wires: limits.wire_limit,
                max_input_values: MAX_INPUTS,
            },
        })
    }
}

/// Internal evidence of the complete logical footprint check. Arithmetic
/// helpers cannot manufacture or change it, and it carries no proving permit.
pub(super) struct AdmittedLimits {
    pub(super) limits: CompilerLimits,
    pub(super) host_allowance_bytes: u64,
    pub(super) construction: ConstructionLimits,
}

#[cfg(test)]
#[path = "ring_circuit_limits/tests.rs"]
mod tests;
