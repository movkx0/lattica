//! Native verifier call storage. The proof is already caller-owned: checking
//! its capacities cannot retroactively reserve the caller's allocation.
//! Release x86_64 bounds are qualified against pinned dependency/toolchain
//! sources; callbacks, stacks and allocator/OS overhead are outside this model.

use super::Val;
use core::fmt::{self, Write};

pub(super) const DIAGNOSTIC_BYTES: usize = 1024;

pub(super) fn copy_public(public: &[Val]) -> Result<Vec<Val>, &'static str> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(public.len())
        .map_err(|_| "native verifier public input allocation failed")?;
    values.extend_from_slice(public);
    Ok(values)
}

struct Diagnostic {
    bytes: [u8; DIAGNOSTIC_BYTES],
    len: usize,
}
impl Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let output = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        output.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The concrete upstream verifier errors use derived Debug and primitive,
/// field, string and vector formatters, which do not allocate while writing.
/// A fixed writer alone does not bound arbitrary user-defined Debug callbacks.
pub(super) fn error(error: &impl fmt::Debug) -> String {
    let mut output = Diagnostic {
        bytes: [0; DIAGNOSTIC_BYTES],
        len: 0,
    };
    if write!(&mut output, "{error:?}").is_err() {
        return "native verifier rejected proof (diagnostic exceeds limit)".to_owned();
    }
    // write_str accepts complete UTF-8 strings, so even the capacity boundary
    // cannot split a codepoint. One final allocation; no growing String.
    core::str::from_utf8(&output.bytes[..output.len])
        .expect("diagnostic contains UTF-8")
        .to_owned()
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
mod storage;
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
pub(super) use storage::{proof_bytes, Plan, PROOF_LIMIT_BYTES, TEMPORARY_LIMIT_BYTES};

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
