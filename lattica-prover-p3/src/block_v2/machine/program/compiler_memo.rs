//! Expression memo storage charged to the same construction allowance as
//! instructions, interning and packing. The lowerer owns and releases each
//! table while exclusively borrowing its builder.
use super::super::verifier::CompileError;
use super::{ConstructionMap, ScopedProgramBuilder};

pub(in super::super) struct CompilerMemo<V: Copy> {
    table: ConstructionMap<usize, V>,
}

impl<V: Copy> CompilerMemo<V> {
    pub(in super::super) fn new() -> Self {
        Self {
            table: ConstructionMap::new(),
        }
    }

    pub(in super::super) fn get(&self, key: &usize) -> Option<&V> {
        self.table.get(key)
    }

    pub(in super::super) fn insert(
        &mut self,
        key: usize,
        value: V,
        builder: &mut ScopedProgramBuilder<'_>,
    ) -> Result<(), CompileError> {
        self.table.insert(key, value, &mut builder.memory);
        if builder.resource_failure().is_some() {
            return Err(CompileError::Shape("expression compiler host allowance"));
        }
        Ok(())
    }

    pub(in super::super) fn release(&mut self, builder: &mut ScopedProgramBuilder<'_>, kind: &str) {
        let before = builder.memory.live;
        let bytes = self.table.clear(&mut builder.memory);
        if let Some(limit) = builder.memory.limit {
            eprintln!("bounded_compiler_memo_release kind={kind} released_bytes={bytes} live_before={before} live_after={} peak_bytes={} limit_bytes={limit}",
                builder.memory.live, builder.memory.peak);
        }
    }
}

#[cfg(test)]
mod tests;
