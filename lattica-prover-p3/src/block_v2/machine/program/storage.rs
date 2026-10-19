//! Backend-independent retained public source accounting, including spare
//! capacity and the Arc allocation used by MachineAir.
use super::*;

impl Program {
    pub(crate) fn source_host_bytes(&self) -> Result<usize, String> {
        fn bytes<T>(capacity: usize) -> Result<usize, String> {
            capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or_else(|| "machine source capacity overflow".into())
        }
        let layout = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<Program>())
            .map_err(|_| "machine source Arc layout overflow")?
            .0
            .pad_to_align();
        let mut total = layout.size();
        let mut add = |n: usize| -> Result<(), String> {
            total = total.checked_add(n).ok_or("machine source size overflow")?;
            Ok(())
        };
        add(bytes::<Op>(self.operations.capacity())?)?;
        add(bytes::<Row>(self.rows.capacity())?)?;
        add(bytes::<u32>(self.references.capacity())?)?;
        for op in &self.operations {
            if let Op::SelectHint { entries, bits, .. } = op {
                add(bytes::<Wire>(entries.capacity())?)?;
                add(bytes::<Wire>(bits.capacity())?)?;
            }
        }
        for row in &self.rows {
            if let Row::Alu(ops) | Row::Cubic(ops) = row {
                add(bytes::<u32>(ops.capacity())?)?;
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_footprint_counts_unused_capacity_and_nested_hint_storage() {
        let mut b = super::super::ProgramBuilder::new(0).unwrap();
        b.input();
        let mut p = b.finish(Some(8)).unwrap();
        let before = p.source_host_bytes().unwrap();
        let capacity = p.operations.capacity();
        p.operations.reserve_exact(capacity + 7);
        let extra = (p.operations.capacity() - capacity) * std::mem::size_of::<Op>();
        assert_eq!(p.source_host_bytes().unwrap(), before + extra);
        let mut entries = Vec::with_capacity(10);
        entries.push(Wire(0));
        let bits = Vec::with_capacity(4);
        let heap = (entries.capacity() + bits.capacity()) * std::mem::size_of::<Wire>();
        let before = p.source_host_bytes().unwrap();
        p.operations.push(Op::SelectHint {
            entries,
            bits,
            out: Wire(0),
        });
        assert_eq!(p.source_host_bytes().unwrap(), before + heap);
    }
}
