//! Bounded public descriptor inventory for complete-stage qualification.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub(crate) enum PortableDescriptor {
    Aes { domain: u64, start_counter: u32, output_len: usize, first: usize, count: usize },
    Shake { input_len: usize, output_len: usize, first: usize, count: usize },
    Affine { operation: u64, bound: u32, modulus: u64, count: usize },
    Transcript { parts: Vec<u8> },
    Statement { setup_seed: [u8; 32] },
    Linear { descriptor: Box<PortableLinear>, count: usize },
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PortableRow { Uniform(i64), Dense(Vec<i64>) }
impl PortableRow {
    pub(crate) fn heap_bytes(values: &[i64; 256]) -> usize {
        if values.iter().all(|v| *v == values[0]) { 0 } else { 256 * size_of::<i64>() }
    }
    pub(crate) fn new(values: &[i64; 256]) -> Self {
        if Self::heap_bytes(values) == 0 { Self::Uniform(values[0]) } else { Self::Dense(values.to_vec()) }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PortableLinear {
    pub(crate) inputs: Vec<(u8, u64)>,
    pub(crate) output: (u8, u64),
    pub(crate) coefficients: Vec<PortableRow>,
    pub(crate) constant: PortableRow,
}
pub(super) const RECIPE_HEAP_BYTES: usize = 32 << 10;
use core::mem::size_of;
#[derive(serde::Serialize)]
struct Entry {
    descriptor_key: [u8; 32],
    descriptor: PortableDescriptor,
    first_lookup: &'static str,
}
pub(super) struct Inventory {
    active: bool,
    entries: [Option<Entry>; 512],
    overflow: bool,
    heap_bytes: usize,
}
impl Inventory {
    pub(super) fn new() -> Self {
        Self { active: std::env::var_os("LATTICA_RINGCT_METADATA_STAGE_PROFILE").is_some(), entries: core::array::from_fn(|_| None), overflow: false, heap_bytes: 0 }
    }
    pub(super) fn record<D: DescriptorKey>(&mut self, key: [u8; 32], descriptor: &D, first_lookup: &'static str) {
        if !self.active { return; }
        if self.entries.iter().flatten().any(|entry| entry.descriptor_key == key) { return; }
        let Some(bytes) = descriptor.portable_heap_bytes() else { return; };
        let Some(next) = self.heap_bytes.checked_add(bytes).filter(|n| *n <= RECIPE_HEAP_BYTES) else {
            self.overflow = true; return;
        };
        if let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) {
            let Some(descriptor) = descriptor.portable() else { return; };
            *slot = Some(Entry { descriptor_key: key, descriptor, first_lookup });
            self.heap_bytes = next;
        } else { self.overflow = true; }
    }
}
pub(crate) fn emit_inventory() -> std::io::Result<()> {
    use std::io::Write;
    CACHE.with(|slot| {
        let cache = slot.borrow();
        let Some(cache) = cache.as_ref() else { return Ok(()); };
        if cache.inventory.overflow { return Err(std::io::Error::other("native descriptor inventory overflow")); }
        let mut out = std::io::stderr().lock();
        for entry in cache.inventory.entries.iter().flatten() {
            out.write_all(b"RINGCT_NATIVE_DESCRIPTOR ")?;
            serde_json::to_writer(&mut out, entry).map_err(std::io::Error::other)?;
            out.write_all(b"\n")?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Recipe { bytes: usize, allocations: Cell<usize> }
    impl DescriptorKey for Recipe {
        fn encode(&self, _: &mut sha3::Sha3_256) { unreachable!() }
        fn family(&self) -> usize { 2 }
        fn portable_heap_bytes(&self) -> Option<usize> { Some(self.bytes) }
        fn portable(&self) -> Option<PortableDescriptor> {
            self.allocations.set(self.allocations.get() + 1);
            Some(PortableDescriptor::Transcript { parts: vec![0; self.bytes] })
        }
    }
    fn active() -> Inventory { let mut i = Inventory::new(); i.active = true; i }
    #[test]
    fn inventory_deduplicates_and_preflights_before_allocating() {
        let mut inventory = active();
        let recipe = Recipe { bytes: RECIPE_HEAP_BYTES, allocations: Cell::new(0) };
        inventory.record([0; 32], &recipe, "cold");
        inventory.record([0; 32], &recipe, "memory");
        assert_eq!(recipe.allocations.get(), 1);
        assert_eq!(inventory.heap_bytes, RECIPE_HEAP_BYTES);
        assert!(!inventory.overflow);
        inventory.record([1; 32], &recipe, "cold");
        assert!(inventory.overflow);
        assert_eq!(recipe.allocations.get(), 1);
        assert_eq!(inventory.entries.iter().flatten().count(), 1);
    }
    #[test]
    fn inventory_index_capacity_is_checked_before_allocating() {
        let mut inventory = active();
        let recipe = Recipe { bytes: 0, allocations: Cell::new(0) };
        for index in 0u64..513 {
            let mut key = [0; 32]; key[..8].copy_from_slice(&index.to_le_bytes());
            inventory.record(key, &recipe, "table");
        }
        assert!(inventory.overflow);
        assert_eq!(recipe.allocations.get(), 512);
    }
    #[test]
    fn uniform_rows_are_lossless_and_dense_rows_are_charged() {
        assert_eq!(PortableRow::new(&[-1; 256]), PortableRow::Uniform(-1));
        assert_eq!(PortableRow::heap_bytes(&[-1; 256]), 0);
        let row = core::array::from_fn(|i| i as i64 - 128);
        assert_eq!(PortableRow::new(&row), PortableRow::Dense(row.to_vec()));
        assert_eq!(PortableRow::heap_bytes(&row), 256 * size_of::<i64>());
    }
}
