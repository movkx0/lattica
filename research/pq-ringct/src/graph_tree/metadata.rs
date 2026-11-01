//! Bounded numerical analysis belonging to one immutable prepared source owner.
//! All backing is included in SourcePreparationPlan's original retained claim.
use super::{
    fixed_sources::{FixedSourceCensus, FixedSourceFailure},
    LeafKind, LeafPlan, OperationFamily, Plan, UnprovedRelationGraph,
};
use crate::{
    component_tree::native_shape::NativePlanningStorage,
    execution::retained_resources::Requirements,
    rust_verify::committed_backend::{Operation, Source},
};
use std::sync::Mutex;
const OPERATIONS: usize = 1311;
const POLYNOMIALS: usize = 1770;
const NONE: u16 = u16::MAX;
const ENTRIES: usize = 32;
type Result<T> = core::result::Result<T, FixedSourceFailure>;
pub(super) type Footprint = (Requirements, Requirements, Requirements);

struct Index {
    leaf_for_operation: [u16; OPERATIONS],
    polynomial_operation: [u16; POLYNOMIALS],
    derived_count: [u16; OPERATIONS],
    common_bytes: [usize; 8],
    byte_count: usize,
}
impl Index {
    fn build(
        leaves: &[LeafPlan],
        derived: impl IntoIterator<Item = Option<usize>>,
        common_bytes: impl IntoIterator<Item = usize>,
    ) -> Result<Self> {
        let mut index = Self {
            leaf_for_operation: [NONE; OPERATIONS],
            polynomial_operation: [NONE; POLYNOMIALS],
            derived_count: [0; OPERATIONS],
            common_bytes: [0; 8],
            byte_count: 0,
        };
        for (ordinal, leaf) in leaves.iter().enumerate() {
            let ordinal = u16::try_from(ordinal).map_err(|_| FixedSourceFailure::Coverage)?;
            if ordinal == NONE {
                return Err(FixedSourceFailure::Coverage);
            }
            for &operation in leaf.operation_indices() {
                let slot = index
                    .leaf_for_operation
                    .get_mut(operation)
                    .ok_or(FixedSourceFailure::Coverage)?;
                if *slot != NONE {
                    return Err(FixedSourceFailure::Coverage);
                }
                *slot = ordinal;
            }
        }
        for (polynomial, operation) in derived.into_iter().enumerate() {
            let slot = index
                .polynomial_operation
                .get_mut(polynomial)
                .ok_or(FixedSourceFailure::Coverage)?;
            if let Some(operation) = operation {
                let count = index
                    .derived_count
                    .get_mut(operation)
                    .ok_or(FixedSourceFailure::Coverage)?;
                *slot = operation as u16;
                *count = count.checked_add(1).ok_or(FixedSourceFailure::Resource)?;
            }
        }
        for byte in common_bytes {
            if index.byte_count == index.common_bytes.len()
                || index.byte_count != 0 && index.common_bytes[index.byte_count - 1] >= byte
            {
                return Err(FixedSourceFailure::Coverage);
            }
            index.common_bytes[index.byte_count] = byte;
            index.byte_count += 1;
        }
        Ok(index)
    }
    fn leaf<'a>(
        &self,
        plan: &'a [LeafPlan],
        family: &OperationFamily,
        operations: &[usize],
    ) -> Result<(usize, &'a LeafPlan)> {
        let first = *operations.first().ok_or(FixedSourceFailure::Coverage)?;
        let ordinal = *self
            .leaf_for_operation
            .get(first)
            .ok_or(FixedSourceFailure::Coverage)? as usize;
        let leaf = plan.get(ordinal).ok_or(FixedSourceFailure::Coverage)?;
        if leaf.kind() != &LeafKind::Operations(family.clone())
            || leaf.operation_indices() != operations
        {
            return Err(FixedSourceFailure::Coverage);
        }
        Ok((ordinal, leaf))
    }
    fn derived_matches(&self, operations: &[usize], polynomials: &[usize]) -> bool {
        if operations.windows(2).any(|p| p[0] >= p[1])
            || polynomials.windows(2).any(|p| p[0] >= p[1])
        {
            return false;
        }
        let expected = operations.iter().try_fold(0usize, |n, &operation| {
            n.checked_add(*self.derived_count.get(operation)? as usize)
        });
        expected == Some(polynomials.len())
            && polynomials.iter().all(|&polynomial| {
                self.polynomial_operation
                    .get(polynomial)
                    .is_some_and(|&operation| {
                        operation != NONE && operations.binary_search(&(operation as usize)).is_ok()
                    })
            })
    }
}
#[derive(Clone, Copy)]
struct Entry {
    family: u8,
    key: [u8; 32],
    storage: NativePlanningStorage,
    value: Footprint,
}
struct Footprints {
    entries: [Option<Entry>; ENTRIES],
    next: usize,
}
impl Footprints {
    fn new() -> Self {
        Self {
            entries: [None; ENTRIES],
            next: 0,
        }
    }
    fn get(&self, family: u8, key: [u8; 32], storage: NativePlanningStorage) -> Option<Footprint> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.family == family && e.key == key && e.storage == storage)
            .map(|e| e.value)
    }
    fn insert(&mut self, entry: Entry) {
        self.entries[self.next] = Some(entry);
        self.next = (self.next + 1) % ENTRIES;
    }
}

pub(crate) struct GraphMetadata {
    fixed: FixedSourceCensus,
    index: Index,
    native_coverage: [bool; 2],
    footprints: Mutex<Footprints>,
}
impl GraphMetadata {
    pub(crate) const fn retained_bytes() -> usize {
        core::mem::size_of::<Result<Self>>()
    }
    pub(crate) const fn construction_bytes() -> usize {
        8 * (Self::retained_bytes()
            + core::mem::size_of::<Footprint>()
            + core::mem::size_of::<NativePlanningStorage>())
    }
    pub(crate) fn new(plan: &Plan, graph: &UnprovedRelationGraph) -> Result<Self> {
        let fixed = FixedSourceCensus::from_graph(graph)?;
        let index = Index::build(
            plan.leaves(),
            graph.polynomials().iter().map(|p| match p.source {
                Source::Derived { operation } => Some(operation),
                _ => None,
            }),
            graph.bytes().iter().enumerate().filter_map(|(i, p)| {
                matches!(p.source, Source::Context | Source::StatementSeed).then_some(i)
            }),
        )?;
        let native_coverage = [false, true].map(|private| {
            let ordinal = if private { 2 } else { 1 };
            let Some(leaf) = plan.leaves().get(ordinal) else {
                return false;
            };
            leaf.kind()
                == &if private {
                    LeafKind::PrivateProof
                } else {
                    LeafKind::Statement
                }
                && leaf.polynomial_indices().iter().copied().eq(graph
                    .polynomials()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| {
                        (if private {
                            matches!(p.source, Source::ProofPolynomial { .. })
                        } else {
                            matches!(p.source, Source::StatementPolynomial { .. })
                        })
                        .then_some(i)
                    }))
                && leaf.byte_indices().iter().copied().eq(graph
                    .bytes()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| {
                        (matches!(p.source, Source::Context | Source::StatementSeed)
                            || if private {
                                matches!(p.source, Source::ProofAlpha)
                            } else {
                                matches!(p.source, Source::StatementSerial { .. })
                            })
                        .then_some(i)
                    }))
                && leaf.operation_indices().iter().copied().eq(graph
                    .operations()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, op)| {
                        (private && matches!(op, Operation::Norm { .. })).then_some(i)
                    }))
                && (!private || leaf.operation_indices().len() == 6)
        });
        Ok(Self {
            fixed,
            index,
            native_coverage,
            footprints: Mutex::new(Footprints::new()),
        })
    }
    pub(super) fn fixed(&self) -> FixedSourceCensus {
        self.fixed
    }
    pub(super) fn native_coverage(&self, private: bool) -> bool {
        self.native_coverage[usize::from(private)]
    }
    pub(super) fn leaf<'a>(
        &self,
        plan: &'a Plan,
        family: &OperationFamily,
        operations: &[usize],
    ) -> Result<(usize, &'a LeafPlan)> {
        self.index.leaf(plan.leaves(), family, operations)
    }
    pub(super) fn common_bytes(&self) -> &[usize] {
        &self.index.common_bytes[..self.index.byte_count]
    }
    pub(super) fn derived_matches(&self, operations: &[usize], polynomials: &[usize]) -> bool {
        self.index.derived_matches(operations, polynomials)
    }
    pub(super) fn footprint<E>(
        &self,
        family: u8,
        key: [u8; 32],
        storage: NativePlanningStorage,
        build: impl FnOnce() -> core::result::Result<Footprint, E>,
    ) -> core::result::Result<Footprint, E> {
        if let Some(value) = self
            .footprints
            .lock()
            .ok()
            .and_then(|cache| cache.get(family, key, storage))
        {
            return Ok(value);
        }
        // Cache poisoning or eviction falls back to the same checked pure
        // calculation. Failed calculations are never retained.
        let value = build()?;
        if let Ok(mut cache) = self.footprints.lock() {
            cache.insert(Entry {
                family,
                key,
                storage,
                value,
            });
        }
        Ok(value)
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;
    fn leaf(operations: Vec<usize>, polynomials: Vec<usize>) -> LeafPlan {
        LeafPlan {
            kind: LeafKind::Operations(OperationFamily::Ntt { modulus: 17 }),
            operations,
            polynomials,
            bytes: vec![1, 3],
        }
    }
    #[test]
    fn graph_indexes_preserve_exact_order_coverage_and_family() {
        let leaves = [leaf(vec![0, 2], vec![0, 2, 3]), leaf(vec![1], vec![1])];
        let index =
            Index::build(&leaves, [Some(0), Some(1), Some(2), Some(0), None], [1, 3]).unwrap();
        let family = OperationFamily::Ntt { modulus: 17 };
        assert_eq!(index.leaf(&leaves, &family, &[0, 2]).unwrap().0, 0);
        assert!(index.leaf(&leaves, &family, &[0]).is_err());
        assert!(index
            .leaf(&leaves, &OperationFamily::Mul { modulus: 17 }, &[0, 2])
            .is_err());
        assert!(index.derived_matches(&[0, 2], &[0, 2, 3]));
        for bad in [vec![0, 2], vec![0, 2, 2], vec![0, 2, 4], vec![2, 0, 3]] {
            assert!(!index.derived_matches(&[0, 2], &bad));
        }
        assert!(!index.derived_matches(&[2, 0], &[0, 2, 3]));
        assert!(Index::build(&[leaf(vec![0], vec![]), leaf(vec![0], vec![])], [], []).is_err());
        assert!(Index::build(&[], [Some(OPERATIONS)], []).is_err());
        assert!(Index::build(&[], [], [1, 1]).is_err());
    }
    #[test]
    fn footprint_cache_requires_exact_key_family_and_storage_and_is_bounded() {
        use crate::component_tree::native_shape::{NativeDescriptor, NativePlanningStorage};
        use lattica_prover_p3::block_v2::machine::program::{ConstructionLimits, MAX_WIRES};
        let storage = NativePlanningStorage::for_descriptor(
            NativeDescriptor::Sparse(crate::sparse_air::Kind::AlphaPrime39),
            ConstructionLimits {
                max_requested_program_bytes: 2 << 30,
                max_wires: MAX_WIRES,
                max_input_values: 1 << 20,
            },
        )
        .unwrap();
        let value = (
            Requirements::default(),
            Requirements::default(),
            Requirements::default(),
        );
        let mut cache = Footprints::new();
        cache.insert(Entry {
            family: 1,
            key: [1; 32],
            storage,
            value,
        });
        assert_eq!(cache.get(1, [1; 32], storage), Some(value));
        assert_eq!(cache.get(2, [1; 32], storage), None);
        assert_eq!(cache.get(1, [2; 32], storage), None);
        let changed = NativePlanningStorage {
            total_requested_bytes: storage.total_requested_bytes + 1,
            ..storage
        };
        assert_eq!(cache.get(1, [1; 32], changed), None);
        for i in 2..=ENTRIES + 1 {
            cache.insert(Entry {
                family: 1,
                key: [i as u8; 32],
                storage,
                value,
            });
        }
        assert_eq!(cache.get(1, [1; 32], storage), None);
        assert_eq!(cache.entries.len(), ENTRIES);
    }
    #[test]
    #[ignore = "synthetic numeric graph-index profile; serialized CPU validation guard"]
    fn graph_metadata_index_profile() {
        let leaves: Vec<_> = (0..OPERATIONS)
            .step_by(8)
            .map(|first| {
                let operations: Vec<_> = (first..(first + 8).min(OPERATIONS)).collect();
                let polynomials = (0..POLYNOMIALS)
                    .filter(|p| operations.binary_search(&(p % OPERATIONS)).is_ok())
                    .collect();
                leaf(operations, polynomials)
            })
            .collect();
        let started = std::time::Instant::now();
        let index = Index::build(
            &leaves,
            (0..POLYNOMIALS).map(|p| Some(p % OPERATIONS)),
            [1, 3],
        )
        .unwrap();
        let construction_ns = started.elapsed().as_nanos();
        let family = OperationFamily::Ntt { modulus: 17 };
        let iterations = 512;
        let started = std::time::Instant::now();
        let mut legacy = 0usize;
        for _ in 0..iterations {
            for leaf in std::hint::black_box(&leaves) {
                let mut selected = leaves.iter().enumerate().filter(|(_, candidate)| {
                    candidate.kind() == leaf.kind()
                        && candidate.operation_indices() == leaf.operation_indices()
                });
                let (ordinal, found) = selected.next().unwrap();
                assert!(selected.next().is_none());
                assert!(found
                    .polynomial_indices()
                    .iter()
                    .copied()
                    .eq((0..POLYNOMIALS).filter(|p| leaf
                        .operation_indices()
                        .binary_search(&(p % OPERATIONS))
                        .is_ok())));
                legacy += std::hint::black_box(ordinal);
            }
        }
        let legacy_ns = started.elapsed().as_nanos();
        let started = std::time::Instant::now();
        let mut indexed = 0usize;
        for _ in 0..iterations {
            for leaf in std::hint::black_box(&leaves) {
                let (ordinal, found) = index
                    .leaf(&leaves, &family, leaf.operation_indices())
                    .unwrap();
                assert!(index.derived_matches(leaf.operation_indices(), found.polynomial_indices()));
                indexed += std::hint::black_box(ordinal);
            }
        }
        let indexed_ns = started.elapsed().as_nanos();
        assert_eq!(legacy, indexed);
        eprintln!(
            "RINGCT_GRAPH_INDEX_PROFILE {}",
            serde_json::json!({
            "scope":"synthetic numerical indexes only; no prepared-source or proof authority",
            "operations":OPERATIONS,"polynomials":POLYNOMIALS,"leaves":leaves.len(),"iterations":iterations,
            "construction_ns":construction_ns,"legacy_ns":legacy_ns,"indexed_ns":indexed_ns,
            "index_bytes":core::mem::size_of::<Index>(),"retained_analysis_bytes":GraphMetadata::retained_bytes(),
            "checksums_equal":true})
        );
    }
}
