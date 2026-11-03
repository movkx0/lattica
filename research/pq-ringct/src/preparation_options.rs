//! Production uses all qualified optimizations. Selectors exist only in the
//! test binary for source-bound metadata ablations; they never permit CPU work
//! in a GPU-required witness scope.
#[cfg(test)]
pub(crate) fn variant() -> &'static str {
    match std::env::var("LATTICA_RINGCT_METADATA_HASH_VARIANT").as_deref() {
        Err(_) | Ok("all") => "all", Ok("reference") => "reference", Ok("nodes") => "nodes",
        Ok("endpoints") => "endpoints", Ok("fields") => "fields",
        _ => panic!("invalid metadata hash variant"),
    }
}
#[cfg(test)]
static ADOPTIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) fn endpoint_adopted() { ADOPTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
#[cfg(test)]
pub(crate) fn endpoint_adoptions() -> usize { ADOPTIONS.load(std::sync::atomic::Ordering::Relaxed) }
fn enabled(name: &str) -> bool {
    #[cfg(test)]
    { let choice = variant(); choice == "all" || choice == name }
    #[cfg(not(test))]
    { let _ = name; true }
}
pub(crate) fn node_batches() -> bool { enabled("nodes") }
pub(crate) fn endpoint_reuse() -> bool { enabled("endpoints") }
pub(crate) fn field_batches() -> bool { enabled("fields") }

#[cfg(test)]
pub(crate) fn reuse_variant() -> &'static str {
    match std::env::var("LATTICA_RINGCT_METADATA_REUSE_VARIANT").as_deref() {
        Err(_) | Ok("all") => "all", Ok("baseline") => "baseline", Ok("structure") => "structure",
        Ok("verifier") => "verifier", Ok("arithmetic") => "arithmetic",
        _ => panic!("invalid metadata reuse variant"),
    }
}
fn reuse_enabled(name: &str) -> bool {
    #[cfg(test)] { let selected = reuse_variant(); selected == "all" || selected == name }
    #[cfg(not(test))] { let _ = name; true }
}
pub(crate) fn structural_reuse() -> bool { reuse_enabled("structure") }
pub(crate) fn verifier_reuse() -> bool { reuse_enabled("verifier") }
pub(crate) fn vector_arithmetic() -> bool { reuse_enabled("arithmetic") }
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum ReuseCounter { StructuralTraversals, FullInventories, ExactComparisons, PreparedStructures,
    VerifierHits, VerifierRecordings, VerifierOverflow, VectorRecipes }
#[cfg(test)]
static REUSE_COUNTS: [std::sync::atomic::AtomicU64; 8] = [const { std::sync::atomic::AtomicU64::new(0) }; 8];
pub(crate) fn reuse_count(counter: ReuseCounter) {
    #[cfg(test)] { REUSE_COUNTS[counter as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    #[cfg(not(test))] { let _ = counter; }
}
#[cfg(test)]
pub(crate) fn reuse_counts() -> [u64; 8] { core::array::from_fn(|i| REUSE_COUNTS[i].load(std::sync::atomic::Ordering::Relaxed)) }

#[cfg(test)]
pub(crate) fn next_variant() -> &'static str {
    match std::env::var("LATTICA_RINGCT_METADATA_NEXT_VARIANT").as_deref() {
        Err(_) | Ok("all") => "all", Ok("baseline") => "baseline",
        Ok("field_hash") => "field_hash", Ok("encoding") => "encoding",
        Ok("case_cache") => "case_cache", _ => panic!("invalid metadata next variant"),
    }
}
fn next_enabled(name: &str) -> bool {
    #[cfg(test)] { let selected = next_variant(); selected == "all" || selected == name }
    #[cfg(not(test))] { let _ = name; true }
}
#[cfg(test)]
pub(crate) fn cooperative_fields() -> bool { next_enabled("field_hash") }
pub(crate) fn buffered_encoding() -> bool { next_enabled("encoding") }
#[cfg(test)]
pub(crate) fn case_verifier_cache() -> bool { next_enabled("case_cache") }
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum NextCounter { ExpressionAllocations, ShapeAllocations, CaseHits, CaseRecordings }
#[cfg(test)]
static NEXT_COUNTS: [std::sync::atomic::AtomicU64; 4] = [const { std::sync::atomic::AtomicU64::new(0) }; 4];
pub(crate) fn next_count(counter: NextCounter) {
    #[cfg(test)] { NEXT_COUNTS[counter as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    #[cfg(not(test))] { let _ = counter; }
}
#[cfg(test)]
pub(crate) fn next_counts() -> [u64; 4] {
    core::array::from_fn(|i| NEXT_COUNTS[i].load(std::sync::atomic::Ordering::Relaxed))
}
