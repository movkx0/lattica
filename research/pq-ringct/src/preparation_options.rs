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

#[cfg(test)]
pub(crate) fn pipeline_variant() -> &'static str {
    match std::env::var("LATTICA_RINGCT_METADATA_PIPELINE_VARIANT").as_deref() {
        Err(_) | Ok("all") => "all", Ok("baseline") => "baseline",
        Ok("field_hash") => "field_hash", Ok("registration") => "registration",
        Ok("arithmetic") => "arithmetic", _ => panic!("invalid metadata pipeline variant"),
    }
}
fn pipeline_enabled(name: &str) -> bool {
    #[cfg(test)] { let selected = pipeline_variant(); selected == "all" || selected == name }
    #[cfg(not(test))] { let _ = name; true }
}
pub(crate) fn paired_fields() -> bool { pipeline_enabled("field_hash") }
pub(crate) fn parallel_registration() -> bool { pipeline_enabled("registration") }
pub(crate) fn fused_arithmetic() -> bool { pipeline_enabled("arithmetic") }

#[cfg(test)]
pub(crate) fn parallel_variant() -> &'static str {
    match std::env::var("LATTICA_RINGCT_METADATA_PARALLEL_VARIANT").as_deref() {
        Err(_) | Ok("all") => "all", Ok("serial") => "serial",
        Ok("registration") => "registration", Ok("crypto") => "crypto",
        Ok("native") => "native", _ => panic!("invalid metadata parallel variant"),
    }
}
pub(crate) fn metadata_workers_enabled(family: &str) -> bool {
    #[cfg(test)]
    { let selected = parallel_variant(); selected == "all" || selected == family }
    #[cfg(not(test))] { let _ = family; true }
}
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum PipelineCounter { RegistrationEncodeNs, RegistrationHashNs, ParallelRegistrations, FusedPairs }
#[cfg(test)]
static PIPELINE_COUNTS: [std::sync::atomic::AtomicU64; 4] = [const { std::sync::atomic::AtomicU64::new(0) }; 4];
pub(crate) fn pipeline_count(counter: PipelineCounter, value: u64) {
    #[cfg(test)] { PIPELINE_COUNTS[counter as usize].fetch_add(value, std::sync::atomic::Ordering::Relaxed); }
    #[cfg(not(test))] { let _ = (counter, value); }
}
#[cfg(test)]
pub(crate) fn pipeline_counts() -> [u64; 4] {
    core::array::from_fn(|i| PIPELINE_COUNTS[i].load(std::sync::atomic::Ordering::Relaxed))
}
pub(crate) struct PipelineSpan {
    #[cfg(test)] started: Option<std::time::Instant>,
    #[cfg(test)] counter: PipelineCounter,
}
impl PipelineSpan {
    pub(crate) fn new(counter: PipelineCounter) -> Self {
        #[cfg(test)] { Self { counter, started: (std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1")).then(std::time::Instant::now) } }
        #[cfg(not(test))] { let _ = counter; Self {} }
    }
}
impl Drop for PipelineSpan {
    fn drop(&mut self) {
        #[cfg(test)] if let Some(started) = self.started {
            pipeline_count(self.counter, u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
    }
}

#[cfg(test)]
pub(crate) const CONSTRUCTOR_NAMES: [&str; 111] = ["source_native_plans", "uniform_native_plans", "sparse_native_plans", "transcript_native_plans", "affine_native_plans", "ntt_native_plans", "mul_native_plans", "g_bound_native_plans", "permutation_native_plans", "linear_map_native_plans", "source_blueprints", "affine_blueprints", "ntt_blueprints", "mul_blueprints", "g_bound_blueprints", "permutation_blueprints", "linear_map_blueprints", "source_compiler_plans", "affine_compiler_plans", "ntt_compiler_plans", "mul_compiler_plans", "g_bound_compiler_plans", "permutation_compiler_plans", "linear_map_compiler_plans", "source_outer_plans", "affine_outer_plans", "ntt_outer_plans", "mul_outer_plans", "g_bound_outer_plans", "permutation_outer_plans", "linear_map_outer_plans", "fixed_plans", "fixed_outer_plans", "shake_plans", "aes_plans", "parameters_plans", "auxiliary_plans", "equality_plans", "source_native_outputs", "source_native_preissues", "uniform_native_outputs", "uniform_native_preissues", "sparse_native_outputs", "sparse_native_preissues", "transcript_native_outputs", "transcript_native_preissues", "affine_native_outputs", "affine_native_preissues", "ntt_native_outputs", "ntt_native_preissues", "mul_native_outputs", "mul_native_preissues", "g_bound_native_outputs", "g_bound_native_preissues", "permutation_native_outputs", "permutation_native_preissues", "linear_map_native_outputs", "linear_map_native_preissues", "source_compiled_outputs", "source_outer_outputs", "source_outer_preissues", "affine_compiled_outputs", "affine_outer_outputs", "affine_outer_preissues", "ntt_compiled_outputs", "ntt_outer_outputs", "ntt_outer_preissues", "mul_compiled_outputs", "mul_outer_outputs", "mul_outer_preissues", "g_bound_compiled_outputs", "g_bound_outer_outputs", "g_bound_outer_preissues", "permutation_compiled_outputs", "permutation_outer_outputs", "permutation_outer_preissues", "linear_map_compiled_outputs", "linear_map_outer_outputs", "linear_map_outer_preissues", "fixed_compiled_outputs", "fixed_outer_outputs", "fixed_outer_preissues", "parameters_compiled_outputs", "parameters_outer_outputs", "parameters_preissues", "auxiliary_compiled_outputs", "auxiliary_outer_outputs", "auxiliary_preissues", "equality_compiled_outputs", "equality_outer_outputs", "equality_preissues", "shake_endpoint_outputs", "shake_native_outputs", "shake_compiled_outputs", "shake_outer_outputs", "shake_native_preissues", "shake_outer_preissues", "shake_request_outputs", "shake_reports", "aes_endpoint_outputs", "aes_native_outputs", "aes_compiled_outputs", "aes_outer_outputs", "aes_native_preissues", "aes_outer_preissues", "aes_request_outputs", "aes_reports", "derive_metadata_shake", "prepare_metadata_shake_endpoints", "derive_metadata_aes", "prepare_metadata_aes_endpoints"];
#[cfg(test)]
static CONSTRUCTOR_NS: [std::sync::atomic::AtomicU64; 111] = [const { std::sync::atomic::AtomicU64::new(0) }; 111];
pub(crate) fn timed_constructor<T>(family: usize, operation: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    let start = (std::env::var("LATTICA_RINGCT_METADATA_PREPARATION_DETAIL").as_deref() == Ok("1")).then(std::time::Instant::now);
    let result = operation();
    #[cfg(test)] if let Some(start) = start {
        CONSTRUCTOR_NS[family].fetch_add(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX), std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(test))] let _ = family;
    result
}
#[cfg(test)]
pub(crate) fn constructor_ns() -> [u64; 111] {
    core::array::from_fn(|i| CONSTRUCTOR_NS[i].load(std::sync::atomic::Ordering::Relaxed))
}
