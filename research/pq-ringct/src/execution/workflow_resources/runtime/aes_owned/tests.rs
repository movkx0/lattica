use super::*;

#[cfg(not(debug_assertions))]
#[test]
fn aes_host_tree_profile_reduces_pcs_inside_original_backend_and_keeps_row_cap() {
    use crate::graph_crypto::OwnedAesNativeSource;
    let request = crate::graph_crypto::owned_test_requests::aes_partition();
    let limits = crate::opencl::Limits { host_bytes: 32 << 30, device_bytes: 8 << 30, max_rows: 1 << 20 };
    let backend = Bytes { host: 24 << 30, device: 8 << 30 };
    for index in 0..request.segments().len() {
        let source = OwnedAesNativeSource::new(&request, index).unwrap();
        let plan = NativePartitionPlan::new(&source, limits, backend).unwrap();
        assert!(plan.startup.get(Category::PhaseScratch).host >= 8 << 30);
        assert!(plan.pcs.get(Category::PhaseScratch).host < 16 << 30);
        assert_eq!(combine(combine(plan.startup, plan.wrappers).unwrap(), plan.pcs)
            .unwrap().total().unwrap(), backend);
        assert!(plan.complete.get(Category::SymbolicCompiler).host > 0);
        assert_eq!(plan.complete.get(Category::IndependentVerifier).host, 64 << 20);
        assert!(NativePartitionPlan::new(&source, limits, Bytes { host: 8 << 30, ..backend }).is_err());
        assert!(NativePartitionPlan::new(&source, limits, Bytes { host: (24 << 30) + 1, ..backend }).is_err());
        assert!(NativePartitionPlan::new(&source, limits, Bytes { device: (8 << 30) - 1, ..backend }).is_err());
        assert!(NativePartitionPlan::new(&source, crate::opencl::Limits { max_rows: 1, ..limits }, backend).is_err());
    }
}
