use super::*;

#[test]
fn terminal_owner_does_not_retain_idle_runtime_allowance() {
    let terminal = memory::terminal_requirements().unwrap().total().unwrap();
    let runtime = memory::runtime_requirements().unwrap().total().unwrap();
    assert_eq!(terminal.device, 0);
    assert!(terminal.host < 1 << 20);
    assert!(runtime.host > 8 << 30);
    assert!(runtime.device > 0 && runtime.device < 8 << 30);
}

#[test]
fn source_census_does_not_replace_native_output_with_the_api_ceiling() {
    let output = GenerationContextPlan::minimum_output_requirements().unwrap();
    assert!(output.get(Category::NativeProof).host > 293_312);
    assert!(output.total().unwrap().host < 1 << 20);
    assert_eq!(output.total().unwrap().device, 0);
}

#[test]
fn generation_plan_preserves_exact_case_and_original_resource_limits() {
    if cfg!(debug_assertions) { return; }
    let limits = Limits { host_bytes: 32 << 30, device_bytes: 8 << 30, max_rows: 1 << 20 };
    for expected in [3, 4] {
        for profile in crate::host_memory_profile::HostMemoryProfile::ALL {
            let plan = GenerationContextPlan::new(expected,
                Limits { host_bytes: profile.worker_bytes(), ..limits }).unwrap();
            assert_eq!(plan.total_requirements().unwrap(),
                memory::combine(plan.runtime_requirements(), plan.terminal_requirements()).unwrap());
        }
    }
    for expected in [0, 1, 2, 5, usize::MAX] {
        assert!(GenerationContextPlan::new(expected, limits).is_err());
    }
    assert!(GenerationContextPlan::new(3, Limits { host_bytes: (32 << 30) + 1, ..limits }).is_err());
    assert!(GenerationContextPlan::new(3, Limits { device_bytes: (8 << 30) + 1, ..limits }).is_err());
    assert!(GenerationContextPlan::new(3, Limits { max_rows: (1 << 20) + 1, ..limits }).is_err());
}
