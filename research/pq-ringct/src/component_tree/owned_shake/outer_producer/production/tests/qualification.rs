//! Hybrid component qualification: fresh CPU native fixtures and compiler,
//! followed by the actual owned GPU outer producer and independent CPU verify.
//! This is deliberately not a fresh all-GPU RingCT workflow measurement.
use super::super::*;
use crate::{
    component_tree::{owned_shake::GroupCompilePlan, EndpointContext, Val},
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{
        NativeProductionPlan, Policy as NativePolicy, ShakeRequestPlan, ShakeWrapperLayout,
    },
    shake_air,
};
use p3_field::PrimeCharacteristicRing;

#[test]
#[ignore = "serialized process guard, exclusive OpenCL and explicit hybrid outer qualification required"]
fn actual_owned_gpu_singleton_pair_and_odd_tail_verify_and_release() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_OUTER_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    // Fixed harness input/context/log backing only. The existing process guard
    // separately bounds real CPU fixture proving scratch; this token does not
    // confer native GPU admission or characterize its memory use.
    let fixture = ledger
        .reserve(
            Category::CompilerInputs,
            Bytes {
                host: 1 << 20,
                device: 0,
            },
        )
        .unwrap();
    let input = [31u8; 137];
    let request_plan = ShakeRequestPlan::new(
        [7; 32],
        0,
        0,
        &input,
        137,
        NativePolicy {
            maximum_shake_permutations: 1,
            ..NativePolicy::default()
        },
    )
    .unwrap();
    let request_token = ledger.admit_phase(request_plan.requirements()).unwrap();
    let request = request_plan.construct(request_token, &ledger).unwrap();
    assert_eq!(request.request().segments().len(), 3);
    let output_bytes = request.request().output_bytes_hint();
    let context = EndpointContext {
        context: [17; 32],
        statement: [Val::from_u64(19); 4],
        input: shake_air::commit_bytes(shake_air::SHAKE_INPUT_DOMAIN, &input),
        output: shake_air::commit_bytes(shake_air::SHAKE_OUTPUT_DOMAIN, &output_bytes),
    };
    drop(output_bytes);
    let request_only = ledger.snapshot().current;
    for (layout, ordinal) in [
        (ShakeWrapperLayout::Singleton, 0),
        (ShakeWrapperLayout::PairedV1, 0),
        (ShakeWrapperLayout::PairedV1, 1),
    ] {
        let started = std::time::Instant::now();
        let plan =
            GroupCompilePlan::new(request.request(), layout, ordinal, context.clone()).unwrap();
        let span = plan.span();
        let children = std::array::from_fn(|offset| {
            if offset >= span.segment_count {
                return None;
            }
            let index = span.first_segment + offset;
            let native = NativeProductionPlan::new(request.request(), index).unwrap();
            let token = ledger.admit_phase(native.requirement()).unwrap();
            Some(
                native
                    .claim_for(request.request(), index, token, &ledger)
                    .unwrap()
                    .produce_cpu_fixture()
                    .unwrap(),
            )
        });
        let token = ledger.admit_phase(plan.requirements()).unwrap();
        let compiled = plan
            .compile_cpu_reference(children, token, &ledger)
            .unwrap();
        let source_only = ledger.snapshot().current;
        let summary = compiled.summary;
        let preparation_ns = started.elapsed().as_nanos();
        // SAFETY: this ignored qualification is run only under the existing
        // serialized process/GPU guard. It does not mutate the environment;
        // that guard spans preflight, dispatch, verification and retirement.
        let prepared = unsafe { PreparedOuter::new(&compiled, &request, &ledger) }.unwrap();
        let admitted = ledger.snapshot();
        assert!(admitted.current.host <= 32 << 30 && admitted.current.device <= 8 << 30);
        // SAFETY: the same externally serialized immutable environment span.
        let output = unsafe { prepared.produce() }.unwrap();
        assert!(output.belongs_to(&ledger));
        let report = output.report();
        assert!(report.independent_verification_complete);
        assert!(!report.authenticated_source_key);
        assert!(!report.transaction_context_authenticated);
        assert!(!report.native_production_admitted && !report.workflow_admitted);
        assert_eq!(ledger.snapshot().current.device, 0);
        eprintln!("owned_outer_hybrid layout={layout:?} ordinal={ordinal} native_cpu_proofs={} recursive_gpu_proofs=1 active_rows={} padded_rows={} fixture_preparation_ns={preparation_ns} setup_ns={} proving_ns={} cpu_verification_ns={} component_elapsed_ns={} host_peak={} device_peak={} full_gpu_workflow=false", span.segment_count, summary.active_rows, summary.padded_rows, report.setup_elapsed_ns.unwrap(), report.proving_elapsed_ns.unwrap(), report.cpu_verification_elapsed_ns.unwrap(), started.elapsed().as_nanos(), admitted.peak.host, admitted.peak.device);
        drop(output);
        assert_eq!(ledger.snapshot().current, source_only);
        drop(compiled);
        assert_eq!(ledger.snapshot().current, request_only);
    }
    drop(request);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
