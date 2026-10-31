use super::*;
use crate::{
    component_tree::{owned_shake::request_merge::RequestClosurePlan, EndpointContext},
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Admission, Policy, ReservedShakeRequest, ShakeRequestPlan},
};

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    })
}

fn one(category: Category, host: u64, device: u64) -> Requirements {
    Requirements::single(category, Bytes { host, device })
}

#[test]
fn bank_maximum_keeps_each_category_and_each_memory_domain() {
    let left = sum(
        one(Category::SymbolicCompiler, 19, 3),
        one(Category::CompilerInputs, 5, 17),
    )
    .unwrap();
    let right = sum(
        one(Category::SymbolicCompiler, 7, 23),
        one(Category::IndependentVerifier, 31, 11),
    )
    .unwrap();
    let result = maximum(left, right).unwrap();
    assert_eq!(
        result.get(Category::SymbolicCompiler),
        Bytes {
            host: 19,
            device: 23
        }
    );
    assert_eq!(
        result.get(Category::CompilerInputs),
        Bytes {
            host: 5,
            device: 17
        }
    );
    assert_eq!(
        result.get(Category::IndependentVerifier),
        Bytes {
            host: 31,
            device: 11
        }
    );
    assert_eq!(
        result.total().unwrap(),
        Bytes {
            host: 55,
            device: 51
        }
    );
    assert_eq!(maximum(right, left).unwrap(), result);
    assert_eq!(maximum(result, result).unwrap(), result);
    // Each source request fits independently, but their componentwise maximum
    // does not fit the representation. Never wrap to an admissible quota.
    assert_eq!(
        maximum(
            one(Category::SymbolicCompiler, u64::MAX, 0),
            one(Category::CompilerInputs, 1, 0),
        ),
        Err(Error::Overflow)
    );
    assert_eq!(
        sum(
            one(Category::SymbolicCompiler, 0, u64::MAX),
            one(Category::SymbolicCompiler, 0, 1),
        ),
        Err(Error::Overflow)
    );
}

#[test]
fn bank_original_reunification_preserves_category_peak_and_refuses_foreign_worker() {
    let ledger = ledger();
    let foreign = self::ledger();
    let requirements = sum(
        one(Category::SymbolicCompiler, 41, 7),
        one(Category::CompilerInputs, 13, 17),
    )
    .unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let inputs = original
        .split(one(Category::CompilerInputs, 13, 17))
        .unwrap();
    let before = ledger.snapshot();
    let original = reunite(original, inputs).unwrap();
    assert_eq!(original.requirements(), requirements);
    assert_eq!(ledger.snapshot(), before);
    let other = foreign.admit_phase(requirements).unwrap();
    assert!(matches!(reunite(original, other), Err(Error::Authority)));
    // The failed helper is terminal and returns no retry owner or bank. Both
    // original claims are released, without altering either recorded peak.
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, before.peak);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
}

fn context() -> EndpointContext {
    EndpointContext {
        context: [11; 32],
        statement: [Val::from_u64(13); 4],
        input: [Val::from_u64(17); 4],
        output: [Val::from_u64(19); 4],
    }
}

fn owner(ledger: &Ledger) -> ReservedShakeRequest {
    let input = [23; 16_416];
    let plan = ShakeRequestPlan::new_active_opt_validate_v1(
        [7; 32],
        9,
        0,
        &input,
        137,
        Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

#[test]
#[ignore = "serialized exact five-leaf/18-height bank source inspection; zero proofs"]
fn exact_hashx_compiler_bank_admits_original_maximum_and_refuses_short_capacity() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_BANK_SOURCE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = owner(&ledger);
    let groups: [_; LEAF_COUNT] = core::array::from_fn(|ordinal| {
        GroupCompilePlan::new(
            owner.request(),
            ShakeWrapperLayout::PairedV1,
            ordinal,
            context(),
        )
        .unwrap()
    });
    let plan = RequestClosurePlan::new(&owner, context());
    let original = ledger.admit_phase(plan.requirements().unwrap()).unwrap();
    let mut request = plan
        .open(original, &ledger)
        .unwrap_or_else(|_| panic!("original request metadata"));
    for group in &groups {
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, &ledger)
            .unwrap();
        let original = ledger.admit_phase(plan.requirements()).unwrap();
        let source = plan.inspect(original, &ledger).unwrap();
        request = request
            .retain_source(group, source, &ledger)
            .unwrap_or_else(|_| panic!("exact original leaf source"));
    }
    let plan = super::super::super::super::super::ParentSourcePlan::new(&request, &ledger).unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    let source = plan.inspect(original, &ledger).unwrap();
    let before = ledger.snapshot().current;
    let refs = groups.each_ref();
    let bank = CompilerBank::reserve_before_native(&source, refs, &ledger).unwrap();
    bank.check(&ledger, Requirements::default()).unwrap();
    let whole = bank.whole;
    for group in &groups {
        assert_eq!(maximum(whole, group.requirements()).unwrap(), whole);
    }
    assert_eq!(
        maximum(whole, Storage::source().unwrap().complete).unwrap(),
        whole
    );
    let verifier = VerificationPlan::component_requirement().get(Category::IndependentVerifier);
    let bank_verifiers = whole.get(Category::IndependentVerifier);
    assert!(bank_verifiers.host >= 2 * verifier.host);
    assert!(bank_verifiers.device >= 2 * verifier.device);
    assert!(bank.check(&foreign, Requirements::default()).is_err());
    drop(bank);
    assert_eq!(ledger.snapshot().current, before);
    assert!(CompilerBank::reserve_before_native(&source, refs, &foreign).is_err());
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let mut swapped = refs;
    swapped.swap(0, 1);
    assert!(CompilerBank::reserve_before_native(&source, swapped, &ledger).is_err());
    assert_eq!(ledger.snapshot().current, before);
    let bank = CompilerBank::reserve_before_native(&source, refs, &ledger).unwrap();
    let failure = match bank.compile_leaf(0, [None, None], &ledger) {
        Err(failure) => failure,
        Ok(_) => panic!("missing original native children cannot compile"),
    };
    assert!(matches!(failure, Failure::Compilation { .. }));
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + caller_requirement().unwrap().total().unwrap().host
    );
    drop(failure);
    assert_eq!(ledger.snapshot().current, before);
    let bank = CompilerBank::reserve_before_native(&source, refs, &ledger).unwrap();
    assert!(matches!(
        bank.compile_leaf(LEAF_COUNT, [None, None], &ledger),
        Err(Failure::Admission(Error::Source))
    ));
    assert_eq!(ledger.snapshot().current, before);

    let required = sum(whole, caller_requirement().unwrap())
        .unwrap()
        .total()
        .unwrap();
    assert_eq!(required.device, 0);
    let room = ledger.snapshot().allowance.host - before.host;
    let exact_filler = room.checked_sub(required.host).unwrap();
    let filler = ledger
        .admit_phase(one(Category::PhaseScratch, exact_filler + 1, 0))
        .unwrap();
    let full = ledger.snapshot().current;
    assert!(matches!(
        CompilerBank::reserve_before_native(&source, refs, &ledger),
        Err(Error::Capacity)
    ));
    assert_eq!(ledger.snapshot().current, full);
    drop(filler);
    let filler = ledger
        .admit_phase(one(Category::PhaseScratch, exact_filler, 0))
        .unwrap();
    let mut bank = CompilerBank::reserve_before_native(&source, refs, &ledger).unwrap();
    assert_eq!(
        ledger.snapshot().current.host,
        ledger.snapshot().allowance.host
    );
    let exact = ledger.snapshot();
    let missing = bank
        .original
        .split(one(Category::PhaseScratch, 1, 0))
        .unwrap();
    assert!(matches!(
        bank.check(&ledger, Requirements::default()),
        Err(Error::Authority)
    ));
    bank.original = reunite(bank.original, missing).unwrap();
    bank.check(&ledger, Requirements::default()).unwrap();
    assert_eq!(ledger.snapshot(), exact);
    drop(bank);
    drop(filler);
    assert_eq!(ledger.snapshot().current, before);
    eprintln!(
        "owned_hashx_compiler_bank source_leaves=5 source_parents=4 original_host_bytes={} caller_host_bytes={} native_proofs=0 recursive_proofs=0 same_attempt_sequence=false workflow_admitted=false",
        whole.total().unwrap().host,
        caller_requirement().unwrap().total().unwrap().host,
    );
    drop(source);
    let refused = match request.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    assert!(refused.report().missing[1..].iter().all(Option::is_some));
    drop(refused);
    drop(groups);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
