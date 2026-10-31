//! Coordinator-only real-device checks for the reserved research entry.
//! No arbitrary callback, numeric operation allowance or failure switch is
//! exposed. These checks do not claim native/recursive proof completion.
use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use crate::opencl::{Limits, PendingRuntime};
use core::mem::size_of;
use lattica_prover_p3::block_v2::native_gpu::{
    operations_arithmetic::{ArithmeticOperationSpec, SignedOperation},
    RawGraphOperationStorage,
};

const HOST: u64 = 32 << 30;
const DEVICE: u64 = 8 << 30;

fn limits() -> Limits {
    Limits {
        host_bytes: HOST,
        device_bytes: DEVICE,
        max_rows: 1 << 20,
    }
}

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host,
        device: DEVICE,
    })
}

/// Exact one-word signed negation geometry. The private spec constructor has
/// four metadata words; input/output/status each have one u64. Both calls use
/// this same shape, and scrub/fence before the next call. Runtime/kernel/error
/// ownership stays with A013; Run/report ownership stays with ReportClaim.
struct NegationClaim {
    reservation: Reservation,
}
impl NegationClaim {
    const WORDS: usize = 1 + 4 + 1 + 1;
    const STAGING: usize = Self::WORDS * size_of::<u64>();

    fn reserve(ledger: &Ledger) -> Result<Self> {
        let wrappers = RawGraphOperationStorage::fixed()?;
        let host = wrappers
            .requested_bytes()
            .checked_add(Self::STAGING)
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()))
            .ok_or("fixed negation claim overflow")?;
        let reservation = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: host as u64,
                    device: Self::STAGING as u64,
                },
            )
            .map_err(|_| "fixed negation reservation refused")?;
        Ok(Self { reservation })
    }
}

/// A closed two-call sequence: negate seven successfully, then reject the
/// mathematical overflow from negating i64::MIN on the GPU itself. Neither
/// input is a caller parameter, and no host rejection or fake flag substitutes
/// for the second kernel's exact status word.
fn fixed_negation_sequence(session: &Session, ledger: &Ledger) -> Result<()> {
    let runtime = session
        .check_reserved_runtime(ledger)
        .map_err(|_| "fixed raw sequence requires original runtime")?;
    let report_claim = ReportClaim::reserve(ledger)?;
    let raw_claim = NegationClaim::reserve(ledger)?;
    if !raw_claim.reservation.belongs_to(ledger) {
        return Err("fixed raw sequence claim changed ledger");
    }
    let charged = ledger.snapshot().current;
    // The operation metadata allocation occurs after the original raw claim.
    let spec = ArithmeticOperationSpec::signed(SignedOperation::Negate, 1)
        .map_err(|_| "fixed negation source descriptor refused")?;
    if spec.raw_input_words() != 1 || spec.output_words() != 1 {
        return Err("fixed negation geometry changed");
    }
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    };
    let result = native_gpu::with_operations(NegationClaim::STAGING, request, |operation| {
        assert_eq!(ledger.snapshot().current, charged);
        operation.arithmetic_output(&spec, &[7])
    });
    match result {
        Ok((output, report)) => {
            let accepted = super::super::validate_preparation_report(&report).is_ok();
            let exact_output = output.as_slice() == [(-7i64) as u64];
            drop(report);
            drop(output);
            if !accepted || !exact_output {
                return Err("fixed negation did not complete the exact GPU relation");
            }
        }
        Err(error) => {
            drop(error);
            return Err("fixed negation unexpectedly failed");
        }
    }
    assert_eq!(ledger.snapshot().current, charged);
    let result = native_gpu::with_operations(NegationClaim::STAGING, request, |operation| {
        assert_eq!(ledger.snapshot().current, charged);
        operation.arithmetic_output(&spec, &[i64::MIN as u64])
    });
    match result {
        Err(error) => {
            let exact_status =
                error == "raw arithmetic opcode 5 invalid input at work item 0, status 2";
            drop(error); // original runtime/raw/report owners are all still live
            if !exact_status {
                return Err("fixed overflow did not return the exact GPU status");
            }
        }
        Ok((output, report)) => {
            drop(report);
            drop(output);
            return Err("fixed overflow was incorrectly accepted");
        }
    }
    assert_eq!(ledger.snapshot().current, charged);
    drop(spec);
    drop(raw_claim);
    drop(report_claim);
    drop(runtime);
    Ok(())
}

#[test]
#[ignore = "dedicated immutable env-clear RTX 5080 worker; exact A013 policy; coordinator only"]
fn gpu_reserved_session_raw_negation_and_overflow_cleanup() {
    let original = ledger(HOST);
    let unrelated = ledger(HOST);
    let pending = PendingRuntime::reserve(&original, limits()).unwrap();
    let startup = pending.reserved_bytes();
    // SAFETY: the coordinator launches this sole test in a dedicated process
    // with A013's fixed immutable environment and existing resource guard.
    let session = unsafe { pending.start().unwrap() };
    assert!(fixed_negation_sequence(&session, &unrelated).is_err());
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
    assert_eq!(original.snapshot().current, startup);
    fixed_negation_sequence(&session, &original).unwrap();
    assert_eq!(original.snapshot().current, startup);
    {
        let _runtime = session.check_reserved_runtime(&original).unwrap();
        assert_eq!(original.snapshot().current, startup);
    }
    let retired = session.finish_reserved().unwrap();
    assert_eq!(retired.managed_live_bytes, 0);
    assert_eq!(retired.host_tree_live_bytes, 0);
    assert!(retired.lease_released);
    assert_eq!(original.snapshot().current, Bytes::ZERO);
    eprintln!("reserved_raw_runtime success=exact_gpu_negation failure=exact_gpu_overflow_status original_ledger_retired=true proof_completion=false");
}

#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "fresh native CPU fixture then complete raw GPU graph; fixed guard; coordinator only"]
fn gpu_reserved_session_genuine_source_graph_original_owners() {
    use crate::native::{self, FixtureAmounts, NativeFixture};
    use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};
    // Reference fixture creation and its built-in independent C verification
    // precede the admitted raw preparation scope. This is not a full GPU spend
    // creation or complete-workflow timing. The real retained fixture remains
    // separately charged by subtracting it before constructing the worker ledger.
    let context = [71; 32];
    let setup_seed = [29; 32];
    let fixture = native::generate_fixture_with_setup_seed(
        context,
        setup_seed,
        3,
        FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
    )
    .unwrap();
    assert_eq!(fixture.statement.len(), STATEMENT_BYTES);
    assert_eq!(fixture.proof.len(), PROOF_BYTES);
    let fixture_backing = fixture
        .statement
        .capacity()
        .checked_add(fixture.proof.capacity())
        .unwrap()
        .checked_add(size_of::<NativeFixture>())
        .unwrap() as u64;
    let original = ledger(HOST.checked_sub(fixture_backing).unwrap());
    let pending = PendingRuntime::reserve(&original, limits()).unwrap();
    let startup = pending.reserved_bytes();
    let source = Construction::new(
        setup_seed,
        context,
        &fixture.statement,
        &fixture.proof,
        &original,
    )
    .unwrap();
    let before_start = original.snapshot().current;
    assert!(before_start.host > startup.host);
    assert_eq!(before_start.device, startup.device + 1_844_280);
    // SAFETY: same dedicated immutable A013 process contract through cleanup.
    let session = unsafe { pending.start().unwrap() };
    assert_eq!(original.snapshot().current, before_start);
    let graph = prepare_owned_graph(&session, source, &original).unwrap();
    assert!(graph.belongs_to(&original));
    let after_callback = original.snapshot().current;
    assert!(after_callback.host > startup.host);
    assert!(after_callback.host < before_start.host);
    assert_eq!(after_callback.device, startup.device);
    drop(graph);
    assert_eq!(original.snapshot().current, startup);
    let retired = session.finish_reserved().unwrap();
    assert_eq!(retired.managed_live_bytes, 0);
    assert_eq!(retired.host_tree_live_bytes, 0);
    assert!(retired.lease_released);
    assert_eq!(original.snapshot().current, Bytes::ZERO);
    drop(fixture);
    eprintln!("reserved_raw_graph cpu_reference_fixture=true strict_gpu_preparation=true original_owners_retired=true source_graph_cpu_differential=false proof_completion=false complete_workflow_timing=false");
}
