use super::*;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::block_v2::typed_recursive::{self, Policy};
use crate::spill_alloc::allocation_requests::{measure, measure_all, Requests};
use p3_air::Air;
use p3_commit::PolynomialSpace;
use p3_field::PrimeCharacteristicRing;

fn bounded(requests: Requests, limit: usize) {
    assert!(!requests.overflow);
    assert!(
        requests.bytes <= limit,
        "{requests:?}, source limit={limit}"
    );
}

#[test]
#[ignore = "requires serial process-wide allocation observation"]
fn global_observer_includes_every_rayon_worker() {
    rayon::broadcast(|_| {}); // Pool creation/runtime is outside the payload model.
    let (per_thread, observed) = measure_all(|| {
        rayon::broadcast(|context| {
            let bytes = (context.index() + 1) << 20;
            let (data, requests) = measure(|| vec![context.index() as u8; bytes]);
            std::hint::black_box(&data);
            assert_eq!(requests.bytes, bytes);
            assert_eq!(requests.calls, 1);
            requests
        })
    });
    let worker_bytes: usize = per_thread.iter().map(|r| r.bytes).sum();
    assert!(!observed.overflow && observed.bytes >= worker_bytes);
    assert!(observed.calls >= per_thread.len());
    assert_eq!(per_thread.len(), rayon::current_num_threads());
    eprintln!("wallet_scratch_global_observer workers={} worker_bytes={worker_bytes} observed_bytes={} calls={}", per_thread.len(), observed.bytes, observed.calls);
}

#[test]
fn all_geometry_plans_are_allocation_free_and_have_exact_admission_boundaries() {
    let mut largest_peak = 0;
    let mut largest_cumulative = 0;
    for htlc in [false, true] {
        for degree in 1..=super::super::MAX_DEGREE_BITS {
            let (plan, requests) = measure(|| Plan::new(degree, htlc));
            let plan = plan.unwrap();
            assert_eq!(requests.calls, 0);
            assert_eq!(requests.bytes, 0);
            plan.admit(TEMPORARY_LIMIT_BYTES).unwrap();
            plan.admit(plan.temporary_peak_bytes).unwrap();
            assert!(plan.admit(plan.temporary_peak_bytes - 1).is_err());
            assert!(plan.cumulative_requested_bytes >= plan.temporary_peak_bytes);
            largest_peak = largest_peak.max(plan.temporary_peak_bytes);
            largest_cumulative = largest_cumulative.max(plan.cumulative_requested_bytes);
        }
    }
    for degree in [0, super::super::MAX_DEGREE_BITS + 1, usize::MAX] {
        assert!(Plan::new(degree, false).is_err());
    }
    eprintln!("wallet_scratch_shapes cases=56 largest_peak_bytes={largest_peak} largest_cumulative_bytes={largest_cumulative} limit_bytes={TEMPORARY_LIMIT_BYTES} allocations=0");
}

#[test]
fn ledger_growth_and_overflow_are_checked_without_allocation() {
    for count in [0, 1, 2, 3, 4, 7, 8, 9, 16, 17, 31, 32, 33, 1025] {
        let mut ledger = Ledger::default();
        ledger.growing::<Ext>(count).unwrap();
        let (values, requests) = measure(|| {
            let mut values = Vec::new();
            for i in 0..count {
                values.push(Ext::from_u64(i as u64));
            }
            values
        });
        bounded(requests, ledger.0);
        assert_eq!(values.len(), count);
    }
    let (_, requests) = measure(|| {
        assert!(add(usize::MAX, 1).is_err());
        assert!(mul(usize::MAX, 2).is_err());
        assert!(Ledger::default().exact::<Ext>(usize::MAX).is_err());
        assert!(Ledger::default().growing::<Val>(usize::MAX).is_err());
        assert!(Ledger(usize::MAX).bytes(1).is_err());
        assert!(Ledger::default().repeat(Ledger(2), usize::MAX).is_err());
    });
    assert_eq!(requests.calls, 0);
    eprintln!("wallet_scratch_ledger growth_cases=14 overflow_cases=6 overflow_allocations=0");
}

#[test]
#[ignore = "requires serial process-wide allocation observation"]
fn periodic_construction_retention_and_parallel_interpolation_fit_their_components() {
    rayon::broadcast(|_| {});
    for htlc in [false, true] {
        let plan = periodic::Storage::new(htlc).unwrap();
        let (columns, requests) = measure_all(|| {
            if htlc {
                crate::htlc_air::periodic()
            } else {
                crate::joinsplit_air::periodic()
            }
        });
        bounded(requests, plan.construction);
        assert_eq!(columns.len(), plan.columns);
        let retained = columns.capacity() * core::mem::size_of::<Vec<Val>>()
            + columns
                .iter()
                .map(|column| column.capacity() * core::mem::size_of::<Val>())
                .sum::<usize>();
        assert!(retained <= plan.retained);
        assert!(columns[..11].iter().all(|c| c.len() == 32));
        assert!(columns[11..].iter().all(|c| c.len() == plan.height));
        let domain = Domain::<Config>::new(Val::ONE, plan.height.ilog2() as usize).unwrap();
        for index in [0, 11] {
            let column = &columns[index];
            for point in [Ext::ONE, Ext::from_u64(13)] {
                let (value, requests) =
                    measure_all(|| domain.evaluate_periodic_column_at(column, point));
                bounded(requests, periodic::evaluation(column.len()).unwrap());
                if point == Ext::ONE {
                    assert_eq!(value, Ext::from(column[0]));
                }
                eprintln!("wallet_scratch_interpolation htlc={htlc} period={} on_coset={} requested_bytes={} calls={} source_bound={}", column.len(), point == Ext::ONE, requests.bytes, requests.calls, periodic::evaluation(column.len()).unwrap());
            }
        }
        eprintln!("wallet_scratch_periodic htlc={htlc} columns={} height={} construction_bytes={} construction_bound={} retained_bytes={retained} retained_bound={} evaluation_peak_bound={} evaluation_cumulative_bound={}", plan.columns, plan.height, requests.bytes, plan.construction, plan.retained, plan.evaluation_peak, plan.evaluation_cumulative);
    }
}

fn numeric_air<A>(name: &str, air: A, htlc: bool)
where
    A: for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, Config>>,
{
    let periodic = periodic::Storage::new(htlc).unwrap();
    let plan = Plan::new(periodic.height.ilog2() as usize + 1, htlc).unwrap();
    let row = vec![Ext::ZERO; air.width()];
    let public = vec![Val::ZERO; air.num_public_values()];
    let values = vec![Ext::ZERO; air.num_periodic_columns()];
    let domain = Domain::<Config>::new(Val::ONE, periodic.height.ilog2() as usize).unwrap();
    let (_, requests) = measure_all(|| {
        p3_uni_stark::verify_constraints::<Config, A, ()>(
            &air,
            &row,
            &row,
            None,
            None,
            &values,
            &public,
            domain,
            Ext::from_u64(13),
            Ext::from_u64(17),
            Ext::ZERO,
        )
    });
    bounded(requests, plan.air_bytes);
    eprintln!(
        "wallet_scratch_air air={name} requested_bytes={} calls={} source_bound={}",
        requests.bytes, requests.calls, plan.air_bytes
    );
}

#[test]
#[ignore = "requires serial process-wide allocation observation"]
fn configuration_and_original_air_evaluation_fit_their_source_components() {
    for _ in 0..3 {
        let (config, requests) = measure_all(profile::verification::make_config);
        config.unwrap();
        bounded(requests, profile::verification::requested_bytes());
    }
    numeric_air("join_split", air::join_split(), false);
    numeric_air("htlc", air::htlc(), true);
    numeric_air("issuance", air::issuance(), false);
    eprintln!(
        "wallet_scratch_configuration cases=3 requested_bound={}",
        profile::verification::requested_bytes()
    );
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
pub(in super::super) fn fresh_check(wallet: &mut super::super::WalletProof, policy: Policy) {
    rayon::broadcast(|_| {});
    let htlc = matches!(policy, Policy::Htlc { .. });
    let plan = Plan::new(wallet.proof.degree_bits, htlc).unwrap();
    let kind = match policy {
        Policy::JoinSplit => "join_split",
        Policy::Htlc { .. } => "htlc",
        Policy::Issuance { .. } => "issuance",
    };
    let check = |wallet: &super::super::WalletProof, label: &str, valid: bool| {
        let (result, requests) = measure_all(|| typed_recursive::verify_wallet(wallet, policy));
        assert_eq!(result.is_ok(), valid, "{label}");
        bounded(requests, plan.cumulative_requested_bytes);
        eprintln!("wallet_scratch_fresh air={kind} mutation={label} valid={valid} requested_bytes={} calls={} cumulative_bound={} peak_payload_bound={}", requests.bytes, requests.calls, plan.cumulative_requested_bytes, plan.temporary_peak_bytes);
    };
    check(wallet, "none", true);
    wallet.chain[0] ^= 1;
    check(wallet, "chain", false);
    wallet.chain[0] ^= 1;
    wallet.public[0] += Val::ONE;
    check(wallet, "public", false);
    wallet.public[0] -= Val::ONE;
    wallet.proof.opened_values.trace_local[0] += Ext::ONE;
    check(wallet, "opening", false);
    wallet.proof.opened_values.trace_local[0] -= Ext::ONE;
    let query = wallet.proof.opening_proof.1.query_proofs.len() - 1;
    let layer = wallet.proof.opening_proof.1.query_proofs[query]
        .commit_phase_openings
        .len()
        - 1;
    wallet.proof.opening_proof.1.query_proofs[query].commit_phase_openings[layer].sibling_values
        [0] += Ext::ONE;
    check(wallet, "last_fri", false);
    wallet.proof.opening_proof.1.query_proofs[query].commit_phase_openings[layer].sibling_values
        [0] -= Ext::ONE;
    check(wallet, "restored", true);
}
