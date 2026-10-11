use super::*;
use crate::block_v2::{commitment::Context, gpu_hash, leaf, profile};
use crate::joinsplit_air as js;
use crate::proving::{Policy, Request};

#[test]
fn base_air_field_selection_preserves_order_and_rejects_extension_constraints() {
    let air = js::JoinSplitAir;
    let layout = AirLayout::from_air::<Val>(&air);
    let constraints = symbolic::uni(&air, Constants::cpu()).unwrap();
    let order = constraints.order.base_indices.clone();
    let count = constraints.base.len();
    let degree = constraints.max_degree();
    let quadratic = constraints
        .into_base_only::<crate::config::Challenge>()
        .unwrap();
    assert_eq!(quadratic.order.base_indices, order);
    assert_eq!(quadratic.base.len(), count);
    assert_eq!(quadratic.max_degree(), degree);
    let program = Program::from_periodic_constraints(layout, &quadratic).unwrap();
    assert_eq!(program.extension, Extension::Quadratic);
    assert_eq!(program.constraints, count);
    let mut nonbase = symbolic::uni(&air, Constants::cpu()).unwrap();
    nonbase.extension.push(profile::Challenge::ONE.into());
    assert!(nonbase
        .into_base_only::<crate::config::Challenge>()
        .is_err());
    let mut malformed = symbolic::uni(&air, Constants::cpu()).unwrap();
    malformed.order.ext_indices.push(0);
    assert!(malformed
        .into_base_only::<crate::config::Challenge>()
        .is_err());
}

#[test]
fn periodic_lowering_preserves_public_air_and_rejects_preprocessed_aliases() {
    let air = leaf::ContextJoinSplitAir;
    let layout = AirLayout::from_air::<Val>(&air);
    let constraints = symbolic::uni(&air, Constants::cpu()).unwrap();
    let program = Program::from_periodic_constraints(layout, &constraints).unwrap();
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(program.layout.num_periodic_columns, 0);
    assert_eq!(program.layout.preprocessed_width, js::N_PERIODIC);
    assert_eq!(program.constraints, 82);
    assert_eq!(program.row_words, 2 * (js::WIDTH + js::N_PERIODIC));
    assert!(Program::from_constraints(layout, &constraints).is_err());
    let mut conflicting = layout;
    conflicting.preprocessed_width = 1;
    assert!(Program::from_periodic_constraints(conflicting, &constraints).is_err());
    conflicting = layout;
    conflicting.permutation_width = 1;
    assert!(Program::from_periodic_constraints(conflicting, &constraints).is_err());
}

#[test]
#[ignore = "requires selected OpenCL GPU and <=3 GiB zero-swap service"]
fn gpu_owned_wallet_proofs_verify_after_shutdown_without_trace_readback() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = crate::block_v2::quotient_pcs::initialize_research_from_env().unwrap();
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0x71; 32],
    };
    let witness = js::demo_witness();
    let request = |policy| Request {
        policy,
        emit_report: true,
    };
    let before = gpu_hash::report("owned_wallet_admission_before").unwrap();
    assert_eq!(
        leaf::prove_joinsplit_on_gpu(&witness, &context, request(Policy::CpuRequired)),
        Err(leaf::LeafError::ProvingPolicy)
    );
    #[cfg(debug_assertions)]
    assert_eq!(
        leaf::prove_joinsplit_on_gpu(&witness, &context, request(Policy::GpuRequired)),
        Err(leaf::LeafError::ProvingPolicy)
    );
    let mut wrong_context = context.clone();
    wrong_context.profile_id[0] ^= 1;
    assert_eq!(
        leaf::prove_joinsplit_on_gpu(&witness, &wrong_context, Request::compatible()),
        Err(leaf::LeafError::WrongProfile)
    );
    let mut issuance = witness.clone();
    issuance.mint = 1;
    assert_eq!(
        leaf::prove_joinsplit_on_gpu(&issuance, &context, Request::compatible()),
        Err(leaf::LeafError::IssuanceNotSupported)
    );
    {
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("LATTICA_V2_WORKER_BUDGET", value),
                    None => std::env::remove_var("LATTICA_V2_WORKER_BUDGET"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("LATTICA_V2_WORKER_BUDGET"));
        std::env::set_var(
            "LATTICA_V2_WORKER_BUDGET",
            "public-worker-is-not-private-wallet-admission",
        );
        assert_eq!(
            leaf::prove_joinsplit_on_gpu(&witness, &context, Request::compatible()),
            Err(leaf::LeafError::GpuFailure)
        );
    }
    let after = gpu_hash::report("owned_wallet_admission_after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    let mut unbalanced = witness.clone();
    unbalanced.fee += 1;
    assert_eq!(
        leaf::prove_joinsplit_on_gpu(&unbalanced, &context, request(Policy::Compatible)),
        Err(leaf::LeafError::GpuFailure)
    );
    let mut artifacts = Vec::new();
    for _ in 0..2 {
        let policy = if cfg!(debug_assertions) {
            Policy::Compatible
        } else {
            Policy::GpuRequired
        };
        let proof = leaf::prove_joinsplit_on_gpu(&witness, &context, request(policy)).unwrap();
        artifacts.push(proof);
    }
    assert_ne!(
        artifacts[0], artifacts[1],
        "fresh hiding must not replay wallet proof bytes"
    );
    gpu_hash::shutdown().unwrap();
    let public = js::public_values(&witness);
    for proof in artifacts {
        leaf::verify_joinsplit_research(&proof, &context, &public).unwrap();
        let mut altered = public.clone();
        altered[js::PI_FEE] += Val::ONE;
        assert!(leaf::verify_joinsplit_research(&proof, &context, &altered).is_err());
        let mut wrong_chain = context.clone();
        wrong_chain.chain_id[0] ^= 1;
        assert!(leaf::verify_joinsplit_research(&proof, &wrong_chain, &public).is_err());
        assert!(
            leaf::verify_joinsplit_research(&proof[..proof.len() - 1], &context, &public).is_err()
        );
    }
}
