use super::*;
use crate::block_v2::machine::{MachineAir, ProgramBuilder};
use p3_air::{check_constraints, BaseAir};
use p3_field::PrimeField64;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_lookup::{
    debug_util::{check_lookups, LookupDebugInstance},
    Lookups,
};
use p3_symmetric::Permutation;

fn fixture() -> (RecursionTemplate, Vec<Val>, Vec<Val>) {
    let mut b = ProgramBuilder::new(8).unwrap();
    let input: [_; 8] = core::array::from_fn(|_| b.input());
    let out = b.poseidon(input);
    for (i, &wire) in out.iter().enumerate() {
        let p = b.public(i).unwrap();
        b.assert_equal(wire, p);
    }
    let sum = b.add(input[0], input[1]);
    let product = b.mul(input[0], input[1]);
    let inv = b.inverse(input[0]);
    let one = b.mul(inv, input[0]);
    let expected = b.constant(Val::ONE);
    b.assert_equal(one, expected);
    let bit = b.input();
    b.assert_bool(bit);
    let selected = b.select(bit, sum, product);
    let expected = b.input();
    b.assert_equal(selected, expected);
    let a = [input[0], input[1], input[2]];
    let c = [input[3], input[4], input[5]];
    let mul = b.cubic_mul(a, c);
    let inverse = b.cubic_inverse(c);
    let restored = b.cubic_mul(mul, inverse);
    for i in 0..3 {
        b.assert_equal(a[i], restored[i]);
    }
    let witness: Vec<_> = (1..=8)
        .map(Val::from_u64)
        .chain([Val::ONE, Val::TWO])
        .collect();
    let public = default_goldilocks_poseidon2_8()
        .permute(core::array::from_fn(|i| witness[i]))
        .to_vec();
    (
        RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [42; 32]).unwrap(),
        public,
        witness,
    )
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires the exclusive full OpenCL profile"]
fn recursion_gpu_reuses_public_setup_with_fresh_verified_private_proofs() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let (template, public, witness) = fixture();
    let prepared = template
        .prepare_gpu(GpuTemplateLimits {
            host_bytes: 4 << 30,
            pcs_host_bytes: 2 << 30,
            max_rows: 256,
        })
        .unwrap();
    let cap = serde_json::to_vec(prepared.preprocessing_cap()).unwrap();
    let (first, first_report) = prepared.prove(&public, &witness).unwrap();
    let (second, second_report) = prepared.prove(&public, &witness).unwrap();
    let mut next_witness = witness.clone();
    next_witness[0] = Val::TWO;
    next_witness[9] = Val::from_u64(4);
    let next_public = default_goldilocks_poseidon2_8()
        .permute(core::array::from_fn(|i| next_witness[i]))
        .to_vec();
    let (next, next_report) = prepared.prove(&next_public, &next_witness).unwrap();
    assert!(prepared.verify(&next, &public).is_err());
    assert_ne!(
        serde_json::to_vec(&first.inner).unwrap(),
        serde_json::to_vec(&second.inner).unwrap()
    );
    assert_eq!(
        cap,
        serde_json::to_vec(prepared.preprocessing_cap()).unwrap()
    );
    let mut wrong = public.clone();
    wrong[0] += Val::ONE;
    assert!(prepared.verify(&first, &wrong).is_err());
    for report in [first_report, second_report, next_report] {
        assert!(report.verified && report.backend_report.stage_coverage_complete);
        assert_eq!(
            report.backend_report.capabilities.scope(),
            crate::proving::CoverageScope::Operation
        );
        assert_eq!(
            report.backend_report.policy,
            crate::proving::Policy::GpuRequired
        );
        assert!(report.proof_json_bytes > 0 && report.query_opened_fields > 0);
        eprintln!(
            "RECURSION_GPU_PROOF {}",
            serde_json::to_string(&report).unwrap()
        );
    }
    drop(prepared);
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires the exclusive full OpenCL profile"]
fn recursion_gpu_mixed_height_tables_verify_with_cpu_and_reject_tampering() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut state = core::array::from_fn(|_| b.input());
    for _ in 0..17 {
        state = b.poseidon(state);
    }
    for (i, &wire) in state.iter().enumerate() {
        let public = b.public(i).unwrap();
        b.assert_equal(wire, public);
    }
    let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [17; 32]).unwrap();
    let geometry = template.geometry().unwrap();
    assert!(geometry
        .tables
        .iter()
        .any(|t| t.height != geometry.tables[0].height));
    let witness = (1..=8).map(Val::from_u64).collect::<Vec<_>>();
    let mut public = core::array::from_fn(|i| witness[i]);
    for _ in 0..17 {
        public = default_goldilocks_poseidon2_8().permute(public);
    }
    let prepared = template
        .prepare_gpu(GpuTemplateLimits {
            host_bytes: 4 << 30,
            pcs_host_bytes: 2 << 30,
            max_rows: 256,
        })
        .unwrap();
    let (mut proof, report) = prepared.prove(&public, &witness).unwrap();
    assert!(report.verified && report.backend_report.stage_coverage_complete);
    proof.inner.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += crate::block_v2::profile::Challenge::ONE;
    assert!(prepared.verify(&proof, &public).is_err());
    eprintln!(
        "RECURSION_MIXED_GPU_PROOF {}",
        serde_json::to_string(&report).unwrap()
    );
}

fn check(template: &RecursionTemplate, public: &[Val], traces: &[RowMajorMatrix<Val>]) {
    let airs = template.airs();
    let pre = airs
        .iter()
        .map(|a| a.preprocessed_trace())
        .collect::<Vec<_>>();
    let lookup = airs
        .iter()
        .map(|a| Lookups::<Val>::from_air::<crate::block_v2::profile::Challenge, _>(a))
        .collect::<Vec<_>>();
    for (i, air) in airs.iter().enumerate() {
        check_constraints(air, &traces[i], if air.kind == 3 { public } else { &[] });
    }
    check_lookups(
        &airs
            .iter()
            .enumerate()
            .map(|(i, air)| LookupDebugInstance {
                main_trace: &traces[i],
                preprocessed_trace: &pre[i],
                public_values: if air.kind == 3 { public } else { &[] },
                lookups: &lookup[i],
                permutation_challenges: &[],
            })
            .collect::<Vec<_>>(),
    );
}

#[test]
fn recursion_tail_tables_preserve_cross_table_wires_and_exact_coverage() {
    assert_eq!(
        partition_rows(262594),
        vec![(0, 262144, 262144), (262144, 450, 512)]
    );
    for rows in 0..2048 {
        let spans = partition_rows(rows);
        assert!(spans.len() <= 2);
        assert_eq!(spans.iter().map(|s| s.1).sum::<usize>(), rows);
        assert!(spans
            .iter()
            .all(|s| s.1 <= s.2 && s.2.is_power_of_two() && s.2 >= 8));
        assert!(spans.iter().map(|s| s.2).sum::<usize>() <= rows.max(8).next_power_of_two());
        if spans.len() == 2 {
            assert_eq!(spans[1].0, spans[0].1);
        }
    }
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut state = core::array::from_fn(|_| b.input());
    for _ in 0..(16 * air::HASH_LANES + 1) {
        state = b.poseidon(state);
    }
    for (i, &wire) in state.iter().enumerate() {
        let public = b.public(i).unwrap();
        b.assert_equal(wire, public);
    }
    let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [9; 32]).unwrap();
    let witness = (1..=8).map(Val::from_u64).collect::<Vec<_>>();
    let mut public = core::array::from_fn(|i| witness[i]);
    for _ in 0..(16 * air::HASH_LANES + 1) {
        public = default_goldilocks_poseidon2_8().permute(public);
    }
    let airs = template.airs();
    let traces = template.traces(&public, &witness).unwrap();
    assert_eq!(airs.iter().filter(|a| a.kind == 2).count(), 2);
    check(&template, &public, &traces);
    let prepared = template.prepare_cpu_reference().unwrap();
    let mut proof = prepared.prove_cpu_reference(&public, &witness).unwrap();
    prepared.verify_cpu_reference(&proof, &public).unwrap();
    proof.inner.degree_bits.remove(2);
    assert!(prepared.verify_cpu_reference(&proof, &public).is_err());
    let tail = airs
        .iter()
        .position(|a| a.kind == 2 && a.first_row > 0)
        .unwrap();
    let mut bad = traces.clone();
    bad[tail].values[0] += Val::ONE;
    assert!(std::panic::catch_unwind(|| check(&template, &public, &bad)).is_err());
}

#[test]
fn recursion_tables_match_reference_and_enforce_global_wires() {
    let (template, public, witness) = fixture();
    MachineAir::from_shared_program(Arc::clone(&template.program))
        .trace(&public, &witness)
        .unwrap();
    let traces = template.traces(&public, &witness).unwrap();
    check(&template, &public, &traces);
    let geometry = template.geometry().unwrap();
    assert!(
        geometry.degree_gate && geometry.quotient_gate,
        "{geometry:?}"
    );
    assert!(geometry.tables.iter().all(|t| t.quotient_chunks <= 8));
    // A cross-table wire substitution must be rejected by the global lookup,
    // even when it changes an unconstrained input opcode's output.
    let mut bad = traces.clone();
    bad[0].values[3] += Val::ONE;
    assert!(std::panic::catch_unwind(|| check(&template, &public, &bad)).is_err());
    let mut wrong = public.clone();
    wrong[0] += Val::ONE;
    assert!(std::panic::catch_unwind(|| check(&template, &wrong, &traces)).is_err());
    // Check every Poseidon checkpoint and every inactive slot independently.
    for column in 0..traces[2].width {
        let mut bad = traces.clone();
        bad[2].values[column] += Val::ONE;
        assert!(
            std::panic::catch_unwind(|| check_constraints(&template.airs()[2], &bad[2], &[]))
                .is_err(),
            "hash column {column}"
        );
    }
    let mut bad = traces.clone();
    let last = bad[2].values.len() - 1;
    bad[2].values[last] = Val::ONE;
    assert!(std::panic::catch_unwind(|| check(&template, &public, &bad)).is_err());
}

#[test]
fn recursion_template_identity_binds_registry_and_program_not_witness() {
    let (template, public, mut witness) = fixture();
    let id = template.identity();
    template.traces(&public, &witness).unwrap();
    witness[0] += Val::ONE;
    assert!(template.traces(&public, &witness).is_err());
    assert_eq!(id, template.identity());
    assert_eq!(
        id,
        RecursionTemplate::new(Arc::clone(&template.program), [42; 32])
            .unwrap()
            .identity()
    );
    assert_ne!(
        id,
        RecursionTemplate::new(Arc::clone(&template.program), [43; 32])
            .unwrap()
            .identity()
    );
    let mut b = ProgramBuilder::new(8).unwrap();
    let _ = b.input();
    assert_ne!(
        id,
        RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [42; 32])
            .unwrap()
            .identity()
    );
}

#[test]
fn recursion_prepared_owner_reuses_setup_with_fresh_proofs() {
    let (template, public, witness) = fixture();
    let prepared = template.prepare_cpu_reference().unwrap();
    let cap = prepared.preprocessing_cap().clone();
    let first = prepared.prove_cpu_reference(&public, &witness).unwrap();
    let second = prepared.prove_cpu_reference(&public, &witness).unwrap();
    assert_ne!(first.inner.commitments.main, second.inner.commitments.main);
    assert_eq!(prepared.preprocessing_cap(), &cap);
    assert_eq!(
        template
            .prepare_cpu_reference()
            .unwrap()
            .preprocessing_cap(),
        &cap
    );
    let another_registry = RecursionTemplate::new(Arc::clone(&template.program), [43; 32])
        .unwrap()
        .prepare_cpu_reference()
        .unwrap();
    assert_ne!(another_registry.preprocessing_cap(), &cap);
    assert!(another_registry
        .verify_cpu_reference(&first, &public)
        .is_err());
    let mut wrong = public.clone();
    wrong[7] += Val::ONE;
    assert!(prepared.verify_cpu_reference(&first, &wrong).is_err());
    let other = RecursionTemplate::new(
        Arc::new(ProgramBuilder::new(8).unwrap().finish(None).unwrap()),
        [42; 32],
    )
    .unwrap()
    .prepare_cpu_reference()
    .unwrap();
    assert!(other.verify_cpu_reference(&first, &public).is_err());
    let mut different = witness.clone();
    different[6] = Val::from_u64(77);
    let different_public = default_goldilocks_poseidon2_8()
        .permute(core::array::from_fn(|i| different[i]))
        .to_vec();
    let third = prepared
        .prove_cpu_reference(&different_public, &different)
        .unwrap();
    prepared
        .verify_cpu_reference(&third, &different_public)
        .unwrap();
    assert_eq!(prepared.identity(), template.identity());
    assert!(prepared.verify_cpu_reference(&third, &public).is_err());
    assert!(public.iter().all(|v| v.as_canonical_u64() < Val::ORDER_U64));
}

#[test]
fn recursion_public_tables_cover_empty_and_both_banks() {
    for count in [0, 1, 32, 64] {
        let mut b = ProgramBuilder::new(count).unwrap();
        for i in 0..count {
            let p = b.public(i).unwrap();
            let w = b.input();
            b.assert_equal(p, w);
        }
        let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [7; 32]).unwrap();
        let public = (0..count).map(Val::from_usize).collect::<Vec<_>>();
        let traces = template.traces(&public, &public).unwrap();
        check(&template, &public, &traces);
        let geometry = template.geometry().unwrap();
        assert!(geometry.degree_gate && geometry.quotient_gate);
        // Inactive scalar lanes must not create unconstrained wire outputs.
        let mut bad = traces.clone();
        let last = bad[0].values.len() - 1;
        bad[0].values[last] = Val::ONE;
        assert!(std::panic::catch_unwind(|| check(&template, &public, &bad)).is_err());
    }
}

#[test]
fn recursion_parent_constraints_bind_mixed_child_and_trusted_cap() {
    use crate::block_v2::machine::program::ConstructionLimits;
    use crate::block_v2::profile::Challenge;
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut state = core::array::from_fn(|_| b.input());
    for _ in 0..17 {
        state = b.poseidon(state);
    }
    for (i, &wire) in state.iter().enumerate() {
        let public = b.public(i).unwrap();
        b.assert_equal(wire, public);
    }
    let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [17; 32]).unwrap();
    let prepared = template.prepare_cpu_reference().unwrap();
    let witness = (1..=8).map(Val::from_u64).collect::<Vec<_>>();
    let mut public = core::array::from_fn(|i| witness[i]);
    for _ in 0..17 {
        public = default_goldilocks_poseidon2_8().permute(public);
    }
    let limits = ConstructionLimits {
        max_requested_program_bytes: 1 << 30,
        max_wires: 8_000_000,
        max_input_values: 1 << 20,
    };
    let mut proof = prepared.prove_cpu_reference(&public, &witness).unwrap();
    let parent = prepared.compile_verifier(&proof, limits).unwrap();
    parent.evaluate(&public).unwrap();
    let mut wrong_public = public;
    wrong_public[0] += Val::ONE;
    assert!(parent.evaluate(&wrong_public).is_err());
    let second = prepared.prove_cpu_reference(&public, &witness).unwrap();
    let second_parent = prepared.compile_verifier(&second, limits).unwrap();
    parent
        .program()
        .evaluate(&public, second_parent.witness())
        .unwrap();
    assert_eq!(
        RecursionTemplate::new(Arc::clone(parent.program()), [18; 32])
            .unwrap()
            .identity(),
        RecursionTemplate::new(Arc::clone(second_parent.program()), [18; 32])
            .unwrap()
            .identity()
    );
    drop(second_parent);
    drop(parent);
    let other = RecursionTemplate::new(Arc::clone(&template.program), [19; 32])
        .unwrap()
        .prepare_cpu_reference()
        .unwrap();
    assert!(other
        .compile_verifier(&proof, limits)
        .unwrap()
        .evaluate(&public)
        .is_err());
    proof.inner.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    assert!(prepared
        .compile_verifier(&proof, limits)
        .unwrap()
        .evaluate(&public)
        .is_err());
    proof.inner.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] -= Challenge::ONE;
    proof.inner.lookup_terminals[0].as_mut().unwrap().0 += Challenge::ONE;
    proof.inner.lookup_terminals[1].as_mut().unwrap().0 -= Challenge::ONE;
    assert!(prepared
        .compile_verifier(&proof, limits)
        .unwrap()
        .evaluate(&public)
        .is_err());
    proof.inner.degree_bits[0] += 1;
    assert!(prepared.compile_verifier(&proof, limits).is_err());
}

fn typed_reduction_fixture_with_terms(terms: usize) -> (RecursionTemplate, Vec<Val>, Vec<Val>) {
    use crate::block_v2::profile::Challenge;
    use p3_field::BasedVectorSpace;
    let mut b = ProgramBuilder::new(3).unwrap();
    let alpha = core::array::from_fn(|_| b.input());
    let mut acc = core::array::from_fn(|_| b.input());
    let mut power = alpha;
    for _ in 0..terms {
        let value = b.input();
        let term = b.ext_scale(power, value);
        acc = b.ext_add(acc, term);
        power = b.ext_mul(power, alpha);
    }
    for i in 0..3 {
        let p = b.public(i).unwrap();
        b.assert_equal(p, acc[i]);
    }
    let witness = (1..=terms as u64 + 6)
        .map(Val::from_u64)
        .collect::<Vec<_>>();
    let a = Challenge::from_basis_coefficients_slice(&witness[..3]).unwrap();
    let mut sum = Challenge::from_basis_coefficients_slice(&witness[3..6]).unwrap();
    let mut power = a;
    for &value in &witness[6..] {
        sum += power * value;
        power *= a;
    }
    let public = sum.as_basis_coefficients_slice().to_vec();
    (
        RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [81; 32]).unwrap(),
        public,
        witness,
    )
}
fn typed_reduction_fixture() -> (RecursionTemplate, Vec<Val>, Vec<Val>) {
    typed_reduction_fixture_with_terms(12)
}
#[test]
fn packed_hashes_bind_both_lanes_and_the_inactive_odd_tail() {
    let mut b = ProgramBuilder::new(8).unwrap();
    let mut state = core::array::from_fn(|_| b.input());
    let witness = (1..=8).map(Val::from_u64).collect::<Vec<_>>();
    let mut expected = core::array::from_fn(|i| witness[i]);
    for _ in 0..3 {
        state = b.poseidon(state);
        expected = default_goldilocks_poseidon2_8().permute(expected);
    }
    for i in 0..8 {
        let p = b.public(i).unwrap();
        b.assert_equal(state[i], p);
    }
    let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [83; 32]).unwrap();
    let airs = template.airs();
    let index = airs.iter().position(|air| air.kind == 2).unwrap();
    assert_eq!(airs[index].active_rows, 2);
    let traces = template.traces(&expected, &witness).unwrap();
    check(&template, &expected, &traces);
    for row in [0, 1] {
        let mut wrong = traces.clone();
        let width = wrong[index].width;
        wrong[index].values[row * width + width / 2] += Val::ONE;
        assert!(std::panic::catch_unwind(|| check(&template, &expected, &wrong)).is_err());
    }
}
#[test]
fn typed_reduction_partial_groups_and_short_chains_match_the_source() {
    for terms in [1, 3, 4, 5, 7, 8, 9, 17] {
        let (template, public, witness) = typed_reduction_fixture_with_terms(terms);
        assert_eq!(
            template.typed_plan().stats().reduction_terms,
            if terms < 4 { 0 } else { terms }
        );
        check(
            &template,
            &public,
            &template.traces(&public, &witness).unwrap(),
        );
    }
}

#[test]
fn compact_verifier_releases_source_and_still_binds_proof_and_public_values() {
    let (template, public, witness) = typed_reduction_fixture();
    let weak = Arc::downgrade(&template.program);
    let owner = template.prepare_cpu_reference().unwrap();
    let proof = owner.prove_cpu_reference(&public, &witness).unwrap();
    let key = owner.verifier();
    assert!(key.matches_program(&template.program));
    let (other, _, _) = typed_reduction_fixture();
    assert!(!key.matches_program(&other.program));
    drop(owner);
    drop(template);
    assert!(weak.upgrade().is_none());
    key.verify(&proof, &public).unwrap();
    let mut bad = public.clone();
    bad[0] += Val::ONE;
    assert!(key.verify(&proof, &bad).is_err());
    let mut builder = ProgramBuilder::new(public.len()).unwrap();
    let publics = (0..public.len())
        .map(|i| builder.public(i).unwrap())
        .collect::<Vec<_>>();
    let mut inputs = super::super::program::ProofInputs::default();
    key.constrain(&mut builder, &mut inputs, &publics, &proof)
        .unwrap();
    let parent = builder.finish(None).unwrap();
    parent.evaluate(&public, &inputs.values).unwrap();
    assert!(parent.evaluate(&bad, &inputs.values).is_err());
}
#[test]
fn typed_reductions_preserve_externally_used_accumulators_and_products() {
    use crate::block_v2::profile::Challenge;
    use p3_field::BasedVectorSpace;
    for reuse_product in [false, true] {
        let mut b = ProgramBuilder::new(3).unwrap();
        let alpha = core::array::from_fn(|_| b.input());
        let mut acc = core::array::from_fn(|_| b.input());
        let mut power = alpha;
        let mut witness = (1..=6).map(Val::from_u64).collect::<Vec<_>>();
        let a = Challenge::from_basis_coefficients_slice(&witness[..3]).unwrap();
        let mut sum = Challenge::from_basis_coefficients_slice(&witness[3..]).unwrap();
        let mut weight = a;
        for i in 0..9 {
            let value = b.input();
            let v = Val::from_u64(7 + i);
            witness.push(v);
            let term = b.ext_scale(power, value);
            let product = weight * v;
            if reuse_product && i == 4 {
                let observed = b.input();
                witness.push(product.as_basis_coefficients_slice()[0]);
                b.assert_equal(term[0], observed);
            }
            acc = b.ext_add(acc, term);
            sum += product;
            if !reuse_product && i == 3 {
                let observed = b.input();
                witness.push(sum.as_basis_coefficients_slice()[0]);
                b.assert_equal(acc[0], observed);
            }
            power = b.ext_mul(power, alpha);
            weight *= a;
        }
        for i in 0..3 {
            let p = b.public(i).unwrap();
            b.assert_equal(p, acc[i]);
        }
        let public = sum.as_basis_coefficients_slice().to_vec();
        let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [82; 32]).unwrap();
        assert_eq!(template.typed_plan().stats().reduction_chains, 2);
        assert_eq!(
            template.typed_plan().stats().reduction_terms,
            if reuse_product { 8 } else { 9 }
        );
        check(
            &template,
            &public,
            &template.traces(&public, &witness).unwrap(),
        );
    }
}

#[test]
fn typed_reduction_matches_source_and_authenticates_boundaries() {
    let (template, public, witness) = typed_reduction_fixture();
    assert_eq!(template.typed_plan().stats().reduction_terms, 12);
    assert_eq!(template.typed_plan().stats().removed_scalar_operations, 72);
    let traces = template.traces(&public, &witness).unwrap();
    check(&template, &public, &traces);
    let index = template.airs().iter().position(|a| a.kind == 4).unwrap();
    let mut wrong = traces.clone();
    wrong[index].values[19] += Val::ONE;
    assert!(std::panic::catch_unwind(|| check(&template, &public, &wrong)).is_err());
    // A uniform accumulator shift preserves transitions, but must fail the
    // authenticated start/end lookup bindings.
    let mut wrong = traces;
    for row in wrong[index]
        .values
        .chunks_exact_mut(19)
        .take(template.typed.groups.len())
    {
        row[0] += Val::ONE;
    }
    assert!(std::panic::catch_unwind(|| check(&template, &public, &wrong)).is_err());
    assert!(template.geometry().unwrap().degree_gate);
}

#[test]
fn typed_reduction_proof_and_parent_bind_next_row_opening() {
    use crate::block_v2::machine::program::ConstructionLimits;
    use crate::block_v2::profile::Challenge;
    let (template, public, witness) = typed_reduction_fixture();
    let owner = template.prepare_cpu_reference().unwrap();
    let mut proof = owner.prove_cpu_reference(&public, &witness).unwrap();
    let limits = ConstructionLimits {
        max_requested_program_bytes: 1 << 30,
        max_wires: 8_000_000,
        max_input_values: 1 << 20,
    };
    owner
        .compile_verifier(&proof, limits)
        .unwrap()
        .evaluate(&public)
        .unwrap();
    let index = template.airs().iter().position(|a| a.kind == 4).unwrap();
    proof.inner.opened_values.instances[index]
        .base_opened_values
        .trace_next
        .as_mut()
        .unwrap()[0] += Challenge::ONE;
    assert!(owner.verify_cpu_reference(&proof, &public).is_err());
    assert!(owner
        .compile_verifier(&proof, limits)
        .unwrap()
        .evaluate(&public)
        .is_err());
    proof.inner.opened_values.instances[index]
        .base_opened_values
        .trace_next = None;
    assert!(owner.compile_verifier(&proof, limits).is_err());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires exclusive full OpenCL profile"]
fn typed_reduction_gpu_proof_matches_cpu_verifier() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let (template, public, witness) = typed_reduction_fixture();
    let mut owner = template
        .prepare_gpu(GpuTemplateLimits {
            host_bytes: 4 << 30,
            pcs_host_bytes: 2 << 30,
            max_rows: 256,
        })
        .unwrap();
    let (_, measurement) = owner.prove(&public, &witness).unwrap();
    assert!(measurement.verified && measurement.backend_report.stage_coverage_complete);
    let cap = owner.preprocessing_cap().roots().to_vec();
    assert!(owner.park_preprocessing_for_test(0).is_err());
    let bytes = owner.park_preprocessing_for_test(1 << 20).unwrap();
    assert!(bytes > 0 && bytes <= 1 << 20);
    assert_eq!(owner.preprocessing_cap().roots(), cap.as_slice());
    assert_eq!(owner.park_preprocessing_for_test(1 << 20).unwrap(), bytes);
    let (proof, measurement) = owner.prove(&public, &witness).unwrap();
    assert!(measurement.verified && measurement.backend_report.stage_coverage_complete);
    assert!(measurement.public_prefix_host_bytes > 0 && measurement.public_salt_host_bytes > 0);
    assert_eq!(
        measurement.public_prefix_host_bytes + measurement.public_salt_host_bytes,
        bytes
    );
    owner.verifier().verify(&proof, &public).unwrap();
    let source = Arc::downgrade(&template.program);
    let key = owner.verifier();
    drop(template);
    let (proof, measurement) = owner
        .into_prove(&public, &witness, || {
            assert!(
                source.upgrade().is_none(),
                "compiler retained into GPU phase"
            );
        })
        .unwrap();
    assert!(measurement.verified && measurement.backend_report.stage_coverage_complete);
    key.verify(&proof, &public).unwrap();
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires exclusive full OpenCL profile"]
fn typed_public_cache_reuses_exact_templates_without_retaining_sources_or_randomness() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let limits = GpuTemplateLimits {
        host_bytes: 4 << 30,
        pcs_host_bytes: 2 << 30,
        max_rows: 256,
    };
    let mut cache = GpuRecursionCache::default();
    let mut proofs = Vec::new();
    let mut encoded = Vec::new();
    for attempt in 0..2 {
        let (template, public, witness) = typed_reduction_fixture();
        let source = Arc::downgrade(&template.program);
        let owner = cache.prepare(template, limits).unwrap();
        let key = owner.verifier();
        let (proof, report) = owner
            .into_prove(&public, &witness, || assert!(source.upgrade().is_none()))
            .unwrap();
        assert_eq!(report.preprocessing_reused, attempt > 0);
        key.verify(&proof, &public).unwrap();
        encoded.push(serde_json::to_vec(&proof.inner).unwrap());
        proofs.push((key, proof, public));
    }
    assert_ne!(
        encoded[0], encoded[1],
        "private proof randomness was reused"
    );
    assert_eq!((cache.stats().hits, cache.stats().misses), (1, 1));
    let (template, public, witness) = typed_reduction_fixture();
    let different = RecursionTemplate::new(Arc::clone(&template.program), [99; 32]).unwrap();
    assert_ne!(different.identity(), template.identity());
    drop(template);
    let owner = cache.prepare(different, limits).unwrap();
    let key = owner.verifier();
    assert!(key.verify(&proofs[0].1, &public).is_err());
    let (proof, report) = owner.into_prove(&public, &witness, || {}).unwrap();
    assert!(!report.preprocessing_reused);
    key.verify(&proof, &public).unwrap();
    assert_eq!((cache.stats().hits, cache.stats().misses), (1, 2));
    cache.clear();
    for (key, proof, public) in proofs {
        key.verify(&proof, &public).unwrap();
    }
}
