//! Adapted from p3-batch-stark 0.6.1 (Plonky3 contributors), Apache-2.0.
//! See LICENSE-APACHE in this directory. Original source SHA-256:
//! 187a2d56e80f692171894aec7af88a618c11c2ae840d54ecec08a4f354cc0948
//! Changes: upstream public types/helpers; quotient evaluations go to a
//! commitment callback; debug checks retained. Transcript and proof assembly
//! are unchanged. Only the explicit GPU quotient research switch selects this.
//! Batch-STARK prover: commits traces, computes quotient polynomials, and
//! produces opening proofs for multiple AIR instances in a single FRI batch.

use p3_air::symbolic::{AirLayout, SymbolicExpressionExt};
use p3_air::Air;
#[cfg(debug_assertions)]
use p3_air::DebugConstraintBuilder;
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{Algebra, PrimeField};
use p3_lookup::folder::ProverConstraintFolderWithLookups;
use p3_lookup::logup::LogUpGadget;
use p3_lookup::{
    check_multiplicity_height_bound, InteractionSymbolicBuilder, Lookup, LookupProtocol,
    LookupTerminal,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::OpenedValues;
use p3_util::log2_strict_usize;
use rayon::prelude::*;
use tracing::{info_span, instrument};

use p3_batch_stark::common::ProverData;
use p3_batch_stark::config::{Challenge, Domain, StarkGenericConfig as SGC, Val};
use p3_batch_stark::proof::{
    BatchCommitments, BatchOpenedValues, BatchProof, OpenedValuesWithLookups,
};
use p3_batch_stark::prover::quotient_values;
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks, get_symbolic_constraints};
use p3_batch_stark::{BatchTranscript, StarkInstance};
#[cfg(debug_assertions)]
mod check_constraints;

/// Per-instance quotient output: chunk domains and unextended evaluations.
pub(super) type InstanceQuotient<SC> = (Vec<Domain<SC>>, Vec<RowMajorMatrix<Val<SC>>>);

#[instrument(skip_all)]
pub(super) fn prove_batch<
    SC,
    #[cfg(debug_assertions)] A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
    #[cfg(not(debug_assertions))] A: for<'a> Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
>(
    config: &SC,
    instances: &[StarkInstance<'_, SC, A>],
    prover_data: &ProverData<SC>,
    commit_quotients: impl FnOnce(
        &SC::Pcs,
        Vec<InstanceQuotient<SC>>,
    ) -> (
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData,
    ),
) -> BatchProof<SC>
where
    SC: SGC,
    Val<SC>: PrimeField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Domain<SC>: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    let common = &prover_data.common;
    // TODO: Extend if additional lookup gadgets are added.
    let lookup_gadget = LogUpGadget::new();

    let pcs = config.pcs();
    let mut transcript = BatchTranscript::<SC>::new(config.initialise_challenger());

    // Collect per-instance degree information.
    let degrees: Vec<usize> = instances.iter().map(|i| i.trace.height()).collect();
    let log_degrees: Vec<usize> = degrees.iter().copied().map(log2_strict_usize).collect();
    // Extended degree accounts for the ZK blinding factor (2x when ZK is enabled).
    let log_ext_degrees: Vec<usize> = log_degrees.iter().map(|&d| d + config.is_zk()).collect();

    // Fail fast: a wrapped multiplicity makes this proof unverifiable.
    // The verifier enforces the same bound.
    check_multiplicity_height_bound(&common.lookups, &degrees)
        .expect("LogUp multiplicity height-bound violated");

    // Read lookups from the keygen-cached CommonData (not from instances).
    let all_lookups: Vec<&[Lookup<Val<SC>>]> = common.lookups.iter().map(|l| &**l).collect();
    // Per-AIR lookup terminal: `Some(terminal)` once filled, `None` for AIRs with no lookups.
    let mut lookup_terminals: Vec<Option<LookupTerminal<SC::Challenge>>> =
        all_lookups.iter().map(|_| None).collect();

    // Base and extended domains for every instance.
    let (trace_domains, ext_trace_domains): (Vec<Domain<SC>>, Vec<Domain<SC>>) = degrees
        .iter()
        .map(|&deg| {
            (
                pcs.natural_domain_for_degree(deg),
                pcs.natural_domain_for_degree(deg * (config.is_zk() + 1)),
            )
        })
        .unzip();

    // Extract AIRs and borrow public values; consume traces later without cloning.
    let airs: Vec<&A> = instances.iter().map(|i| i.air).collect();
    let pub_vals: Vec<&[Val<SC>]> = instances
        .iter()
        .map(|i| i.public_values.as_slice())
        .collect();

    // Determine preprocessed widths and quotient chunk counts per instance.
    let mut preprocessed_widths = Vec::with_capacity(airs.len());
    let (log_num_quotient_chunks, num_quotient_chunks): (Vec<usize>, Vec<usize>) = airs
        .iter()
        .zip(pub_vals.iter())
        .enumerate()
        .map(|(i, (air, _pv))| {
            // Width of the preprocessed trace for this instance (0 if absent).
            let pre_w = common
                .preprocessed
                .as_ref()
                .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
                .unwrap_or(0);
            preprocessed_widths.push(pre_w);

            let layout = AirLayout {
                preprocessed_width: pre_w,
                main_width: air.width(),
                num_public_values: air.num_public_values(),
                num_periodic_columns: air.num_periodic_columns(),
                ..Default::default()
            };

            // Infer the log of the quotient polynomial degree from symbolic analysis.
            let lq_chunks =
                info_span!("infer log of constraint degree", air_idx = i).in_scope(|| {
                    get_log_num_quotient_chunks::<Val<SC>, SC::Challenge, A, LogUpGadget>(
                        air,
                        layout,
                        all_lookups[i],
                        config.is_zk(),
                        &lookup_gadget,
                    )
                });
            // Actual number of quotient chunks (doubled when ZK is enabled).
            let n_chunks = 1 << (lq_chunks + config.is_zk());
            (lq_chunks, n_chunks)
        })
        .unzip();

    let n_instances = airs.len();
    let widths: Vec<usize> = airs.iter().map(|a| A::width(a)).collect();

    // Transcript: Observe instance count and per-instance bindings.
    transcript.observe_instance_count(n_instances);
    for i in 0..n_instances {
        transcript.observe_instance_binding(
            log_ext_degrees[i],
            log_degrees[i],
            widths[i],
            num_quotient_chunks[i],
        );
    }

    // Transcript: Main trace commitment

    // Build PCS inputs for every instance and commit in a single batch.
    let main_commit_inputs = instances
        .iter()
        .zip(ext_trace_domains.iter().cloned())
        .map(|(inst, dom)| (dom, inst.trace.clone()))
        .collect::<Vec<_>>();
    let (main_commit, main_data) = pcs.commit(main_commit_inputs);

    transcript.observe_main(&main_commit, &pub_vals);
    transcript.observe_preprocessed(&preprocessed_widths, common.preprocessed.as_ref());

    // Transcript: Lookup challenges and permutation traces

    // Draw per-instance challenges for the lookup argument.
    let challenges_per_instance = transcript.sample_perm_challenges(&all_lookups, &lookup_gadget);

    // Generate permutation traces for instances that have lookups.
    let mut permutation_commit_inputs = Vec::with_capacity(n_instances);
    instances
        .iter()
        .enumerate()
        .zip(ext_trace_domains.iter().cloned())
        .for_each(|((i, inst), ext_domain)| {
            if !all_lookups[i].is_empty() {
                // Compute the permutation argument trace and the AIR's single terminal.
                let (generated_perm, terminal) = lookup_gadget.generate_permutation::<SC>(
                    inst.trace,
                    &inst.air.preprocessed_trace(),
                    &inst.public_values,
                    all_lookups[i],
                    &challenges_per_instance[i],
                );

                // Record the AIR's terminal for transcript observation and proof emission.
                lookup_terminals[i] = terminal;

                #[cfg(debug_assertions)]
                {
                    use self::check_constraints::check_constraints;

                    let preprocessed_trace = inst.air.preprocessed_trace();

                    let perm_vals: Vec<SC::Challenge> = terminal.iter().map(|t| t.0).collect();
                    let lookup_constraints_inputs = (all_lookups[i], &lookup_gadget);
                    check_constraints(
                        inst.air,
                        inst.trace,
                        &preprocessed_trace,
                        &generated_perm,
                        &challenges_per_instance[i],
                        &perm_vals,
                        &inst.public_values,
                        lookup_constraints_inputs,
                    );
                }

                // Consume the generated matrix directly; no extra clone before flattening.
                permutation_commit_inputs.push((ext_domain, generated_perm.flatten_to_base()));
            }
        });

    // Debug-only: verify that all lookup sums balance across instances.
    #[cfg(debug_assertions)]
    {
        use p3_lookup::debug_util::{check_lookups, LookupDebugInstance};

        let preprocessed_traces: Vec<_> = instances
            .iter()
            .map(|inst| inst.air.preprocessed_trace())
            .collect();
        let debug_instances: Vec<_> = instances
            .iter()
            .zip(preprocessed_traces.iter())
            .zip(all_lookups.iter())
            .map(|((inst, prep), lookups)| LookupDebugInstance {
                main_trace: inst.trace,
                preprocessed_trace: prep,
                public_values: &inst.public_values,
                lookups,
                permutation_challenges: &[],
            })
            .collect();
        check_lookups(&debug_instances);
    }

    // Commit all permutation traces (if any).
    let permutation_commit_and_data = if !permutation_commit_inputs.is_empty() {
        Some(pcs.commit(permutation_commit_inputs))
    } else {
        None
    };

    // Transcript: observe permutation commitment + per-AIR terminals, sample alpha.
    let alpha: Challenge<SC> = transcript.observe_perm_and_sample_alpha(
        permutation_commit_and_data.as_ref().map(|(c, _)| c),
        &lookup_terminals,
    );

    // Capture only the permutation prover data;
    //
    // The commitment isn't read in the parallel closure below.
    let permutation_data = permutation_commit_and_data.as_ref().map(|(_, data)| data);

    // Permutation-matrix index per instance: the prefix count of prior instances
    // that contribute a permutation trace. Precomputing this removes the only
    // cross-iteration dependency, so each instance's quotient is independent.
    let perm_indices: Vec<usize> = all_lookups
        .iter()
        .scan(0usize, |next, lookups| {
            let idx = *next;
            if !lookups.is_empty() {
                *next += 1;
            }
            Some(idx)
        })
        .collect();

    // Each instance's quotient chunks are independent, so compute them in
    // parallel. `quotient_values` already parallelises over rows; with many
    // instances this fills the cores that a single instance leaves idle.
    let per_instance: Vec<InstanceQuotient<SC>> = (0..n_instances)
        .into_par_iter()
        .map(|i| {
            let _air_span = info_span!("compute quotient", air_idx = i).entered();

            let log_chunks = log_num_quotient_chunks[i];
            let n_chunks = num_quotient_chunks[i];
            // Build the quotient domain: disjoint from the trace domain,
            // with size = ext_degree * num_quotient_chunks.
            let quotient_domain =
                ext_trace_domains[i].create_disjoint_domain(1 << (log_ext_degrees[i] + log_chunks));

            let sym_layout = AirLayout {
                preprocessed_width: preprocessed_widths[i],
                main_width: airs[i].width(),
                num_public_values: airs[i].num_public_values(),
                num_periodic_columns: airs[i].num_periodic_columns(),
                ..Default::default()
            };

            // Debug-only: verify the static constraint-count hint matches symbolic analysis.
            debug_assert!(
                airs[i].num_constraints().is_none_or(|n| {
                    n == get_symbolic_constraints(
                        airs[i],
                        sym_layout,
                        all_lookups[i],
                        &lookup_gadget,
                    )
                    .0
                    .len()
                }),
                "num_constraints() = {} but symbolic evaluation found {} base constraints",
                airs[i].num_constraints().unwrap(),
                get_symbolic_constraints(airs[i], sym_layout, all_lookups[i], &lookup_gadget,)
                    .0
                    .len(),
            );

            // Evaluate the committed main trace on the quotient domain via LDE.
            let trace_on_quotient_domain =
                pcs.get_evaluations_on_domain(&main_data, i, quotient_domain);

            // Evaluate the permutation trace on the quotient domain (if lookups exist).
            let permutation_on_quotient_domain = permutation_data
                .filter(|_| !all_lookups[i].is_empty())
                .map(|perm_data| {
                    pcs.get_evaluations_on_domain(perm_data, perm_indices[i], quotient_domain)
                });

            // Evaluate preprocessed columns on the quotient domain (if present).
            let preprocessed_on_quotient_domain = common
                .preprocessed
                .as_ref()
                .and_then(|g| g.instances[i].as_ref())
                .map(|meta| {
                    let preprocessed_prover_data = prover_data
                        .prover_only
                        .preprocessed_prover_data
                        .as_ref()
                        .expect(
                            "preprocessed_prover_data must exist when preprocessed columns exist",
                        );
                    pcs.get_evaluations_on_domain_no_random(
                        preprocessed_prover_data,
                        meta.matrix_index,
                        quotient_domain,
                    )
                });

            // Compute quotient(x) = constraints(x) / Z_H(x) on the quotient domain.
            let perm_vals: Vec<_> = lookup_terminals[i].iter().map(|t| t.0).collect();
            let q_values = quotient_values(
                pcs,
                airs[i],
                pub_vals[i],
                sym_layout,
                trace_domains[i],
                quotient_domain,
                &trace_on_quotient_domain,
                permutation_on_quotient_domain.as_ref(),
                all_lookups[i],
                &perm_vals,
                &lookup_gadget,
                &challenges_per_instance[i],
                preprocessed_on_quotient_domain.as_ref(),
                alpha,
            );

            // Flatten extension values to base field and split into degree-bounded chunks.
            let q_flat = RowMajorMatrix::new_col(q_values).flatten_to_base();
            let chunk_mats = quotient_domain.split_evals(n_chunks, q_flat);
            let chunk_domains = quotient_domain.split_domains(n_chunks);
            // Keep evaluations small; the callback transforms and commits on device.
            (chunk_domains, chunk_mats)
        })
        .collect();

    // Concatenate in instance order so the commit layout stays deterministic.
    let mut quotient_chunk_domains = Vec::new();
    let mut quotient_chunk_mats = Vec::new();
    let mut quotient_chunk_ranges = Vec::with_capacity(n_instances);
    for (chunk_domains, ldes) in per_instance {
        let start = quotient_chunk_domains.len();
        quotient_chunk_mats.push((chunk_domains.clone(), ldes));
        quotient_chunk_domains.extend(chunk_domains);
        let end = quotient_chunk_domains.len();
        quotient_chunk_ranges.push((start, end));
    }

    // Commit all quotient chunks in a single batch.
    let (quotient_commit, quotient_data) = commit_quotients(pcs, quotient_chunk_mats);
    transcript.observe_quotient_commitment(&quotient_commit);

    // Transcript: Optional ZK randomization polynomial
    //
    // When ZK is enabled, commit to a random extension-field polynomial of
    // degree 2n. The PCS later adds (R(X) - R(z)) / (X - z) to the batch,
    // hiding the trace values at the query points.
    //
    // TODO: This approach is only statistically ZK.
    // A perfectly-ZK version would use a true extension-field polynomial.
    let (opt_r_commit, opt_r_data) = if SC::Pcs::ZK {
        let (r_commit, r_data) = pcs
            .get_opt_randomization_poly_commitment(ext_trace_domains.iter().copied())
            .expect("ZK is enabled, so we should have randomization commitments");
        (Some(r_commit), Some(r_data))
    } else {
        (None, None)
    };

    if let Some(r_commit) = &opt_r_commit {
        transcript.observe_random_commitment(r_commit);
    }

    // Transcript: OOD opening

    // Sample the out-of-domain evaluation point.
    let zeta: Challenge<SC> = transcript.sample_zeta();

    // Build the opening rounds and produce the FRI opening proof.
    let (opened_values, opening_proof) = {
        let mut rounds = Vec::new();

        // Round 0 (optional): randomization polynomial opened at zeta per instance.
        let round0 = opt_r_data.as_ref().map(|r_data| {
            let round0_points = trace_domains.iter().map(|_| vec![zeta]).collect();
            (r_data, round0_points)
        });
        rounds.extend(round0);

        // Round 1: main trace. Open at zeta; also at the next domain point
        // if the AIR accesses the next row.
        let round1_points = trace_domains
            .iter()
            .enumerate()
            .map(|(i, dom)| {
                if !airs[i].main_next_row_columns().is_empty() {
                    vec![
                        zeta,
                        dom.next_point(zeta)
                            .expect("domain should support next_point operation"),
                    ]
                } else {
                    vec![zeta]
                }
            })
            .collect::<Vec<_>>();
        rounds.push((&main_data, round1_points));

        // Round 2: quotient chunks, each opened at zeta only.
        let round2_points = quotient_chunk_ranges
            .iter()
            .cloned()
            .flat_map(|(s, e)| (s..e).map(|_| vec![zeta]))
            .collect::<Vec<_>>();
        rounds.push((&quotient_data, round2_points));

        // Round 3 (optional): preprocessed columns. Open at zeta, and also
        // at the next-row point if the AIR reads preprocessed next-row columns.
        if let Some(global) = &common.preprocessed {
            let preprocessed_prover_data = prover_data
                .prover_only
                .preprocessed_prover_data
                .as_ref()
                .expect("preprocessed_prover_data must exist when preprocessed columns exist");
            let pre_points = global
                .matrix_to_instance
                .iter()
                .map(|&inst_idx| {
                    if !airs[inst_idx].preprocessed_next_row_columns().is_empty() {
                        let zeta_next_i = trace_domains[inst_idx]
                            .next_point(zeta)
                            .expect("domain should support next_point operation");
                        vec![zeta, zeta_next_i]
                    } else {
                        vec![zeta]
                    }
                })
                .collect();
            rounds.push((preprocessed_prover_data, pre_points));
        }

        // Round 4 (optional): permutation traces for instances with lookups.
        // Always opened at both zeta and the next-row point.
        let lookup_points: Vec<_> = trace_domains
            .iter()
            .zip(&all_lookups)
            .filter(|&(_, lookups)| !lookups.is_empty())
            .map(|(dom, _)| {
                vec![
                    zeta,
                    dom.next_point(zeta)
                        .expect("domain should support next_point operation"),
                ]
            })
            .collect();

        if let Some((_, perm_data)) = &permutation_commit_and_data {
            let lookup_round = (perm_data, lookup_points);
            rounds.push(lookup_round);
        }

        pcs.open_with_preprocessing(
            rounds,
            &mut transcript.challenger,
            common.preprocessed.is_some(),
        )
    };

    // Parse opened values into per-instance structures

    // Permutation round follows preprocessed (if present), else takes its slot.
    let permutation_idx = if common.preprocessed.is_some() {
        SC::Pcs::PREPROCESSED_TRACE_IDX + 1
    } else {
        SC::Pcs::PREPROCESSED_TRACE_IDX
    };

    // Main trace opened values: one entry per instance.
    let trace_values_for_mats = &opened_values[SC::Pcs::TRACE_IDX];
    assert_eq!(trace_values_for_mats.len(), n_instances);

    let mut per_instance = Vec::with_capacity(n_instances);

    // Preprocessed openings (if a global preprocessed commitment exists).
    let preprocessed_openings = common
        .preprocessed
        .as_ref()
        .map(|_| &opened_values[SC::Pcs::PREPROCESSED_TRACE_IDX]);

    // Iterator over permutation opened values (one per instance with lookups).
    let is_lookup = permutation_commit_and_data.is_some();
    let permutation_values_for_mats = if is_lookup {
        &opened_values[permutation_idx]
    } else {
        &vec![]
    };
    let mut permutation_values_for_mats = permutation_values_for_mats.iter();

    // Iterate over quotient chunk ranges to assemble per-instance opened values.
    let mut quotient_openings_iter = opened_values[SC::Pcs::QUOTIENT_IDX].iter();
    for (i, (s, e)) in quotient_chunk_ranges.iter().copied().enumerate() {
        // Optional randomization polynomial opening.
        let random = if opt_r_data.is_some() {
            Some(opened_values[0][i][0].clone())
        } else {
            None
        };

        // Main trace: local row always present; next row only if AIR uses it.
        let tv = &trace_values_for_mats[i];
        let trace_local = tv[0].clone();
        let trace_next = if !airs[i].main_next_row_columns().is_empty() {
            Some(tv[1].clone())
        } else {
            None
        };

        // Quotient chunks: collect the zeta-point opening of each chunk.
        let mut qcs = Vec::with_capacity(e - s);
        for _ in s..e {
            let mat_vals = quotient_openings_iter
                .next()
                .expect("chunk index in bounds");
            qcs.push(mat_vals[0].clone());
        }

        // Preprocessed openings: local and optionally next row.
        let (preprocessed_local, preprocessed_next) = if let (Some(global), Some(pre_round)) =
            (&common.preprocessed, preprocessed_openings)
        {
            global.instances[i].as_ref().map_or((None, None), |meta| {
                let vals = &pre_round[meta.matrix_index];
                if !airs[i].preprocessed_next_row_columns().is_empty() {
                    assert_eq!(
                        vals.len(),
                        2,
                        "expected two opening points (zeta, zeta_next) for preprocessed trace"
                    );
                    (Some(vals[0].clone()), Some(vals[1].clone()))
                } else {
                    assert_eq!(
                        vals.len(),
                        1,
                        "expected one opening point (zeta) for preprocessed trace"
                    );
                    (Some(vals[0].clone()), None)
                }
            })
        } else {
            (None, None)
        };

        // Permutation openings: present only for instances with lookups.
        let (permutation_local, permutation_next) = if !all_lookups[i].is_empty() {
            let perm_v = permutation_values_for_mats
                .next()
                .expect("instance should have permutation openings");
            (perm_v[0].clone(), perm_v[1].clone())
        } else {
            (vec![], vec![])
        };

        // Assemble the complete opened values for this instance.
        let base_opened = OpenedValues {
            trace_local,
            trace_next,
            preprocessed_local,
            preprocessed_next,
            quotient_chunks: qcs,
            random,
        };

        per_instance.push(OpenedValuesWithLookups {
            base_opened_values: base_opened,
            permutation_local,
            permutation_next,
        });
    }

    // Extract the permutation commitment (if any) for inclusion in the proof.
    let permutation = permutation_commit_and_data
        .as_ref()
        .map(|(comm, _)| comm.clone());

    // Assemble the final proof structure.
    BatchProof {
        commitments: BatchCommitments {
            main: main_commit,
            quotient_chunks: quotient_commit,
            random: opt_r_commit,
            permutation,
        },
        opened_values: BatchOpenedValues {
            instances: per_instance,
        },
        opening_proof,
        lookup_terminals,
        degree_bits: log_ext_degrees,
    }
}
