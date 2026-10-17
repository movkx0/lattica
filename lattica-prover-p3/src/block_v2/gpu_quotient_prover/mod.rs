//! Adapted from p3-batch-stark 0.6.1 (Plonky3 contributors), Apache-2.0.
//! See LICENSE-APACHE in this directory. Original source SHA-256:
//! 187a2d56e80f692171894aec7af88a618c11c2ae840d54ecec08a4f354cc0948
//! Changes: upstream public types/helpers; quotient evaluations go to a
//! commitment callback; debug checks retained. Transcript and proof encoding
//! are unchanged; opened values move into admitted native containers.
//! Only the explicit GPU quotient research switch selects this.
//! Batch-STARK prover: commits traces, computes quotient polynomials, and
//! produces opening proofs for multiple AIR instances in a single FRI batch.

use p3_air::symbolic::{AirLayout, SymbolicExpressionExt};
mod compile;
mod domain;
mod evaluate;
use domain::ProverDomain;
mod input;
mod opened_values;
#[cfg(feature = "gpu")]
pub(crate) mod uni;
pub(super) use input::ProvingInstance;
pub(crate) mod lookup_program;
pub(crate) mod program;
#[cfg(test)]
mod tests;
use p3_air::Air;
#[cfg(debug_assertions)]
use p3_air::DebugConstraintBuilder;
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{Algebra, PrimeField64};
#[cfg(feature = "gpu-metal")]
mod metal;
use p3_lookup::folder::ProverConstraintFolderWithLookups;
use p3_lookup::logup::LogUpGadget;
use p3_lookup::{
    check_multiplicity_height_bound, InteractionSymbolicBuilder, Lookup, LookupProtocol,
    LookupTerminal,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_util::log2_strict_usize;
use rayon::prelude::*;
use tracing::{info_span, instrument};

use p3_batch_stark::common::ProverData;
use p3_batch_stark::config::{Challenge, Domain, StarkGenericConfig as SGC, Val};
use p3_batch_stark::proof::{BatchCommitments, BatchOpenedValues, BatchProof};
use p3_batch_stark::prover::quotient_values;
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks, get_symbolic_constraints};
use p3_batch_stark::{BatchTranscript, StarkInstance};
#[cfg(debug_assertions)]
mod check_constraints;

/// Per-instance quotient output: chunk domains and unextended evaluations.
pub(super) type InstanceQuotient<SC> = (Vec<Domain<SC>>, Vec<RowMajorMatrix<Val<SC>>>);

enum QuotientOutput<SC: SGC> {
    Host(Vec<Challenge<SC>>),
    Device(super::gpu_hash::device::DeviceMatrix),
}

enum InstanceOutput<SC: SGC> {
    Host(InstanceQuotient<SC>),
    Device {
        domain: super::gpu_hash::device::DomainSpec,
        chunks: usize,
        values: super::gpu_hash::device::DeviceMatrix,
    },
}

#[instrument(skip_all)]
pub(super) fn prove_batch<
    SC,
    #[cfg(debug_assertions)] A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>
        + Air<super::machine::symbolic::Builder>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
    #[cfg(not(debug_assertions))] A: for<'a> Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>
        + Air<super::machine::symbolic::Builder>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
>(
    config: &SC,
    instances: Vec<ProvingInstance<'_, SC, A>>,
    prover_data: &ProverData<SC>,
    release_quotient_prefix: impl Fn(&mut <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData),
    commit_quotients: impl FnOnce(
        &SC::Pcs,
        Vec<InstanceQuotient<SC>>,
    ) -> (
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData,
    ),
    run: &crate::proving::Run,
) -> BatchProof<SC>
where
    SC: SGC<
        Challenge = super::profile::Challenge,
        Pcs = super::quotient_pcs::CandidatePcs,
        Challenger = super::profile::Challenger,
    >,
    Val<SC>: PrimeField64,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Domain<SC>: Send + Sync,
    SC::Pcs: Sync
        + Pcs<
            super::profile::Challenge,
            SC::Challenger,
            Domain = p3_field::coset::TwoAdicMultiplicativeCoset<crate::config::Val>,
        >,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    let pcs = config.pcs();
    let _execution_observation = pcs
        .observe_execution(run)
        .expect("GPU execution observation admission failed");
    let randomness_attempt = pcs
        .begin_randomness_attempt()
        .expect("GPU randomness attempt failed; use a fresh proof configuration");
    // Cover a failed device snapshot before the new challenger can create its
    // own guard. Failed transcript initialization must also retire the RNGs.
    let challenger = config.initialise_challenger();
    let transcript_attempt = challenger
        .begin_attempt()
        .expect("GPU transcript attempt failed; use a fresh proof configuration");
    let _randomness_observation = pcs
        .observe_randomness(run)
        .expect("GPU randomness stage admission failed");
    pcs.check_gpu_challenger(&challenger)
        .expect("GPU transcript selection or proof session mismatch");
    let _transcript_observation = challenger
        .observe_execution(run)
        .expect("GPU transcript stage admission failed");
    let (instances, traces): (Vec<_>, Vec<_>) = instances
        .into_iter()
        .map(|instance| (instance.metadata, instance.trace))
        .unzip();
    let common = &prover_data.common;
    // TODO: Extend if additional lookup gadgets are added.
    let lookup_gadget = LogUpGadget::new();

    let device_main = traces.iter().any(|trace| trace.host().is_none());
    assert!(
        !challenger.is_gpu() || device_main,
        "GPU transcript requires a device-owned main trace"
    );
    if device_main {
        assert!(
            !instances.is_empty() && instances.len() <= 256,
            "device main AIR count"
        );
        assert_eq!(
            config.is_zk(),
            1,
            "device main traces require the hiding profile"
        );
        assert!(
            super::quotient_pcs::gpu_quotient_resident_enabled()
                && super::quotient_pcs::gpu_lookup_enabled(),
            "device main traces require owned GPU quotient and lookup consumers"
        );
        let session = pcs.quotient_session().expect("device main trace session");
        for (instance, trace) in instances.iter().zip(&traces) {
            assert_eq!(
                instance.public_values.len(),
                instance.air.num_public_values()
            );
            trace
                .validate_device(&session, instance.air.width())
                .expect("device main trace rejected before commitment randomness");
        }
    }
    // CPU lookup borrows its original traces. Device inputs have no host
    // representation and must never enter CPU lookup generation.
    let host_traces: Vec<_> = traces.iter().map(|trace| trace.host()).collect();
    #[cfg(debug_assertions)]
    let audit_traces: Vec<std::borrow::Cow<'_, RowMajorMatrix<Val<SC>>>> = run
        .measure(
            crate::proving::Stage::ConstraintAudit,
            crate::proving::Backend::Cpu,
            || {
                traces
                    .iter()
                    .map(|trace| match trace {
                        input::TraceInput::Host(matrix) => std::borrow::Cow::Borrowed(*matrix),
                        input::TraceInput::Device(matrix) => std::borrow::Cow::Owned(
                            pcs.audit_main_device(matrix)
                                .expect("explicit device main trace debug audit"),
                        ),
                    })
                    .collect()
            },
        )
        .expect("CPU trace debug audit not admitted");
    let gpu_scalars = challenger.is_gpu();
    let mut transcript = BatchTranscript::<SC>::new(challenger);

    // Collect per-instance degree information.
    let degrees: Vec<usize> = traces.iter().map(|trace| trace.height()).collect();
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
    let (trace_domains, ext_trace_domains): (Vec<ProverDomain>, Vec<ProverDomain>) = degrees
        .iter()
        .map(|&deg| {
            (
                ProverDomain::natural(pcs, deg, gpu_scalars),
                ProverDomain::natural(pcs, deg * (config.is_zk() + 1), gpu_scalars),
            )
        })
        .unzip();

    // Extract AIRs and borrow public values; consume traces later without cloning.
    let airs: Vec<&A> = instances.iter().map(|i| i.air).collect();
    let pub_vals: Vec<&[Val<SC>]> = instances.iter().map(|i| i.public_values).collect();

    // Determine preprocessed widths and quotient chunk counts per instance.
    let gpu_symbolic = super::quotient_pcs::gpu_quotient_eval_enabled()
        || super::quotient_pcs::gpu_quotient_resident_enabled();
    // Admit aggregate instruction storage before allocation/session creation.
    // Compile AIRs sequentially so symbolic scratch is shared across the batch.
    let mut compiled = gpu_symbolic.then(|| {
        compile::Batch::new(airs.len(), pcs.host_output_budget())
            .expect("GPU quotient compiler admission failed; no fallback")
    });
    let compiler_session = gpu_symbolic.then(|| {
        // Host-input evaluation has no owned PCS session. Its public compiler
        // arithmetic still gets an explicit session from the selected engine.
        if super::quotient_pcs::gpu_quotient_resident_enabled() {
            pcs.quotient_session()
        } else {
            super::gpu_hash::device::DeviceSession::new()
        }
        .expect("GPU quotient compiler session failed; no fallback")
    });
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
            let lq_chunks = if let Some(compiled) = &mut compiled {
                let (program, log_chunks, base_count) = compile::air(
                    compiler_session
                        .as_ref()
                        .expect("selected compiler session"),
                    run,
                    *air,
                    layout,
                    all_lookups[i],
                    config.is_zk(),
                )
                .expect("GPU quotient compilation failed; no fallback");
                compiled
                    .push(program, log_chunks, base_count)
                    .expect("GPU quotient batch storage admission failed; no fallback");
                compiled.get(i).log_chunks
            } else {
                info_span!("infer log constraint degree", air_idx = i).in_scope(|| {
                    get_log_num_quotient_chunks::<Val<SC>, SC::Challenge, A, LogUpGadget>(
                        air,
                        layout,
                        all_lookups[i],
                        config.is_zk(),
                        &lookup_gadget,
                    )
                })
            };
            let n_chunks = lq_chunks
                .checked_add(config.is_zk())
                .and_then(|bits| u32::try_from(bits).ok())
                .and_then(|bits| 1usize.checked_shl(bits))
                .expect("quotient chunk geometry exceeds host word size");
            (lq_chunks, n_chunks)
        })
        .unzip();

    if let Some(compiled) = &compiled {
        compiled.report();
    }
    drop(compiler_session);

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

    // Compile/validate lookup metadata before consuming the main commitment RNG.
    let lookup_session = super::quotient_pcs::gpu_lookup_enabled().then(|| {
        pcs.quotient_session()
            .expect("GPU lookup requires owned resident PCS")
    });
    let lookup_programs: Vec<_> = all_lookups
        .iter()
        .enumerate()
        .map(|(i, lookups)| {
            lookup_session
                .as_ref()
                .filter(|_| !lookups.is_empty())
                .map(|session| {
                    let layout = AirLayout {
                        preprocessed_width: preprocessed_widths[i],
                        ..AirLayout::from_air::<crate::config::Val>(airs[i])
                    };
                    let program = std::sync::Arc::new(
                        lookup_program::LookupProgram::compile(layout, lookups)
                            .expect("GPU lookup expression layout rejected"),
                    );
                    session
                        .prepare_lookup(program)
                        .expect("GPU lookup program admission failed")
                })
        })
        .collect();

    // Transcript: Main trace commitment

    if device_main {
        assert!(
            num_quotient_chunks.iter().sum::<usize>() <= 256,
            "device batch exceeds aggregate quotient matrix bound before main draws"
        );
    }
    if pcs.uses_gpu_randomness() {
        let bounds: Vec<_> = (0..n_instances)
            .map(|i| super::randomness::resources::Bounds {
                rows: degrees[i] as u64,
                main_columns: widths[i] as u64,
                preprocessing_columns: preprocessed_widths[i] as u64,
                lookup_columns: if all_lookups[i].is_empty() {
                    0
                } else {
                    3 * (all_lookups[i].len() as u64 + 1)
                },
                quotient_rows: (degrees[i] as u64)
                    .checked_shl(1 + log_num_quotient_chunks[i] as u32)
                    .expect("GPU randomness quotient height overflow"),
                quotient_chunks: num_quotient_chunks[i] as u64,
            })
            .collect();
        super::randomness::resources::check_batch_worker(true, &bounds)
            .expect("GPU randomness proof exceeds worker reservation before main draws");
    }
    // Build PCS inputs for every instance and commit in a single batch.
    let (main_commit, mut main_data) = if device_main {
        let inputs = traces
            .into_iter()
            .zip(ext_trace_domains.iter().copied())
            .map(|(trace, domain)| match trace {
                input::TraceInput::Device(matrix) => (domain, matrix),
                input::TraceInput::Host(_) => unreachable!("validated device trace batch"),
            })
            .collect();
        pcs.commit_main_device(inputs)
            .expect("GPU main commitment failed; no silent fallback")
    } else {
        let inputs: Vec<_> = host_traces
            .iter()
            .zip(ext_trace_domains.iter().copied())
            .map(|(trace, domain)| (domain.cpu(), (*trace.expect("host trace batch")).clone()))
            .collect();
        pcs.commit(inputs)
    };

    transcript.observe_main(&main_commit, &pub_vals);
    transcript.observe_preprocessed(&preprocessed_widths, common.preprocessed.as_ref());

    // Transcript: Lookup challenges and permutation traces

    // Draw per-instance challenges for the lookup argument.
    let challenges_per_instance = if gpu_scalars {
        assert_eq!(lookup_gadget.num_challenges(), 2);
        transcript.challenger.gpu_lookup_challenges(&all_lookups)
    } else {
        transcript.sample_perm_challenges(&all_lookups, &lookup_gadget)
    };

    // Generate each permutation trace on the explicitly selected backend.
    let mut permutation_commit_inputs = Vec::with_capacity(n_instances);
    let mut permutation_device_inputs = Vec::with_capacity(n_instances);
    for ((i, inst), ext_domain) in instances
        .iter()
        .enumerate()
        .zip(ext_trace_domains.iter().cloned())
    {
        if all_lookups[i].is_empty() {
            continue;
        }
        #[cfg(debug_assertions)]
        let audit = |generated: &RowMajorMatrix<SC::Challenge>,
                     terminal: &Option<LookupTerminal<SC::Challenge>>| {
            run.measure(
                crate::proving::Stage::ConstraintAudit,
                crate::proving::Backend::Cpu,
                || {
                    let preprocessed_trace = inst.air.preprocessed_trace();
                    let perm_vals: Vec<_> = terminal.iter().map(|t| t.0).collect();
                    self::check_constraints::check_constraints(
                        inst.air,
                        audit_traces[i].as_ref(),
                        &preprocessed_trace,
                        generated,
                        &challenges_per_instance[i],
                        &perm_vals,
                        &inst.public_values,
                        (all_lookups[i], &lookup_gadget),
                    );
                },
            )
            .expect("CPU constraint debug audit not admitted")
        };
        if let Some(session) = &lookup_session {
            use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
            let public: Vec<_> = inst
                .public_values
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect();
            let challenges: Vec<[u64; 3]> = challenges_per_instance[i]
                .iter()
                .map(|c| {
                    let coefficients: &[crate::config::Val] = c.as_basis_coefficients_slice();
                    std::array::from_fn(|j| coefficients[j].as_canonical_u64())
                })
                .collect();
            let (generated, terminal) = run
                .measure(
                    crate::proving::Stage::Lookup,
                    crate::proving::Backend::OpenCl,
                    || {
                        let main = pcs.lookup_original_trace(
                            &main_data,
                            i,
                            log_degrees[i] as u32,
                            widths[i],
                        )?;
                        let pre = common
                            .preprocessed
                            .as_ref()
                            .and_then(|g| g.instances[i].as_ref())
                            .map(|meta| {
                                pcs.lookup_original_trace(
                                    prover_data
                                        .prover_only
                                        .preprocessed_prover_data
                                        .as_ref()
                                        .expect("preprocessing data"),
                                    meta.matrix_index,
                                    log_degrees[i] as u32,
                                    meta.width,
                                )
                            })
                            .transpose()?;
                        session.lookup_permutation(
                            lookup_programs[i].as_ref().expect("prepared GPU lookup"),
                            &main,
                            pre.as_ref(),
                            &public,
                            &challenges,
                        )
                    },
                )
                .expect("admitted GPU lookup stage")
                .expect("GPU lookup execution failed");
            let terminal = Some(LookupTerminal(SC::Challenge::from_basis_coefficients_fn(
                |j| crate::config::Val::from_u64(terminal[j]),
            )));
            #[cfg(debug_assertions)]
            {
                let audit_matrix = run
                    .measure(
                        crate::proving::Stage::ConstraintAudit,
                        crate::proving::Backend::Cpu,
                        || {
                            let words = session
                                .read(&generated, generated.spec().bytes())
                                .expect("GPU lookup debug audit readback");
                            let values = words
                                .chunks_exact(3)
                                .map(|c| {
                                    SC::Challenge::from_basis_coefficients_fn(|j| {
                                        crate::config::Val::from_u64(c[j])
                                    })
                                })
                                .collect();
                            RowMajorMatrix::new(values, all_lookups[i].len() + 1)
                        },
                    )
                    .expect("CPU lookup debug readback not admitted");
                eprintln!(
                    "bounded_lookup_cpu_audit matrix_readback_bytes={}",
                    generated.spec().bytes()
                );
                audit(&audit_matrix, &terminal);
            }
            lookup_terminals[i] = terminal;
            permutation_device_inputs.push((ext_domain, generated));
        } else {
            let (generated, terminal) = run
                .measure(
                    crate::proving::Stage::Lookup,
                    crate::proving::Backend::Cpu,
                    || {
                        lookup_gadget.generate_permutation::<SC>(
                            host_traces[i].expect("CPU lookup cannot consume a device trace"),
                            &inst.air.preprocessed_trace(),
                            &inst.public_values,
                            all_lookups[i],
                            &challenges_per_instance[i],
                        )
                    },
                )
                .expect("admitted CPU lookup stage");
            #[cfg(debug_assertions)]
            audit(&generated, &terminal);
            lookup_terminals[i] = terminal;
            permutation_commit_inputs.push((ext_domain.cpu(), generated.flatten_to_base()));
        }
    }

    // Debug-only: verify that all lookup sums balance across instances.
    #[cfg(debug_assertions)]
    run.measure(
        crate::proving::Stage::ConstraintAudit,
        crate::proving::Backend::Cpu,
        || {
            use p3_lookup::debug_util::{check_lookups, LookupDebugInstance};

            let preprocessed_traces: Vec<_> = instances
                .iter()
                .map(|inst| inst.air.preprocessed_trace())
                .collect();
            let debug_instances: Vec<_> = instances
                .iter()
                .zip(preprocessed_traces.iter())
                .zip(all_lookups.iter())
                .zip(audit_traces.iter())
                .map(|(((inst, prep), lookups), trace)| LookupDebugInstance {
                    main_trace: trace.as_ref(),
                    preprocessed_trace: prep,
                    public_values: &inst.public_values,
                    lookups,
                    permutation_challenges: &[],
                })
                .collect();
            check_lookups(&debug_instances);
        },
    )
    .expect("CPU lookup balance debug audit not admitted");

    // Commit all permutation traces (if any).
    let mut permutation_commit_and_data = if !permutation_device_inputs.is_empty() {
        Some(
            pcs.commit_lookup_device(permutation_device_inputs)
                .expect("GPU permutation commitment failed"),
        )
    } else if !permutation_commit_inputs.is_empty() {
        Some(pcs.commit(permutation_commit_inputs))
    } else {
        None
    };

    // Transcript: observe permutation commitment + per-AIR terminals, sample alpha.
    drop(lookup_programs);
    drop(lookup_session);

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
    let per_instance: Vec<InstanceOutput<SC>> = (0..n_instances)
        .into_par_iter()
        .map(|i| {
            let _air_span = info_span!("compute quotient", air_idx = i).entered();

            let log_chunks = log_num_quotient_chunks[i];
            let n_chunks = num_quotient_chunks[i];
            // Build the quotient domain: disjoint from the trace domain,
            // with size = ext_degree * num_quotient_chunks.
            let quotient_domain =
                ext_trace_domains[i].quotient(pcs, log_ext_degrees[i] + log_chunks);

            let sym_layout = AirLayout {
                preprocessed_width: preprocessed_widths[i],
                main_width: airs[i].width(),
                num_public_values: airs[i].num_public_values(),
                num_periodic_columns: airs[i].num_periodic_columns(),
                ..Default::default()
            };

            if let Some(compiled) = &compiled {
                debug_assert!(airs[i]
                    .num_constraints()
                    .is_none_or(|n| n == compiled.get(i).base_constraints));
            } else {
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
            }

            let q_values: QuotientOutput<SC> =
                if super::quotient_pcs::gpu_quotient_resident_enabled() {
                    QuotientOutput::Device(
                        run.measure(
                            crate::proving::Stage::Quotient,
                            crate::proving::Backend::OpenCl,
                            || {
                                use super::gpu_hash::device::Extension;
                                let session = pcs
                                    .quotient_session()
                                    .expect("owned quotient session required");
                                let main = pcs
                                    .quotient_device_prefix(
                                        &main_data,
                                        i,
                                        quotient_domain,
                                        airs[i].width(),
                                        Extension::Base,
                                    )
                                    .expect("owned main LDE required; no fallback");
                                let permutation = if all_lookups[i].is_empty() {
                                    None
                                } else {
                                    Some(
                                        pcs.quotient_device_prefix(
                                            permutation_data.expect("permutation data"),
                                            perm_indices[i],
                                            quotient_domain,
                                            all_lookups[i].len() + 1,
                                            Extension::Cubic,
                                        )
                                        .expect("owned permutation LDE required; no fallback"),
                                    )
                                };
                                let preprocessed = common
                                    .preprocessed
                                    .as_ref()
                                    .and_then(|g| g.instances[i].as_ref())
                                    .map(|meta| {
                                        pcs.quotient_device_prefix(
                                            prover_data
                                                .prover_only
                                                .preprocessed_prover_data
                                                .as_ref()
                                                .expect("preprocessing data"),
                                            meta.matrix_index,
                                            quotient_domain,
                                            preprocessed_widths[i],
                                            Extension::Base,
                                        )
                                        .expect("owned public preprocessing required; no fallback")
                                    });
                                let terminals: Vec<_> =
                                    lookup_terminals[i].iter().map(|t| t.0).collect();
                                evaluate::owned_quotient(
                                    &session,
                                    &compiled
                                        .as_ref()
                                        .expect("selected GPU program")
                                        .get(i)
                                        .program,
                                    pub_vals[i],
                                    trace_domains[i],
                                    quotient_domain,
                                    &main,
                                    permutation.as_ref(),
                                    &terminals,
                                    &challenges_per_instance[i],
                                    preprocessed.as_ref(),
                                    alpha,
                                )
                                .expect("owned GPU quotient evaluation failed; no fallback")
                            },
                        )
                        .expect("admitted owned GPU quotient stage"),
                    )
                } else {
                    // Evaluate the committed main trace on the quotient domain via LDE.
                    let trace_on_quotient_domain =
                        pcs.get_evaluations_on_domain(&main_data, i, quotient_domain.cpu());

                    // Evaluate the permutation trace on the quotient domain (if lookups exist).
                    let permutation_on_quotient_domain = permutation_data
                        .filter(|_| !all_lookups[i].is_empty())
                        .map(|perm_data| {
                            pcs.get_evaluations_on_domain(
                                perm_data,
                                perm_indices[i],
                                quotient_domain.cpu(),
                            )
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
                                quotient_domain.cpu(),
                            )
                        });

                    // Compute quotient(x) = constraints(x) / Z_H(x) on the quotient domain.
                    let perm_vals: Vec<_> = lookup_terminals[i].iter().map(|t| t.0).collect();
                    let gpu_evaluation = super::quotient_pcs::gpu_quotient_eval_enabled();
                    #[cfg(feature = "gpu-metal")]
                    let metal_evaluation = crate::metal_compute::resident::gpu_quotient()
                        .expect("validated Metal quotient policy");
                    #[cfg(not(feature = "gpu-metal"))]
                    let metal_evaluation = false;
                    let q_values = run
                        .measure(
                            crate::proving::Stage::Quotient,
                            if gpu_evaluation {
                                crate::proving::Backend::OpenCl
                            } else if metal_evaluation {
                                crate::proving::Backend::Metal
                            } else {
                                crate::proving::Backend::Cpu
                            },
                            || {
                                if gpu_evaluation {
                                    return evaluate::quotient_values(
                                        &compiled
                                            .as_ref()
                                            .expect("selected GPU program")
                                            .get(i)
                                            .program,
                                        pub_vals[i],
                                        trace_domains[i].cpu(),
                                        quotient_domain.cpu(),
                                        &trace_on_quotient_domain,
                                        permutation_on_quotient_domain.as_ref(),
                                        &perm_vals,
                                        &challenges_per_instance[i],
                                        preprocessed_on_quotient_domain.as_ref(),
                                        alpha,
                                    )
                                    .expect("GPU quotient evaluation failed; no silent fallback");
                                }
                                #[cfg(feature = "gpu-metal")]
                                if metal_evaluation {
                                    return metal::evaluate::<SC, _, _>(
                                        pcs, airs[i], pub_vals[i], sym_layout,
                                        trace_domains[i].cpu(), quotient_domain.cpu(),
                                        &trace_on_quotient_domain, permutation_on_quotient_domain.as_ref(),
                                        all_lookups[i], &perm_vals, &lookup_gadget,
                                        &challenges_per_instance[i], preprocessed_on_quotient_domain.as_ref(), alpha,
                                    ).expect("validated Metal quotient evaluation");
                                }
                                quotient_values(
                                    pcs,
                                    airs[i],
                                    pub_vals[i],
                                    sym_layout,
                                    trace_domains[i].cpu(),
                                    quotient_domain.cpu(),
                                    &trace_on_quotient_domain,
                                    permutation_on_quotient_domain.as_ref(),
                                    all_lookups[i],
                                    &perm_vals,
                                    &lookup_gadget,
                                    &challenges_per_instance[i],
                                    preprocessed_on_quotient_domain.as_ref(),
                                    alpha,
                                )
                            },
                        )
                        .expect("admitted CPU quotient stage");
                    QuotientOutput::Host(q_values)
                };

            // Flatten extension values to base field and split into degree-bounded chunks.
            match q_values {
                QuotientOutput::Device(values) => InstanceOutput::Device {
                    domain: quotient_domain.into(),
                    chunks: n_chunks,
                    values,
                },
                QuotientOutput::Host(values) => {
                    let q_flat = RowMajorMatrix::new_col(values).flatten_to_base();
                    InstanceOutput::Host((
                        quotient_domain.cpu().split_domains(n_chunks),
                        quotient_domain.cpu().split_evals(n_chunks, q_flat),
                    ))
                }
            }
        })
        .collect();

    release_quotient_prefix(&mut main_data);
    if let Some((_, data)) = &mut permutation_commit_and_data {
        release_quotient_prefix(data);
    }

    // Concatenate in instance order so the commit layout stays deterministic.
    let mut quotient_chunks = 0usize;
    let mut quotient_chunk_mats = Vec::new();
    let mut quotient_chunk_ranges = Vec::with_capacity(n_instances);
    let mut device_quotients = Vec::new();
    for output in per_instance {
        let start = quotient_chunks;
        let chunks = match output {
            InstanceOutput::Host((domains, ldes)) => {
                let count = domains.len();
                quotient_chunk_mats.push((domains, ldes));
                count
            }
            InstanceOutput::Device {
                domain,
                chunks,
                values,
            } => {
                device_quotients.push((domain, values, chunks));
                chunks
            }
        };
        quotient_chunks += chunks;
        let end = quotient_chunks;
        quotient_chunk_ranges.push((start, end));
    }

    let (quotient_commit, quotient_data) = if device_quotients.is_empty() {
        commit_quotients(pcs, quotient_chunk_mats)
    } else {
        assert!(
            quotient_chunk_mats.is_empty() && device_quotients.len() == n_instances,
            "owned quotient commitment requires every AIR on device; no fallback"
        );
        pcs.commit_quotients_device(
            device_quotients
                .iter()
                .map(|(domain, values, chunks)| ((*domain).into(), values, *chunks))
                .collect(),
        )
        .expect("owned quotient commitment failed; no silent fallback")
    };
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
        let (r_commit, r_data) = if gpu_scalars {
            pcs.randomization_device(ext_trace_domains.iter().copied().map(Into::into))
                .expect("owned randomization failed; no fallback")
        } else {
            pcs.get_opt_randomization_poly_commitment(ext_trace_domains.iter().map(|d| d.cpu()))
                .expect("ZK requires randomization commitments")
        };
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
    let next_points = transcript.challenger.next_points(
        zeta,
        &trace_domains
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<_>>(),
    );

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
            .map(|(i, _dom)| {
                if !airs[i].main_next_row_columns().is_empty() {
                    vec![zeta, next_points[i]]
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
                        let zeta_next_i = next_points[inst_idx];
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
            .enumerate()
            .zip(&all_lookups)
            .filter(|&(_, lookups)| !lookups.is_empty())
            .map(|((i, _dom), _)| vec![zeta, next_points[i]])
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

    // Global preprocessing has one matrix per participating instance. Check
    // the inverse map used to construct the opening points before consuming it.
    if let Some(global) = &common.preprocessed {
        assert_eq!(global.instances.len(), n_instances);
        assert!(
            global
                .matrix_to_instance
                .iter()
                .enumerate()
                .all(|(matrix, &i)| {
                    global
                        .instances
                        .get(i)
                        .and_then(Option::as_ref)
                        .is_some_and(|meta| meta.matrix_index == matrix)
                }),
            "preprocessing opening map is not one-to-one"
        );
    }
    let per_instance = opened_values::assemble(
        opened_values,
        quotient_chunk_ranges
            .iter()
            .copied()
            .enumerate()
            .map(|(i, (start, end))| opened_values::Instance {
                main_next: !airs[i].main_next_row_columns().is_empty(),
                quotient_start: start,
                quotient_end: end,
                preprocessed: common.preprocessed.as_ref().and_then(|global| {
                    global.instances[i].as_ref().map(|meta| {
                        (
                            meta.matrix_index,
                            !airs[i].preprocessed_next_row_columns().is_empty(),
                        )
                    })
                }),
                permutation: !all_lookups[i].is_empty(),
            }),
        opened_values::Rounds {
            random: opt_r_data.is_some(),
            preprocessed: common.preprocessed.is_some(),
            permutation: permutation_commit_and_data.is_some(),
        },
        pcs.host_output_budget(),
    )
    .expect("native opened-value handoff admission failed");

    // The opening proof owns its query material; the permutation commitment
    // can now move into the result while its prover data is released.
    let permutation = permutation_commit_and_data.map(|(comm, _)| comm);

    // Assemble the final proof structure.
    let proof = BatchProof {
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
    };
    if let Some(guard) = randomness_attempt {
        guard.complete();
    }
    if let Some(guard) = transcript_attempt {
        guard.complete();
    }
    proof
}
