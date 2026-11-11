//! Constrained batch verifier for a trusted multi-table recursion template.
//! Table shapes and the preprocessing cap come from the caller's registered
//! template. Proof contents supply witnesses, never instructions or keys.
use super::*;
use crate::block_v2::machine::symbolic::{self, Builder};
use p3_air::Air;

struct Openings {
    local: Vec<Extension>,
    next: Option<Vec<Extension>>,
    pre: Vec<Extension>,
    random: Vec<Extension>,
    quotient: Vec<Vec<Extension>>,
    perm_local: Vec<Extension>,
    perm_next: Vec<Extension>,
    terminal: Extension,
}

pub(crate) fn verify<
    A: BaseAir<Val>
        + Air<Builder>
        + Air<p3_lookup::InteractionSymbolicBuilder<Val, profile::Challenge>>
        + super::super::periodic::Source,
>(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    airs: &[A],
    log_heights: &[usize],
    publics: &[Vec<Wire>],
    preprocessing_cap: &[Digest],
    proof: &BatchProof<Config>,
) -> Result<(), CompileError> {
    let n = airs.len();
    if !(1..=8).contains(&n)
        || log_heights.len() != n
        || publics.len() != n
        || log_heights.iter().any(|h| !(3..=24).contains(h))
        || proof.degree_bits != log_heights.iter().map(|h| h + 1).collect::<Vec<_>>()
        || proof.opened_values.instances.len() != n
        || proof.lookup_terminals.len() != n
        || proof.lookup_terminals.iter().any(Option::is_none)
        || proof.commitments.random.is_none()
        || proof.commitments.permutation.is_none()
    {
        return Err(CompileError::Shape("trusted mixed batch geometry"));
    }
    let prepared = airs
        .iter()
        .map(|a| symbolic::prepare_air(a, Constants::cpu()))
        .collect::<Result<Vec<_>, _>>()?;
    let bus = match prepared[0].lookups.first().map(|l| &l.kind) {
        Some(Kind::Global(name)) => name,
        _ => {
            return Err(CompileError::Unsupported(
                "mixed recursion requires one global wire bus",
            ))
        }
    };
    let mut total_chunks = 0usize;
    for (i, (air, prepared)) in airs.iter().zip(&prepared).enumerate() {
        if publics[i].len() != air.num_public_values()
            || air.preprocessed_width() == 0
            || !air.preprocessed_next_row_columns().is_empty()
            || air.num_periodic_columns() != 0
            || prepared.lookups.is_empty()
            || prepared.lookups.iter().any(|l| {
                l.kind != Kind::Global(bus.clone()) || l.elements.iter().any(|e| e.len() != 2)
            })
        {
            return Err(CompileError::Unsupported(
                "mixed recursion table or bus shape",
            ));
        }
        let chunks = 1 << (prepared.log_chunks + 1);
        total_chunks += chunks;
        let permutation_width = (prepared.lookups.len() + 1) * 3;
        let opened = &proof.opened_values.instances[i];
        let base = &opened.base_opened_values;
        if base.trace_local.len() != air.width()
            || base.trace_next.is_some() != !air.main_next_row_columns().is_empty()
            || base
                .trace_next
                .as_ref()
                .is_some_and(|v| v.len() != air.width())
            || base
                .preprocessed_local
                .as_ref()
                .is_none_or(|v| v.len() != air.preprocessed_width())
            || base.preprocessed_next.is_some()
            || base.random.as_ref().is_none_or(|v| v.len() != 3)
            || base.quotient_chunks.len() != chunks
            || base.quotient_chunks.iter().any(|v| v.len() != 3)
            || opened.permutation_local.len() != permutation_width
            || opened.permutation_next.len() != permutation_width
        {
            return Err(CompileError::Shape("mixed batch opened values"));
        }
    }
    if total_chunks > MAX_MATRICES {
        return Err(CompileError::Shape("mixed batch quotient matrix bound"));
    }
    let max_domain = *log_heights.iter().max().unwrap() + 1;
    let log_lde = max_domain + profile::LOG_BLOWUP;
    if preprocessing_cap.len() != 1 << log_lde.min(profile::CAP_HEIGHT) {
        return Err(CompileError::Shape("trusted mixed preprocessing cap"));
    }
    let main_cap = inputs.cap_view(b, Some(&proof.commitments.main), log_lde)?;
    let quotient_cap = inputs.cap_view(b, Some(&proof.commitments.quotient_chunks), log_lde)?;
    let random_cap = inputs.cap_view(b, proof.commitments.random.as_ref(), log_lde)?;
    let perm_cap = inputs.cap_view(b, proof.commitments.permutation.as_ref(), log_lde)?;
    let zero = b.ext_constant([Val::ZERO; 3]);
    let mut total_terminal = zero;
    let mut opened = Vec::with_capacity(n);
    for (i, inst) in proof.opened_values.instances.iter().enumerate() {
        let base = &inst.base_opened_values;
        let terminal = inputs.extension(b, proof.lookup_terminals[i].as_ref().unwrap().0);
        total_terminal = b.ext_add(total_terminal, terminal);
        opened.push(Openings {
            local: inputs.extensions_view(b, Some(&base.trace_local), airs[i].width())?,
            next: base
                .trace_next
                .as_ref()
                .map(|v| inputs.extensions_view(b, Some(v), airs[i].width()))
                .transpose()?,
            pre: inputs.extensions_view(
                b,
                base.preprocessed_local.as_deref(),
                airs[i].preprocessed_width(),
            )?,
            random: inputs.extensions_view(b, base.random.as_deref(), 3)?,
            quotient: base
                .quotient_chunks
                .iter()
                .map(|v| inputs.extensions_view(b, Some(v), 3))
                .collect::<Result<_, _>>()?,
            perm_local: inputs.extensions_view(
                b,
                Some(&inst.permutation_local),
                inst.permutation_local.len(),
            )?,
            perm_next: inputs.extensions_view(
                b,
                Some(&inst.permutation_next),
                inst.permutation_next.len(),
            )?,
            terminal,
        });
    }
    b.ext_assert_equal(total_terminal, zero);
    let mut transcript = Transcript::new(b);
    observe_usize(&mut transcript, b, n);
    for (i, air) in airs.iter().enumerate() {
        for value in [
            log_heights[i] + 1,
            log_heights[i],
            air.width(),
            opened[i].quotient.len(),
        ] {
            observe_usize(&mut transcript, b, value);
        }
    }
    observe_cap(&mut transcript, b, &main_cap);
    for public in publics {
        transcript.observe_slice(b, public);
    }
    for air in airs {
        observe_usize(&mut transcript, b, air.preprocessed_width());
    }
    observe_cap(&mut transcript, b, preprocessing_cap);
    let lookup_alpha = transcript.sample_ext(b);
    let lookup_beta = transcript.sample_ext(b);
    let gamma = b.ext_mul(lookup_beta, lookup_beta);
    let prefix = b.ext_add(lookup_alpha, gamma);
    let challenge_pattern = [prefix, lookup_beta];
    observe_cap(&mut transcript, b, &perm_cap);
    for o in &opened {
        transcript.observe_slice(b, &o.terminal);
    }
    let alpha = transcript.sample_ext(b);
    observe_cap(&mut transcript, b, &quotient_cap);
    observe_cap(&mut transcript, b, &random_cap);
    let zeta = transcript.sample_ext(b);
    let next: Vec<_> = log_heights
        .iter()
        .map(|h| {
            let rotation = b.constant(Val::TWO_ADIC_GENERATORS[*h]);
            b.ext_scale(zeta, rotation)
        })
        .collect();
    let random_points: Vec<_> = opened
        .iter()
        .map(|o| {
            [Point {
                point: zeta,
                values: &o.random,
            }]
        })
        .collect();
    let main_points: Vec<Vec<_>> = opened
        .iter()
        .zip(&next)
        .map(|(o, &next)| {
            let mut points = vec![Point {
                point: zeta,
                values: &o.local,
            }];
            if let Some(values) = &o.next {
                points.push(Point {
                    point: next,
                    values,
                });
            }
            points
        })
        .collect();
    let pre_points: Vec<_> = opened
        .iter()
        .map(|o| {
            [Point {
                point: zeta,
                values: &o.pre,
            }]
        })
        .collect();
    let perm_points: Vec<_> = opened
        .iter()
        .zip(&next)
        .map(|(o, &next)| {
            [
                Point {
                    point: zeta,
                    values: &o.perm_local,
                },
                Point {
                    point: next,
                    values: &o.perm_next,
                },
            ]
        })
        .collect();
    let quotient_points: Vec<_> = opened
        .iter()
        .flat_map(|o| &o.quotient)
        .map(|v| {
            [Point {
                point: zeta,
                values: v,
            }]
        })
        .collect();
    let random_matrices: Vec<_> = random_points.iter().map(|p| p.as_slice()).collect();
    let main_matrices: Vec<_> = main_points.iter().map(|p| p.as_slice()).collect();
    let quotient_matrices: Vec<_> = quotient_points.iter().map(|p| p.as_slice()).collect();
    let pre_matrices: Vec<_> = pre_points.iter().map(|p| p.as_slice()).collect();
    let perm_matrices: Vec<_> = perm_points.iter().map(|p| p.as_slice()).collect();
    let rounds = [
        Round {
            commitment: &random_cap,
            log_domain: max_domain,
            matrices: &random_matrices,
            preprocessing: false,
        },
        Round {
            commitment: &main_cap,
            log_domain: max_domain,
            matrices: &main_matrices,
            preprocessing: false,
        },
        Round {
            commitment: &quotient_cap,
            log_domain: max_domain,
            matrices: &quotient_matrices,
            preprocessing: false,
        },
        Round {
            commitment: preprocessing_cap,
            log_domain: max_domain,
            matrices: &pre_matrices,
            preprocessing: true,
        },
        Round {
            commitment: &perm_cap,
            log_domain: max_domain,
            matrices: &perm_matrices,
            preprocessing: false,
        },
    ];
    let domains: Vec<_> = log_heights.iter().map(|h| h + 1).collect();
    let quotient_domains: Vec<_> = opened
        .iter()
        .zip(&domains)
        .flat_map(|(o, h)| std::iter::repeat_n(*h, o.quotient.len()))
        .collect();
    super::super::pcs::verify_with_heights(
        b,
        inputs,
        &mut transcript,
        &rounds,
        Some(&[
            domains.clone(),
            domains.clone(),
            quotient_domains,
            domains.clone(),
            domains,
        ]),
        Some(&proof.opening_proof),
        None,
    )?;
    for (i, (air, o)) in airs.iter().zip(&opened).enumerate() {
        assert_air_constraints(
            b,
            air,
            &prepared[i],
            &publics[i],
            log_heights[i],
            &o.local,
            o.next.as_deref(),
            &o.pre,
            &o.perm_local,
            &o.perm_next,
            &o.quotient,
            o.terminal,
            zeta,
            alpha,
            Values::repeat(&challenge_pattern, prepared[i].lookups.len())?,
            Constants::cpu(),
        )?;
    }
    Ok(())
}
