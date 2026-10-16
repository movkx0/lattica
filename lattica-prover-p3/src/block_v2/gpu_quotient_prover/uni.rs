//! Owned single-AIR proving with the p3-uni-stark 0.6.1 transcript/proof layout.
//! Adapted from the Plonky3 prover, Apache-2.0; see LICENSE-APACHE.
//! Upstream prover.rs SHA-256:
//! 8a682484ec3b5724387fe8e9d5f98d643788b492848ccc002ee709cb8a9bcc31
//! Periodic polynomials are auxiliary quotient inputs, never commitments or
//! extra verifier inputs. Private trace, quotient and PCS matrices stay on GPU.
use super::{compile, evaluate, input::TraceInput, opened_values, program::Program};
use crate::block_v2::{
    gpu_hash::device::{DeviceMatrix, DeviceSession, DomainSpec, Extension, MatrixSpec, RowOrder},
    machine::{compiler_constants::Constants, symbolic},
    pcs_field::{PcsField, ProvingConfig},
};
use crate::config::Val;
use crate::proving::Run;
use p3_air::{symbolic::AirLayout, Air};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Pcs;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::LogUpGadget;
use p3_uni_stark::{Commitments, Proof, StarkGenericConfig};
mod admission;
pub(crate) use admission::Prepared;

/// Static public tables are encoded compactly on the host. Expansion,
/// interpolation and coset evaluation run on GPU; no periodic evaluations return.
fn periodic_prefix(
    session: &DeviceSession,
    columns: &[Vec<Val>],
    log_rows: u32,
    shift: u64,
    host_allowance: usize,
) -> Result<Option<DeviceMatrix>, String> {
    if columns.is_empty() {
        return Ok(None);
    }
    let staging_words = columns.iter().try_fold(
        columns
            .len()
            .checked_mul(2)
            .ok_or("periodic metadata overflow")?,
        |n, c| {
            c.len()
                .checked_mul(3)
                .and_then(|words| n.checked_add(words))
                .ok_or("periodic source size overflow")
        },
    )?;
    if staging_words
        .checked_mul(8)
        .is_none_or(|n| n > host_allowance)
    {
        return Err("periodic input geometry exceeds its host allowance".into());
    }
    let words: Vec<Vec<u64>> = columns
        .iter()
        .map(|column| column.iter().map(|v| v.as_canonical_u64()).collect())
        .collect();
    let input = session.periodic_matrix(log_rows, &words, host_allowance)?;
    drop(words);
    session
        .lde(&input, log_rows, shift, RowOrder::BitReversed)
        .map(Some)
}

pub(crate) fn prove<
    E: PcsField,
    #[cfg(debug_assertions)] A: Air<symbolic::Builder> + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
    #[cfg(not(debug_assertions))] A: Air<symbolic::Builder>,
>(
    config: &ProvingConfig<E>,
    air: &A,
    trace: DeviceMatrix,
    public_values: &[Val],
    run: &Run,
    prepared: Prepared,
) -> Result<Proof<ProvingConfig<E>>, String> {
    let pcs = config.pcs();
    prepared.check_operation_host_allowance(pcs.host_output_budget())?;
    let periodic_host_allowance = prepared.periodic_host_bytes();
    let session = pcs.quotient_session()?;
    let input = TraceInput::<Val>::Device(trace);
    input.validate_device(&session, air.width())?;
    let log_degree = input.height().ilog2() as usize;
    let log_ext_degree = log_degree + 1;
    let layout = AirLayout::from_air::<Val>(air);
    if prepared.rows != input.height()
        || prepared.shape.extension != E::DEVICE_EXTENSION
        || !prepared.recorded.matches_layout(layout)
    {
        return Err("owned uni recording differs from runtime shape".into());
    }
    if config.is_zk() != 1
        || layout.preprocessed_width != 0
        || public_values.len() != layout.num_public_values
    {
        return Err(
            "owned uni proving requires hiding, exact publics and no preprocessed commitment"
                .into(),
        );
    }
    let mut compiled = compile::Batch::new(1, symbolic::HOST_BYTES as usize)?;
    let _execution = session.observe_single_air(run)?;
    let randomness_attempt = pcs.begin_randomness_attempt()?;
    let mut challenger = config.initialise_challenger();
    let transcript_attempt = challenger.begin_attempt()?;
    if !challenger.is_gpu() || !pcs.uses_gpu_randomness() {
        return Err("owned uni proving requires GPU randomness and transcript".into());
    }
    pcs.check_gpu_challenger(&challenger)?;
    let _randomness = pcs.observe_randomness(run)?;
    let _transcript = challenger.observe_execution(run)?;
    let TraceInput::Device(trace) = input else {
        unreachable!()
    };
    #[cfg(debug_assertions)]
    run.measure(
        crate::proving::Stage::ConstraintAudit,
        crate::proving::Backend::Cpu,
        || {
            let host = pcs.audit_main_device(&trace)?;
            p3_air::check_constraints(air, &host, public_values);
            Ok::<(), String>(())
        },
    )
    .map_err(|e| e.to_string())??;

    // The empty lookup list preserves the uni constraint order and hiding
    // degree rule. Only the internal evaluator layout lowers periodic inputs.
    let gadget = LogUpGadget::new();
    let constraints = prepared
        .recorded
        .normalize(Constants::device(&session, run))
        .map_err(|e| format!("owned uni symbolic compilation: {e:?}"))?;
    let log_chunks = symbolic::batch_log_chunks(air, &constraints, &[], &gadget, 1)
        .map_err(|e| format!("owned uni quotient degree: {e:?}"))?;
    if air
        .num_constraints()
        .is_some_and(|n| n != constraints.base.len())
    {
        return Err("owned uni constraint count hint differs from symbolic evaluation".into());
    }
    let constraints = constraints
        .into_base_only::<E>()
        .map_err(|e| format!("owned uni base constraints: {e:?}"))?;
    let program = Program::from_periodic_constraints(layout, &constraints)?;
    prepared.shape.check(&program)?;
    compiled.push(program, log_chunks, constraints.base.len())?;
    drop(constraints);
    compiled.report();
    let chunks = 1usize
        .checked_shl((log_chunks + 1) as u32)
        .ok_or("uni quotient degree overflow")?;
    let trace_domain = DomainSpec::new(1, log_degree)?;
    let ext_domain = DomainSpec::new(1, log_ext_degree)?;
    let quotient_domain = session.disjoint_domain(ext_domain, log_ext_degree + log_chunks)?;
    let periodic = if let Some(source) = prepared.periodic {
        periodic_prefix(
            &session,
            source.columns(),
            log_degree as u32,
            quotient_domain.shift().as_canonical_u64(),
            periodic_host_allowance,
        )?
    } else {
        None
    };
    let (trace_commit, trace_data) = pcs.commit_main_device(vec![(ext_domain, trace)])?;

    // Exact p3-uni-stark order: degrees, zero preprocessing width, main cap,
    // publics, alpha, quotient cap, randomization cap, zeta, PCS opening.
    challenger.observe(Val::from_usize(log_ext_degree));
    challenger.observe(Val::from_usize(log_degree));
    challenger.observe(Val::ZERO);
    challenger.observe(trace_commit.clone());
    challenger.observe_slice(public_values);
    let alpha: E = challenger.sample_algebra_element();
    let main = pcs.quotient_device_prefix(
        &trace_data,
        0,
        quotient_domain,
        air.width(),
        Extension::Base,
    )?;
    let quotient = evaluate::owned_quotient(
        &session,
        &compiled.get(0).program,
        public_values,
        trace_domain,
        quotient_domain,
        &main,
        None,
        &[],
        &[],
        periodic.as_ref(),
        alpha,
    )?;
    drop(main);
    drop(periodic);
    drop(compiled);
    let (quotient_commit, quotient_data) =
        pcs.commit_quotient_device(quotient_domain, &quotient, chunks)?;
    drop(quotient);
    challenger.observe(quotient_commit.clone());
    let (random_commit, random_data) = pcs.randomization_device([ext_domain])?;
    challenger.observe(random_commit.clone());
    let zeta: E = challenger.sample_algebra_element();
    let zeta_next = challenger.next_points(zeta, &[trace_domain])[0];
    let main_next = !air.main_next_row_columns().is_empty();
    let main_points = if main_next {
        vec![zeta, zeta_next]
    } else {
        vec![zeta]
    };
    let (values, opening_proof) = pcs.open_with_preprocessing(
        vec![
            (&random_data, vec![vec![zeta]]),
            (&trace_data, vec![main_points]),
            (&quotient_data, vec![vec![zeta]; chunks]),
        ],
        &mut challenger,
        false,
    );
    let mut instances = opened_values::assemble(
        values,
        core::iter::once(opened_values::Instance {
            main_next,
            quotient_start: 0,
            quotient_end: chunks,
            preprocessed: None,
            permutation: false,
        }),
        opened_values::Rounds {
            random: true,
            preprocessed: false,
            permutation: false,
        },
        pcs.host_output_budget(),
    )?;
    let proof = Proof {
        commitments: Commitments {
            trace: trace_commit,
            quotient_chunks: quotient_commit,
            random: Some(random_commit),
        },
        opened_values: instances.pop().unwrap().base_opened_values,
        opening_proof,
        degree_bits: log_ext_degree,
    };
    if let Some(guard) = randomness_attempt {
        guard.complete();
    }
    if let Some(guard) = transcript_attempt {
        guard.complete();
    }
    Ok(proof)
}

#[cfg(test)]
mod tests;
