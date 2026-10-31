//! Consume the admitted public recording before private witness generation.
//! The same normalization, degree rule and compiler checks serve both paths.
//! No witness, proof, RNG draw or transcript update occurs in this preparation.
use super::*;

#[cfg(test)]
mod tests;

/// Single-use normalized public program and periodic source. No caller may
/// construct fields or clone this owner. Its enclosing quota and device lease
/// must already cover normalization and remain held through later proving.
pub(crate) struct Normalized {
    compiled: compile::Batch,
    periodic: Option<periodic::Source>,
    rows: usize,
    extension: Extension,
    layout: AirLayout,
    log_chunks: usize,
    chunks: usize,
    periodic_host_allowance: usize,
    operation_host_allowance: usize,
}

impl Normalized {
    pub(crate) fn quotient_chunks(&self) -> usize {
        self.chunks
    }
    pub(crate) fn operation_host_allowance(&self) -> usize {
        self.operation_host_allowance
    }
}

pub(in crate::block_v2::gpu_quotient_prover::uni) enum Input {
    Recorded(Prepared),
    Normalized(Normalized),
}

pub(in crate::block_v2::gpu_quotient_prover::uni) enum InProgress {
    Recorded {
        recorded: symbolic::RecordedUni,
        shape: ProgramShape,
        periodic: Option<periodic::Source>,
    },
    Normalized {
        log_chunks: usize,
        periodic: Option<periodic::Source>,
    },
}

fn layout_key(l: AirLayout) -> [usize; 7] {
    [
        l.main_width,
        l.preprocessed_width,
        l.num_public_values,
        l.permutation_width,
        l.num_permutation_challenges,
        l.num_permutation_values,
        l.num_periodic_columns,
    ]
}

impl Input {
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn rows(&self) -> usize {
        match self {
            Self::Recorded(p) => p.rows,
            Self::Normalized(p) => p.rows,
        }
    }
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn extension(&self) -> Extension {
        match self {
            Self::Recorded(p) => p.shape.extension,
            Self::Normalized(p) => p.extension,
        }
    }
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn matches_layout(
        &self,
        layout: AirLayout,
    ) -> bool {
        match self {
            Self::Recorded(p) => p.recorded.matches_layout(layout),
            Self::Normalized(p) => layout_key(p.layout) == layout_key(layout),
        }
    }
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn periodic_host_bytes(&self) -> usize {
        match self {
            Self::Recorded(p) => p.periodic_host_bytes(),
            Self::Normalized(p) => p.periodic_host_allowance,
        }
    }
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn check_operation_host_allowance(
        &self,
        configured: usize,
    ) -> Result<(), String> {
        match self {
            Self::Recorded(p) => p.check_operation_host_allowance(configured),
            Self::Normalized(p) if p.operation_host_allowance == configured => Ok(()),
            Self::Normalized(_) => {
                Err("wallet operation host allowance differs from normalized budget".into())
            }
        }
    }
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn into_compilation(
        self,
    ) -> Result<(compile::Batch, InProgress), String> {
        match self {
            Self::Recorded(p) => {
                // Preserve the legacy allocation point: before observations,
                // attempt guards and normalization in the normal prove path.
                let compiled = compile::Batch::new(1, symbolic::HOST_BYTES as usize)?;
                Ok((
                    compiled,
                    InProgress::Recorded {
                        recorded: p.recorded,
                        shape: p.shape,
                        periodic: p.periodic,
                    },
                ))
            }
            Self::Normalized(p) => Ok((
                p.compiled,
                InProgress::Normalized {
                    log_chunks: p.log_chunks,
                    periodic: p.periodic,
                },
            )),
        }
    }
}

impl InProgress {
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn finish<
        E: PcsField,
        A: BaseAir<Val>,
    >(
        self,
        air: &A,
        layout: AirLayout,
        session: &DeviceSession,
        run: &Run,
        compiled: &mut compile::Batch,
    ) -> Result<(usize, Option<periodic::Source>), String> {
        match self {
            Self::Normalized {
                log_chunks,
                periodic,
            } => Ok((log_chunks, periodic)),
            Self::Recorded {
                recorded,
                shape,
                periodic,
            } => {
                let log_chunks = normalize_recording::<E, A>(
                    recorded, shape, air, layout, session, run, compiled,
                )?;
                Ok((log_chunks, periodic))
            }
        }
    }
}

// This is the original uni::prove normalization block, shared without changing
// constraint ordering, hiding degree, field constants or program validation.
fn normalize_recording<E: PcsField, A: BaseAir<Val>>(
    recorded: symbolic::RecordedUni,
    shape: ProgramShape,
    air: &A,
    layout: AirLayout,
    session: &DeviceSession,
    run: &Run,
    compiled: &mut compile::Batch,
) -> Result<usize, String> {
    let gadget = LogUpGadget::new();
    let constraints = recorded
        .normalize(Constants::device(session, run))
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
    shape.check(&program)?;
    compiled.push(program, log_chunks, constraints.base.len())?;
    drop(constraints);
    Ok(log_chunks)
}

// Only the actual normalized degree reaches this final profile check. Keep it
// separate from private witness/proof continuation so its refusals can be
// qualified on public metadata alone. No caller-supplied chunk hint is stored.
fn checked_profile_chunks(log_chunks: usize, expected_chunks: usize) -> Result<usize, String> {
    let shift = log_chunks
        .checked_add(1)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("uni quotient degree overflow")?;
    let chunks = 1usize
        .checked_shl(shift)
        .ok_or("uni quotient degree overflow")?;
    if chunks != expected_chunks {
        return Err("normalized wallet quotient chunks differ from admitted profile".into());
    }
    Ok(chunks)
}

impl Prepared {
    /// Requires an already admitted GPU runtime and enclosing host reservation.
    /// Consumes the exact recording; expected_chunks is checked against the
    /// actual normalized AIR, never a numeric hint. Failure drops all public
    /// program/periodic owners before any private witness is constructed.
    pub(crate) fn normalize_for_profile<E: PcsField, A: BaseAir<Val>>(
        self,
        config: &ProvingConfig<E>,
        air: &A,
        run: &Run,
        expected_chunks: usize,
    ) -> Result<Normalized, String> {
        if !expected_chunks.is_power_of_two()
            || !(2..=crate::block_v2::profile::MAX_QUOTIENT_CHUNKS).contains(&expected_chunks)
        {
            return Err("normalized wallet quotient profile is unsupported".into());
        }
        self.check_operation_host_allowance(config.pcs().host_output_budget())?;
        let layout = AirLayout::from_air::<Val>(air);
        if !self.recorded.matches_layout(layout)
            || self.shape.extension != E::DEVICE_EXTENSION
            || config.is_zk() != 1
            || layout.preprocessed_width != 0
        {
            return Err("normalized wallet program differs from its prepared profile".into());
        }
        let rows = self.rows;
        let extension = self.shape.extension;
        let periodic_host_allowance = self.periodic_host_bytes();
        let operation_host_allowance = self.operation_host_allowance()?;
        let session = config.pcs().quotient_session()?;
        let (mut compiled, progress) = Input::Recorded(self).into_compilation()?;
        let _execution = session.observe_single_air(run)?;
        let (log_chunks, periodic) =
            progress.finish::<E, A>(air, layout, &session, run, &mut compiled)?;
        let chunks = checked_profile_chunks(log_chunks, expected_chunks)?;
        Ok(Normalized {
            compiled,
            periodic,
            rows,
            extension,
            layout,
            log_chunks,
            chunks,
            periodic_host_allowance,
            operation_host_allowance,
        })
    }
}
