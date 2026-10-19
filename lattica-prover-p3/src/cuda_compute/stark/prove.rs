//! Protocol order follows p3-uni-stark 0.6.1's prover: trace, quotient, random
//! commitment, then the hiding PCS opening rounds (random, trace, quotient).
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    #[cfg(test)]
    AfterTrace,
    #[cfg(test)]
    AfterQuotient,
    #[cfg(test)]
    PanicAfterQuotient,
    #[cfg(test)]
    AfterPcs,
}

impl Starks {
    pub(crate) fn prove<F: StarkField>(
        &self,
        prepared: &PreparedStark<F>,
        trace: &Matrix,
        public_values: Option<&Buffer>,
        random: StarkRandomness<'_>,
        host_bytes: usize,
    ) -> Result<NativeStarkProof<F>> {
        self.prove_impl(
            prepared,
            trace,
            public_values,
            random,
            host_bytes,
            parameters::<F>(),
            Fault::None,
        )
    }

    pub(super) fn prove_impl<F: StarkField>(
        &self,
        prepared: &PreparedStark<F>,
        trace: &Matrix,
        public_values: Option<&Buffer>,
        random: StarkRandomness<'_>,
        host_bytes: usize,
        params: FriParameters,
        _fault: Fault,
    ) -> Result<NativeStarkProof<F>> {
        self.transforms.check_owner(trace)?;
        if !Arc::ptr_eq(&prepared.runtime.state, &self.runtime.state)
            || trace.spec
                != MatrixSpec::new(
                    prepared.log_rows,
                    prepared.layout.main_width,
                    Extension::Base,
                    RowOrder::Natural,
                    1,
                )?
        {
            return Err("CUDA STARK trace differs from prepared AIR or runtime".into());
        }
        match (public_values, prepared.layout.num_public_values) {
            (None, 0) => (),
            (Some(values), count)
                if count != 0
                    && values.len() == count
                    && Arc::ptr_eq(values.owner(), &self.runtime.state) =>
            {
                ()
            }
            _ => return Err("CUDA STARK public values differ from prepared AIR".into()),
        }
        for family in [random.masks, random.commitments, random.fri] {
            family.check_runtime(&self.runtime)?;
        }
        let log_extended = prepared.log_rows + 1;
        let log_lde = (log_extended as usize)
            .checked_add(params.log_blowup)
            .filter(|&n| n <= 25)
            .ok_or("CUDA STARK LDE height exceeds admission")? as u32;
        let log_quotient = log_extended + prepared.log_chunks as u32;
        let chunks = 1usize << (prepared.log_chunks + 1);
        let cap_bytes = (1usize << params.cap_height.min(log_lde as usize)) * 4 * 8;
        // Returned caps and raw cap conversion coexist with PCS proof output.
        // The fixed metadata allowance also covers point/round assembly and
        // moving the opened values into the unchanged STARK proof structure.
        let header = cap_bytes
            .checked_mul(6)
            .and_then(|n| n.checked_add(HOST_METADATA))
            .ok_or("CUDA STARK host header storage overflow")?;
        let pcs_host = host_bytes
            .checked_sub(header)
            .filter(|&n| n != 0)
            .ok_or("CUDA STARK headers exceed aggregate host allowance")?;
        let mut transcript = self.transcripts.start()?;
        let transcript_attempt = transcript.begin_attempt()?;
        let result = random.masks.with_attempt(|| {
            random.commitments.with_attempt(|| {
                random.fri.with_attempt(|| {
                    let trace_input = self.hiding.prepare_trace(
                        trace,
                        random.masks,
                        log_lde,
                        trace.spec.columns.min(16),
                    )?;
                    let trace_data = self.hiding.commit_batch(
                        &self.commitments,
                        &[HidingInput::Trace(&trace_input)],
                        random.commitments,
                        params.cap_height,
                    )?;
                    drop(trace_input);
                    transcript.observe(&[log_extended as u64, prepared.log_rows as u64, 0])?;
                    let trace_cap = observe_cap(&trace_data, &mut transcript, cap_bytes)?;
                    if let Some(values) = public_values {
                        for first in
                            (0..values.len()).step_by(crate::transcript_limits::BATCH_WORDS)
                        {
                            transcript.observe_resident(
                                values,
                                first,
                                (values.len() - first).min(crate::transcript_limits::BATCH_WORDS),
                            )?;
                        }
                    }
                    #[cfg(test)]
                    if matches!(_fault, Fault::AfterTrace) {
                        return Err("injected CUDA STARK trace failure".into());
                    }
                    let alpha = transcript.sample_resident(F::DIMENSION)?;
                    let quotient = trace_data.evaluate_quotient(
                        &self.hiding,
                        &self.quotients,
                        &prepared.quotient,
                        0,
                        prepared.layout.main_width,
                        prepared.log_rows,
                        log_quotient,
                        prepared.periodic.as_ref(),
                        &alpha,
                        public_values,
                    )?;
                    drop(alpha);
                    let quotient_input = self.hiding.prepare_quotient(
                        &quotient,
                        chunks,
                        random.masks,
                        log_lde,
                        2,
                    )?;
                    let quotient_data = self.hiding.commit_batch(
                        &self.commitments,
                        &[HidingInput::Quotient(&quotient_input)],
                        random.commitments,
                        params.cap_height,
                    )?;
                    drop(quotient_input);
                    drop(quotient);
                    let quotient_cap = observe_cap(&quotient_data, &mut transcript, cap_bytes)?;
                    #[cfg(test)]
                    match _fault {
                        Fault::AfterQuotient => {
                            return Err("injected CUDA STARK quotient failure".into())
                        }
                        Fault::PanicAfterQuotient => panic!("injected CUDA STARK quotient unwind"),
                        _ => (),
                    }
                    let random_input = self.hiding.prepare_randomization(
                        log_extended,
                        1,
                        F::EXTENSION,
                        random.masks,
                        log_lde,
                        2,
                    )?;
                    let random_data = self.hiding.commit_batch(
                        &self.commitments,
                        &[HidingInput::Randomization(&random_input)],
                        random.commitments,
                        params.cap_height,
                    )?;
                    drop(random_input);
                    let random_cap = observe_cap(&random_data, &mut transcript, cap_bytes)?;
                    let zeta = transcript.sample_resident(F::DIMENSION)?;
                    let trace_points = if prepared.main_next {
                        let next = self.scalars.next_points(
                            FieldSpan {
                                buffer: &zeta,
                                first: 0,
                            },
                            F::EXTENSION,
                            &[prepared.log_rows],
                        )?;
                        let both = self.runtime.allocate(2 * F::DIMENSION)?;
                        both.copy_from(0, &zeta, 0, F::DIMENSION)?;
                        both.copy_from(F::DIMENSION, &next, 0, F::DIMENSION)?;
                        both
                    } else {
                        zeta.clone()
                    };
                    let point = OpeningPoints {
                        values: FieldSpan {
                            buffer: &zeta,
                            first: 0,
                        },
                        count: 1,
                    };
                    let random_points = [point];
                    let main_points = [OpeningPoints {
                        values: FieldSpan {
                            buffer: &trace_points,
                            first: 0,
                        },
                        count: if prepared.main_next { 2 } else { 1 },
                    }];
                    let mut quotient_points = vector(chunks)?;
                    quotient_points.resize(chunks, point);
                    let rounds = [
                        OpeningRound {
                            commitment: &random_data,
                            points: &random_points,
                        },
                        OpeningRound {
                            commitment: &trace_data,
                            points: &main_points,
                        },
                        OpeningRound {
                            commitment: &quotient_data,
                            points: &quotient_points,
                        },
                    ];
                    let (values, opening_proof) = self.openings.open::<F>(
                        params,
                        &rounds,
                        false,
                        random.fri,
                        &mut transcript,
                        pcs_host,
                    )?;
                    #[cfg(test)]
                    if matches!(_fault, Fault::AfterPcs) {
                        return Err("injected CUDA STARK PCS failure".into());
                    }
                    let opened_values = assemble(values, prepared.main_next, chunks)?;
                    for family in [random.masks, random.commitments, random.fri] {
                        family.check_live()?;
                    }
                    transcript.check_live()?;
                    Ok(p3_uni_stark::Proof {
                        commitments: p3_uni_stark::Commitments {
                            trace: trace_cap,
                            quotient_chunks: quotient_cap,
                            random: Some(random_cap),
                        },
                        opened_values,
                        opening_proof,
                        degree_bits: log_extended as usize,
                    })
                })
            })
        })?;
        transcript_attempt.complete();
        Ok(result)
    }
}

fn observe_cap(
    data: &super::super::HiddenCommitment,
    transcript: &mut Transcript,
    host_bytes: usize,
) -> Result<<ValMmcs as p3_commit::Mmcs<Val>>::Commitment> {
    let raw = data.cap(host_bytes)?;
    transcript.observe(&raw)?;
    let mut cap = vector(raw.len() / 4)?;
    for words in raw.chunks_exact(4) {
        cap.push(std::array::from_fn(|i| Val::from_u64(words[i])));
    }
    Ok(MerkleCap::new(cap))
}

fn one<T>(values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        return Err("CUDA STARK opening shape differs from protocol".into());
    }
    Ok(values.into_iter().next().unwrap())
}

fn assemble<F: StarkField>(
    values: p3_commit::OpenedValues<F>,
    main_next: bool,
    chunks: usize,
) -> Result<p3_uni_stark::OpenedValues<F>> {
    if values.len() != 3 {
        return Err("CUDA STARK requires three opening rounds".into());
    }
    let mut rounds = values.into_iter();
    let random = one(one(rounds.next().unwrap())?)?;
    let main = one(rounds.next().unwrap())?;
    if main.len() != if main_next { 2 } else { 1 } {
        return Err("CUDA STARK trace point count differs from AIR".into());
    }
    let mut main = main.into_iter();
    let trace_local = main.next().unwrap();
    let trace_next = main.next();
    let quotient = rounds.next().unwrap();
    if quotient.len() != chunks {
        return Err("CUDA STARK quotient chunk count differs from AIR".into());
    }
    let mut quotient_chunks = vector(chunks)?;
    for chunk in quotient {
        quotient_chunks.push(one(chunk)?);
    }
    Ok(p3_uni_stark::OpenedValues {
        trace_local,
        trace_next,
        preprocessed_local: None,
        preprocessed_next: None,
        quotient_chunks,
        random: Some(random),
    })
}
