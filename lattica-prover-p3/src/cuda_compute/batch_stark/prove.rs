//! Transcript and opening order mirror p3-batch-stark 0.6.1. Structural
//! integers are extension elements; public statements remain base elements.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    #[cfg(test)]
    AfterTrace,
    #[cfg(test)]
    AfterPermutation,
    #[cfg(test)]
    AfterQuotient,
    #[cfg(test)]
    PanicAfterQuotient,
    #[cfg(test)]
    AfterPcs,
}

fn observe_usize(transcript: &mut Transcript, n: usize) -> Result<()> {
    transcript.observe(&[n as u64, 0, 0])
}
fn observe_buffer(transcript: &mut Transcript, buffer: &Buffer) -> Result<()> {
    for first in (0..buffer.len()).step_by(crate::transcript_limits::BATCH_WORDS) {
        transcript.observe_resident(
            buffer,
            first,
            (buffer.len() - first).min(crate::transcript_limits::BATCH_WORDS),
        )?;
    }
    Ok(())
}

impl BatchStarks {
    pub(crate) fn prove(
        &self,
        prepared: &PreparedBatch,
        inputs: &[MachineInputs<'_>],
        random: StarkRandomness<'_>,
        host_bytes: usize,
    ) -> Result<NativeBatchProof> {
        self.prove_impl(prepared, inputs, random, host_bytes, Fault::None)
    }

    pub(super) fn prove_impl(
        &self,
        prepared: &PreparedBatch,
        inputs: &[MachineInputs<'_>],
        random: StarkRandomness<'_>,
        host_bytes: usize,
        fault: Fault,
    ) -> Result<NativeBatchProof> {
        if !Arc::ptr_eq(&prepared.runtime.state, &self.runtime.state)
            || inputs.len() != prepared.instances.len()
        {
            return Err("CUDA batch input count or runtime differs from preparation".into());
        }
        let mut input_bytes = 0usize;
        for (input, instance) in inputs.iter().zip(&prepared.instances) {
            if input.public.len() != instance.layout.num_public_values
                || input.witness.len() != instance.witnesses
                || input
                    .public
                    .iter()
                    .chain(input.witness)
                    .any(|&v| v >= crate::gpu_matrix::GOLDILOCKS_MODULUS)
            {
                return Err("CUDA batch input count or canonical encoding mismatch".into());
            }
            input_bytes = input_bytes
                .checked_add(input.public.len())
                .and_then(|n| n.checked_add(input.witness.len()))
                .ok_or("CUDA batch input size overflow")?;
        }
        // Charge borrowed raw inputs, retained public metadata, proof caps and
        // schedule vectors alongside the PCS output/scratch allowance.
        let pcs_host = input_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(self.runtime.snapshot().public_program_bytes))
            .and_then(|n| n.checked_add(PROOF_HEADERS))
            .and_then(|n| host_bytes.checked_sub(n))
            .filter(|&n| n > 0)
            .ok_or("CUDA batch headers exceed host allowance")?;
        for family in [random.masks, random.commitments, random.fri] {
            family.check_runtime(&self.runtime)?;
        }
        prepared.preprocessing.check_runtime(&self.runtime)?;
        let mut transcript = self.transcripts.start()?;
        let transcript_guard = transcript.begin_attempt()?;
        let preparation_guard = prepared.preprocessing.begin_attempt(&self.runtime)?;
        let result = random.masks.with_attempt(|| {
            random.commitments.with_attempt(|| {
                random.fri.with_attempt(|| {
                    self.prove_inner(prepared, inputs, random, pcs_host, &mut transcript, fault)
                })
            })
        })?;
        prepared.preprocessing.check_runtime(&self.runtime)?;
        transcript.check_live()?;
        for family in [random.masks, random.commitments, random.fri] {
            family.check_live()?;
        }
        preparation_guard.complete();
        transcript_guard.complete();
        Ok(result)
    }

    fn prove_inner(
        &self,
        prepared: &PreparedBatch,
        inputs: &[MachineInputs<'_>],
        random: StarkRandomness<'_>,
        host_bytes: usize,
        transcript: &mut Transcript,
        _fault: Fault,
    ) -> Result<NativeBatchProof> {
        let params = parameters();
        let count = inputs.len();
        observe_usize(transcript, count)?;
        for i in &prepared.instances {
            for n in [
                i.log_rows as usize + 1,
                i.log_rows as usize,
                i.layout.main_width,
                i.chunks(),
            ] {
                observe_usize(transcript, n)?;
            }
        }
        let mut executions = vector(count)?;
        for (input, i) in inputs.iter().zip(&prepared.instances) {
            executions.push(self.witnesses.generate(
                &i.witness,
                input.public,
                input.witness,
                host_bytes,
            )?);
        }
        let main = self.commit_traces(executions.iter().map(|e| &e.trace), prepared, random)?;
        let main_cap = observe_cap(&main, transcript)?;
        for execution in &executions {
            if let Some(public) = &execution.public {
                observe_buffer(transcript, public)?;
            }
        }
        for i in &prepared.instances {
            observe_usize(transcript, i.layout.preprocessed_width)?;
        }
        observe_cap(&prepared.preprocessing, transcript)?;
        #[cfg(test)]
        if matches!(_fault, Fault::AfterTrace) {
            return Err("injected CUDA batch trace failure".into());
        }

        // Allocate mappings/outputs before the single batch-wide alpha/beta draw.
        let mut scalar_inputs = vector(count)?;
        for ids in &prepared.bus_ids {
            scalar_inputs.push(self.scalars.prepare_lookup(
                Extension::Cubic,
                prepared.message_width,
                ids,
            )?);
        }
        let pair = transcript.sample_resident(6)?;
        let mut challenges = vector(count)?;
        for input in scalar_inputs {
            challenges.push(input.finish(&pair)?);
        }
        drop(pair);
        let mut permutations = vector(count)?;
        for ((execution, i), challenge) in
            executions.iter().zip(&prepared.instances).zip(&challenges)
        {
            permutations.push(self.lookups.generate(
                &i.lookup,
                &execution.trace,
                Some(i.preprocessing.matrix()),
                execution.public.as_ref(),
                challenge,
                Extension::Cubic,
            )?);
        }
        let permutation =
            self.commit_traces(permutations.iter().map(|p| &p.trace), prepared, random)?;
        let permutation_cap = observe_cap(&permutation, transcript)?;
        for p in &permutations {
            let t = p.terminal();
            transcript.observe_resident(t.buffer, t.first, 3)?;
        }
        let terminals: Vec<_> = permutations
            .iter()
            .map(|p| p.terminal().buffer.clone())
            .collect();
        drop(permutations);
        let alpha = transcript.sample_resident(3)?;
        #[cfg(test)]
        if matches!(_fault, Fault::AfterPermutation) {
            return Err("injected CUDA batch permutation failure".into());
        }
        // Release main witness rows after the committed/lookup consumers finish.
        let publics: Vec<_> = executions.into_iter().map(|e| e.public).collect();
        let mut quotient_inputs = vector(count)?;
        for (index, i) in prepared.instances.iter().enumerate() {
            let words = i.layout.num_public_values + 3 * (i.layout.num_permutation_challenges + 1);
            let values = self.runtime.allocate(words)?;
            let public_words = i.layout.num_public_values;
            if let Some(public) = &publics[index] {
                values.copy_from(0, public, 0, public_words)?;
            }
            values.copy_from(public_words, &challenges[index], 0, challenges[index].len())?;
            values.copy_from(
                public_words + challenges[index].len(),
                &terminals[index],
                0,
                3,
            )?;
            let committed = |commitment, columns, extension| {
                Some(CommittedMatrix {
                    commitment,
                    index,
                    columns,
                    extension,
                })
            };
            let quotient = self.hiding.evaluate_committed_quotient(
                &self.quotients,
                &i.quotient,
                [
                    committed(&main, i.layout.main_width, Extension::Base),
                    committed(
                        &prepared.preprocessing,
                        i.layout.preprocessed_width,
                        Extension::Base,
                    ),
                    committed(&permutation, i.layout.permutation_width, Extension::Cubic),
                ],
                i.log_rows,
                i.log_rows + 1 + i.log_chunks as u32,
                &alpha,
                Some(&values),
            )?;
            quotient_inputs.push(self.hiding.prepare_quotient(
                &quotient,
                i.chunks(),
                random.masks,
                i.log_lde(params),
                2,
            )?);
        }
        drop(alpha);
        drop(challenges);
        drop(publics);
        let borrowed: Vec<_> = quotient_inputs.iter().map(HidingInput::Quotient).collect();
        let quotient = self.hiding.commit_batch(
            &self.commitments,
            &borrowed,
            random.commitments,
            params.cap_height,
        )?;
        drop(borrowed);
        drop(quotient_inputs);
        let quotient_cap = observe_cap(&quotient, transcript)?;
        #[cfg(test)]
        match _fault {
            Fault::AfterQuotient => return Err("injected CUDA batch quotient failure".into()),
            Fault::PanicAfterQuotient => panic!("injected CUDA batch quotient unwind"),
            _ => (),
        }
        let mut random_inputs = vector(count)?;
        for i in &prepared.instances {
            random_inputs.push(self.hiding.prepare_randomization(
                i.log_rows + 1,
                1,
                Extension::Cubic,
                random.masks,
                i.log_lde(params),
                2,
            )?);
        }
        let borrowed: Vec<_> = random_inputs
            .iter()
            .map(HidingInput::Randomization)
            .collect();
        let random_data = self.hiding.commit_batch(
            &self.commitments,
            &borrowed,
            random.commitments,
            params.cap_height,
        )?;
        drop(borrowed);
        drop(random_inputs);
        let random_cap = observe_cap(&random_data, transcript)?;
        let zeta = transcript.sample_resident(3)?;
        let logs: Vec<_> = prepared.instances.iter().map(|i| i.log_rows).collect();
        let next = self.scalars.next_points(
            FieldSpan {
                buffer: &zeta,
                first: 0,
            },
            Extension::Cubic,
            &logs,
        )?;
        let pairs = self.runtime.allocate(count * 6)?;
        for index in 0..count {
            pairs.copy_from(index * 6, &zeta, 0, 3)?;
            pairs.copy_from(index * 6 + 3, &next, index * 3, 3)?;
        }
        let point = OpeningPoints {
            values: FieldSpan {
                buffer: &zeta,
                first: 0,
            },
            count: 1,
        };
        let ordinary = vec![point; count];
        let chunks = prepared.instances.iter().map(Instance::chunks).sum();
        let quotient_points = vec![point; chunks];
        let permutation_points: Vec<_> = (0..count)
            .map(|i| OpeningPoints {
                values: FieldSpan {
                    buffer: &pairs,
                    first: i * 6,
                },
                count: 2,
            })
            .collect();
        // MachineAir currently reads no main/preprocessing next rows. Prepare
        // explicitly rejects changed AIR access patterns rather than omit them.
        let rounds = [
            OpeningRound {
                commitment: &random_data,
                points: &ordinary,
            },
            OpeningRound {
                commitment: &main,
                points: &ordinary,
            },
            OpeningRound {
                commitment: &quotient,
                points: &quotient_points,
            },
            OpeningRound {
                commitment: &prepared.preprocessing,
                points: &ordinary,
            },
            OpeningRound {
                commitment: &permutation,
                points: &permutation_points,
            },
        ];
        let (values, opening_proof) = self
            .openings
            .open::<Challenge>(params, &rounds, true, random.fri, transcript, host_bytes)?;
        #[cfg(test)]
        if matches!(_fault, Fault::AfterPcs) {
            return Err("injected CUDA batch PCS failure".into());
        }
        let opened_values = assemble(values, &prepared.instances)?;
        let mut lookup_terminals = vector(count)?;
        // Only completed proof values leave the device. No lookup polynomial or
        // sampled challenge is downloaded for the host quotient/transcript path.
        for terminal in &terminals {
            let mut words = [0; 3];
            terminal.read(0, &mut words)?;
            lookup_terminals.push(Some(p3_lookup::LookupTerminal(
                Challenge::from_basis_coefficients_fn(|i| Val::from_u64(words[i])),
            )));
        }
        Ok(p3_batch_stark::BatchProof {
            commitments: p3_batch_stark::BatchCommitments {
                main: main_cap,
                permutation: Some(permutation_cap),
                quotient_chunks: quotient_cap,
                random: Some(random_cap),
            },
            opened_values,
            opening_proof,
            lookup_terminals,
            degree_bits: prepared
                .instances
                .iter()
                .map(|i| i.log_rows as usize + 1)
                .collect(),
        })
    }

    fn commit_traces<'a>(
        &self,
        traces: impl Iterator<Item = &'a Matrix>,
        prepared: &PreparedBatch,
        random: StarkRandomness<'_>,
    ) -> Result<HiddenCommitment> {
        let params = parameters();
        let mut inputs = vector(prepared.instances.len())?;
        for (trace, i) in traces.zip(&prepared.instances) {
            inputs.push(
                self.hiding
                    .prepare_trace(trace, random.masks, i.log_lde(params), 16)?,
            );
        }
        let borrowed: Vec<_> = inputs.iter().map(HidingInput::Trace).collect();
        self.hiding.commit_batch(
            &self.commitments,
            &borrowed,
            random.commitments,
            params.cap_height,
        )
    }
}

fn single<T>(values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        return Err("CUDA batch opening point count mismatch".into());
    }
    Ok(values.into_iter().next().unwrap())
}
fn assemble(
    values: p3_commit::OpenedValues<Challenge>,
    instances: &[Instance],
) -> Result<p3_batch_stark::BatchOpenedValues<Challenge>> {
    if values.len() != 5 {
        return Err("CUDA machine batch requires five PCS rounds".into());
    }
    let mut rounds = values.into_iter();
    let mut next = || rounds.next().unwrap().into_iter();
    let (mut random, mut main, mut quotient, mut prep, mut perm) =
        (next(), next(), next(), next(), next());
    if [random.len(), main.len(), prep.len(), perm.len()] != [instances.len(); 4]
        || quotient.len() != instances.iter().map(Instance::chunks).sum::<usize>()
    {
        return Err("CUDA batch opening matrix count mismatch".into());
    }
    let mut output = vector(instances.len())?;
    for i in instances {
        let mut chunks = vector(i.chunks())?;
        for _ in 0..i.chunks() {
            chunks.push(single(quotient.next().unwrap())?);
        }
        let permutation = perm.next().unwrap();
        if permutation.len() != 2 {
            return Err("CUDA batch permutation points mismatch".into());
        }
        let mut permutation = permutation.into_iter();
        output.push(p3_batch_stark::proof::OpenedValuesWithLookups {
            base_opened_values: p3_uni_stark::OpenedValues {
                trace_local: single(main.next().unwrap())?,
                trace_next: None,
                preprocessed_local: Some(single(prep.next().unwrap())?),
                preprocessed_next: None,
                quotient_chunks: chunks,
                random: Some(single(random.next().unwrap())?),
            },
            permutation_local: permutation.next().unwrap(),
            permutation_next: permutation.next().unwrap(),
        });
    }
    Ok(p3_batch_stark::BatchOpenedValues { instances: output })
}
