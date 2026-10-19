//! Native FRI transcript protocol and authenticated proof egress.
//! All polynomial, challenge and transcript arithmetic runs on CUDA. Host work
//! schedules public geometry and converts bounded egress into existing types.
use super::*;
use crate::{
    config::{Val, ValMmcs},
    cuda_compute::{Commitments, DeviceRandom, HiddenCommitment, HiddenOpenings, Transcript},
};
use p3_commit::{BatchOpening, ExtensionMmcs};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_merkle_tree::MerkleCap;

pub(in crate::cuda_compute) mod storage;
#[cfg(test)]
mod tests;

pub(crate) trait FriField: ExtensionField<Val> {
    const EXTENSION: Extension;
}
impl FriField for crate::config::Challenge {
    const EXTENSION: Extension = Extension::Quadratic;
}
impl FriField for p3_field::extension::CubicTrinomialExtensionField<Val> {
    const EXTENSION: Extension = Extension::Cubic;
}

pub(crate) type NativeFriProof<F> =
    FriProof<F, ExtensionMmcs<Val, F, ValMmcs>, Val, Vec<BatchOpening<Val, ValMmcs>>>;

#[derive(Clone, Copy, Debug)]
pub(crate) struct FriParameters {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub commit_proof_of_work_bits: usize,
    pub query_proof_of_work_bits: usize,
    pub cap_height: usize,
}

impl FriParameters {
    pub(crate) fn from_upstream<M>(params: &p3_fri::FriParameters<M>, cap_height: usize) -> Self {
        Self {
            log_blowup: params.log_blowup,
            log_final_poly_len: params.log_final_poly_len,
            max_log_arity: params.max_log_arity,
            num_queries: params.num_queries,
            commit_proof_of_work_bits: params.commit_proof_of_work_bits,
            query_proof_of_work_bits: params.query_proof_of_work_bits,
            cap_height,
        }
    }
}

fn vector<T>(capacity: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(super::super::error)?;
    Ok(result)
}

fn fields<F: ExtensionField<Val>>(words: &[u64]) -> Result<Vec<F>> {
    if words.len() % F::DIMENSION != 0 {
        return Err("CUDA FRI egress field width mismatch".into());
    }
    let mut result = vector(words.len() / F::DIMENSION)?;
    for value in words.chunks_exact(F::DIMENSION) {
        result.push(F::from_basis_coefficients_fn(|j| Val::from_u64(value[j])));
    }
    Ok(result)
}
fn digests(words: &[u64]) -> Result<Vec<[Val; 4]>> {
    if words.len() % 4 != 0 {
        return Err("CUDA FRI egress digest width mismatch".into());
    }
    let mut result = vector(words.len() / 4)?;
    for value in words.chunks_exact(4) {
        result.push(std::array::from_fn(|j| Val::from_u64(value[j])));
    }
    Ok(result)
}

fn input_opening(data: &HiddenOpenings, query: usize) -> Result<BatchOpening<Val, ValMmcs>> {
    let mut values = vector(data.matrices.len())?;
    let mut salts = vector(data.matrices.len())?;
    for matrix in &data.matrices {
        let width = matrix.spec.columns;
        values.push(fields(&matrix.values[query * width..(query + 1) * width])?);
        salts.push(fields(&matrix.salts[query * 4..(query + 1) * 4])?);
    }
    let path = digests(&data.paths[query * data.path_len * 4..(query + 1) * data.path_len * 4])?;
    Ok(BatchOpening::new(values, (salts, path)))
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    AfterFirstCap,
    #[cfg(test)]
    PanicAfterFirstCap,
    #[cfg(test)]
    BeforeQueries,
}

impl Fri {
    /// Admission for a caller that will produce the reduced vectors later.
    pub(crate) fn proof_host_bytes<F: FriField>(
        &self,
        params: FriParameters,
        heights: &[usize],
        originals: &[&HiddenCommitment],
    ) -> Result<usize> {
        self.protocol_plan::<F>(params, heights, originals, usize::MAX)
            .map(|(plan, _)| plan.host_peak)
    }

    fn protocol_plan<F: FriField>(
        &self,
        params: FriParameters,
        heights: &[usize],
        originals: &[&HiddenCommitment],
        host_bytes: usize,
    ) -> Result<(storage::Plan, Vec<(usize, usize)>)> {
        if heights.is_empty()
            || heights.len() > 26
            || heights.iter().any(|&h| h > 25)
            || originals.is_empty()
            || originals.len() > 256
        {
            return Err("CUDA FRI protocol geometry exceeds admission".into());
        }
        let mut initial = vector(originals.len())?;
        let mut authenticated_heights = [false; 26];
        for data in originals {
            data.check_runtime(&self.runtime)?;
            for spec in data.specs() {
                if !heights.contains(&(spec.log_rows as usize)) {
                    return Err("CUDA FRI reduction omits a committed input height".into());
                }
                authenticated_heights[spec.log_rows as usize] = true;
            }
            initial.push((
                data.query_host_bytes(params.num_queries)?,
                data.specs().len(),
            ));
        }
        if heights.iter().any(|&h| !authenticated_heights[h]) {
            return Err("CUDA FRI reduction has no authenticated input".into());
        }
        let plan = storage::Plan::new(params, heights, F::DIMENSION, &initial, host_bytes)?;
        Ok((plan, initial))
    }

    /// Inputs are opening reductions, one per distinct committed height. The
    /// caller has observed original commitments/claims and sampled alpha.
    /// This method authenticates every original input query itself; callers
    /// cannot provide unauthenticated values in place of those openings.
    pub(crate) fn prove<F: FriField>(
        &self,
        commitments: &Commitments,
        params: FriParameters,
        inputs: Vec<FriVector>,
        originals: &[&HiddenCommitment],
        random: &DeviceRandom,
        transcript: &mut Transcript,
        host_bytes: usize,
    ) -> Result<NativeFriProof<F>> {
        self.prove_impl(
            commitments,
            params,
            inputs,
            originals,
            random,
            transcript,
            host_bytes,
            Fault::None,
        )
    }

    fn prove_impl<F: FriField>(
        &self,
        commitments: &Commitments,
        params: FriParameters,
        inputs: Vec<FriVector>,
        originals: &[&HiddenCommitment],
        random: &DeviceRandom,
        transcript: &mut Transcript,
        host_bytes: usize,
        _fault: Fault,
    ) -> Result<NativeFriProof<F>> {
        commitments.check_runtime(&self.runtime)?;
        random.check_runtime(&self.runtime)?;
        transcript.check_runtime(&self.runtime)?;
        if inputs.is_empty() || inputs.len() > 26 || originals.is_empty() || originals.len() > 256 {
            return Err("CUDA FRI input or commitment count exceeds admission".into());
        }
        let mut heights = vector(inputs.len())?;
        for input in &inputs {
            self.owner(&input.matrix)?;
            shape::vector(input.matrix.spec)?;
            if input.extension() != F::EXTENSION {
                return Err("CUDA FRI proof extension mismatch".into());
            }
            heights.push(input.log_rows() as usize);
        }
        let (plan, initial) = self.protocol_plan::<F>(params, &heights, originals, host_bytes)?;
        let mut attempts = vector(originals.len())?;
        for data in originals {
            attempts.push(data.begin_attempt(&self.runtime)?);
        }
        let transcript_attempt = transcript.begin_attempt()?;
        let proof = random.with_attempt(|| {
            let mut commits = vector(plan.layers.len())?;
            let mut witnesses = vector(plan.layers.len())?;
            let mut retained = vector(plan.layers.len())?;
            let mut inputs = inputs.into_iter().peekable();
            let mut folded = inputs.next().unwrap();
            for layer in &plan.layers {
                if folded.log_rows() as usize != layer.input_log {
                    return Err("CUDA FRI execution differs from admitted schedule".into());
                }
                let data = self.commit_layer(
                    commitments,
                    &folded,
                    layer.log_arity,
                    random,
                    params.cap_height,
                )?;
                let cap = data.cap(layer.cap_bytes)?;
                for chunk in cap.chunks(crate::transcript_limits::BATCH_WORDS) {
                    transcript.observe(chunk)?;
                }
                commits.push(MerkleCap::new(digests(&cap)?));
                #[cfg(test)]
                if retained.is_empty() {
                    match _fault {
                        Fault::AfterFirstCap => {
                            return Err("injected CUDA FRI protocol failure".into())
                        }
                        Fault::PanicAfterFirstCap => panic!("injected CUDA FRI protocol unwind"),
                        _ => (),
                    }
                }
                witnesses.push(Val::from_u64(
                    transcript.grind(params.commit_proof_of_work_bits)?,
                ));
                let beta = transcript.sample_resident(F::DIMENSION)?;
                let round = self.round(
                    F::EXTENSION,
                    layer.log_arity,
                    FieldSpan {
                        buffer: &beta,
                        first: 0,
                    },
                )?;
                drop(beta);
                folded = round.fold(&folded)?;
                if let Some(input) = inputs.next_if(|v| v.log_rows() == folded.log_rows()) {
                    folded = round.mix(&folded, &input)?;
                }
                retained.push(data);
            }
            if inputs.next().is_some() {
                return Err("CUDA FRI did not consume every input".into());
            }
            let coefficients = self.final_polynomial(
                &folded,
                params.log_blowup,
                params.log_final_poly_len,
                plan.final_bytes,
            )?;
            drop(folded);
            let span = coefficients.span();
            for first in (0..coefficients.words()).step_by(crate::transcript_limits::BATCH_WORDS) {
                transcript.observe_resident(
                    span.buffer,
                    first,
                    (coefficients.words() - first).min(crate::transcript_limits::BATCH_WORDS),
                )?;
            }
            let final_poly = fields(&coefficients.read(plan.final_bytes)?)?;
            drop(coefficients);
            // Observe each arity in order, after all final coefficients.
            for layer in &plan.layers {
                transcript.observe(&[layer.log_arity as u64])?;
            }
            let query_pow_witness =
                Val::from_u64(transcript.grind(params.query_proof_of_work_bits)?);
            let sampled = transcript.sample_bits(heights[0], params.num_queries)?;
            let mut indices = vector(sampled.len())?;
            indices.extend(sampled.into_iter().map(|i| i as usize));
            #[cfg(test)]
            if matches!(_fault, Fault::BeforeQueries) {
                return Err("injected CUDA FRI query-phase failure".into());
            }
            let mut query_proofs = vector(params.num_queries)?;
            for _ in 0..params.num_queries {
                query_proofs.push(QueryProof {
                    input_proof: vector(originals.len())?,
                    commit_phase_openings: vector(retained.len())?,
                });
            }
            for (batch, data) in originals.iter().enumerate() {
                let height = data.specs().map(|s| s.log_rows as usize).max().unwrap();
                let mut local = vector(indices.len())?;
                local.extend(indices.iter().map(|i| i >> (heights[0] - height)));
                let openings =
                    data.open(commitments, &self.transforms, &local, initial[batch].0)?;
                for (query, proof) in query_proofs.iter_mut().enumerate() {
                    proof.input_proof.push(input_opening(&openings, query)?);
                }
            }
            let mut shift = 0;
            for (data, layer) in retained.into_iter().zip(&plan.layers) {
                let arity = 1usize << layer.log_arity;
                let mut local = vector(indices.len())?;
                local.extend(indices.iter().map(|i| i >> (shift + layer.log_arity)));
                let openings = data.open(self, commitments, &local, layer.query_bytes)?;
                for (query, proof) in query_proofs.iter_mut().enumerate() {
                    let index_in_group = (indices[query] >> shift) % arity;
                    let mut values = fields::<F>(
                        &openings.values[query * openings.width..(query + 1) * openings.width],
                    )?;
                    values.remove(index_in_group);
                    let mut salts = vector(1)?;
                    salts.push(fields::<Val>(&openings.salts[query * 4..(query + 1) * 4])?);
                    let path = digests(
                        &openings.paths
                            [query * openings.path_len * 4..(query + 1) * openings.path_len * 4],
                    )?;
                    proof.commit_phase_openings.push(CommitPhaseProofStep {
                        log_arity: layer.log_arity as u8,
                        sibling_values: values,
                        opening_proof: (salts, path),
                    });
                }
                shift += layer.log_arity;
            }
            for data in originals {
                data.check_runtime(&self.runtime)?;
            }
            transcript.check_live()?;
            Ok(FriProof {
                commit_phase_commits: commits,
                commit_pow_witnesses: witnesses,
                query_proofs,
                final_poly,
                query_pow_witness,
            })
        })?;
        for attempt in attempts {
            attempt.complete();
        }
        transcript_attempt.complete();
        Ok(proof)
    }
}
