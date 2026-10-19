//! Native hiding PCS openings. Every original opening is evaluated once,
//! observed while resident, reduced on CUDA and authenticated by native FRI.
use super::{
    Commitments, DeviceRandom, FieldSpan, Fri, FriField, FriParameters, HiddenCommitment,
    NativeFriProof, OpeningAccumulator, Openings, Result, Runtime, Transcript, Transforms,
};
use crate::{
    config::Val,
    gpu_matrix::{Extension, MatrixSpec, RowOrder},
};
use p3_commit::{OpenedValues, Pcs};
use p3_field::{ExtensionField, PrimeCharacteristicRing};

pub(super) mod storage;
#[cfg(test)]
mod tests;

const PREPROCESSED_ROUND: usize = <crate::config::MyPcs as Pcs<
    crate::config::Challenge,
    crate::config::Challenger,
>>::PREPROCESSED_TRACE_IDX;
pub(crate) type NativeHidingProof<F> = (OpenedValues<F>, NativeFriProof<F>);

#[derive(Clone, Copy)]
pub(crate) struct OpeningPoints<'a> {
    pub values: FieldSpan<'a>,
    pub count: usize,
}

pub(crate) struct OpeningRound<'a> {
    pub commitment: &'a HiddenCommitment,
    pub points: &'a [OpeningPoints<'a>],
}

pub(crate) struct PcsOpenings {
    runtime: Runtime,
    openings: Openings,
    transforms: Transforms,
    commitments: Commitments,
    fri: Fri,
}

fn vector<T>(capacity: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result.try_reserve_exact(capacity).map_err(super::error)?;
    Ok(result)
}
fn fields<F: ExtensionField<Val>>(words: &[u64]) -> Result<Vec<F>> {
    if words.len() % F::DIMENSION != 0 {
        return Err("CUDA PCS egress field width mismatch".into());
    }
    let mut result = vector(words.len() / F::DIMENSION)?;
    for value in words.chunks_exact(F::DIMENSION) {
        result.push(F::from_basis_coefficients_fn(|i| Val::from_u64(value[i])));
    }
    Ok(result)
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    AfterObservation,
    #[cfg(test)]
    PanicAfterObservation,
    #[cfg(test)]
    AfterReduction,
}

impl PcsOpenings {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        Ok(Self {
            runtime: runtime.clone(),
            openings: Openings::new(runtime)?,
            transforms: Transforms::new(runtime)?,
            commitments: Commitments::new(runtime)?,
            fri: Fri::new(runtime)?,
        })
    }

    /// Preserves HidingFriPcs's point/matrix/round ordering and masking suffix.
    /// The optional public preprocessing round is the upstream fixed index;
    /// every other committed matrix must contain the pinned masking width.
    pub(crate) fn open<F: FriField>(
        &self,
        params: FriParameters,
        rounds: &[OpeningRound<'_>],
        public_preprocessing: bool,
        salts: &DeviceRandom,
        transcript: &mut Transcript,
        host_bytes: usize,
    ) -> Result<(OpenedValues<F>, NativeHidingProof<F>)> {
        self.open_impl(
            params,
            rounds,
            public_preprocessing,
            salts,
            transcript,
            host_bytes,
            Fault::None,
        )
    }

    fn open_impl<F: FriField>(
        &self,
        params: FriParameters,
        rounds: &[OpeningRound<'_>],
        public_preprocessing: bool,
        salts: &DeviceRandom,
        transcript: &mut Transcript,
        host_bytes: usize,
        _fault: Fault,
    ) -> Result<(OpenedValues<F>, NativeHidingProof<F>)> {
        salts.check_runtime(&self.runtime)?;
        transcript.check_runtime(&self.runtime)?;
        let plan = self.plan::<F>(params, rounds, public_preprocessing, host_bytes)?;
        let mut originals = vector(rounds.len())?;
        let mut attempts = vector(rounds.len())?;
        for round in rounds {
            originals.push(round.commitment);
            attempts.push(round.commitment.begin_attempt(&self.runtime)?);
        }
        let transcript_attempt = transcript.begin_attempt()?;
        let result = salts.with_attempt(|| {
            let mut captured = vector(plan.matrices)?;
            for round in rounds {
                for (matrix, points) in round.points.iter().enumerate() {
                    let opening = round.commitment.retain_opening(
                        &self.openings,
                        matrix,
                        F::EXTENSION,
                        points.values,
                        points.count,
                    )?;
                    opening.with(|o| o.observe(transcript))?;
                    captured.push(opening);
                }
            }
            #[cfg(test)]
            match _fault {
                Fault::AfterObservation => {
                    return Err("injected CUDA PCS observation failure".into())
                }
                Fault::PanicAfterObservation => panic!("injected CUDA PCS observation unwind"),
                _ => (),
            }
            let alpha = transcript.sample_resident(F::DIMENSION)?;
            let mut accumulators: [Option<OpeningAccumulator<'_>>; 26] =
                std::array::from_fn(|_| None);
            let mut values = vector(rounds.len())?;
            let mut random_values = vector(rounds.len())?;
            let mut captured = captured.into_iter();
            for round in rounds {
                let mut round_values = vector(round.points.len())?;
                let mut round_random = vector(round.points.len())?;
                for points in round.points {
                    let opening = captured
                        .next()
                        .ok_or("CUDA PCS retained opening count mismatch")?;
                    let shape = opening.shape();
                    let height = shape.lde.log_rows as usize;
                    let accumulator = match accumulators[height].take() {
                        Some(accumulator) => accumulator,
                        None => self.openings.accumulator(
                            shape.lde.log_rows,
                            shape.lde.shift,
                            F::EXTENSION,
                            FieldSpan {
                                buffer: &alpha,
                                first: 0,
                            },
                            0,
                        )?,
                    };
                    accumulators[height] =
                        Some(opening.with(|o| accumulator.append(&self.transforms, o))?);
                    let raw = opening.with(|o| o.values(o.words() * 8))?;
                    let width = shape.lde.columns;
                    let split = (width - shape.random_columns) * F::DIMENSION;
                    let mut matrix_values = vector(points.count)?;
                    let mut matrix_random = vector(points.count)?;
                    for point in raw.chunks_exact(width * F::DIMENSION) {
                        matrix_values.push(fields(&point[..split])?);
                        matrix_random.push(fields(&point[split..])?);
                    }
                    round_values.push(matrix_values);
                    round_random.push(matrix_random);
                    // The immutable copied points and evaluated values are
                    // released here; only original prefixes and reductions remain.
                }
                values.push(round_values);
                random_values.push(round_random);
            }
            if captured.next().is_some() {
                return Err("CUDA PCS retained an extra opening".into());
            }
            drop(alpha);
            #[cfg(test)]
            if matches!(_fault, Fault::AfterReduction) {
                return Err("injected CUDA PCS reduction failure".into());
            }
            let mut inputs = vector(plan.heights.len())?;
            for accumulator in accumulators.into_iter().rev().flatten() {
                inputs.push(self.fri.rescale(&accumulator.finish()?)?);
            }
            let proof = self.fri.prove::<F>(
                &self.commitments,
                params,
                inputs,
                &originals,
                salts,
                transcript,
                plan.fri_host_bytes,
            )?;
            for round in rounds {
                round.commitment.check_runtime(&self.runtime)?;
            }
            transcript.check_live()?;
            Ok((values, (random_values, proof)))
        })?;
        for attempt in attempts {
            attempt.complete();
        }
        transcript_attempt.complete();
        Ok(result)
    }
}
