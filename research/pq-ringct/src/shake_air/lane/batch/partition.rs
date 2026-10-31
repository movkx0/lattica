use super::*;
use crate::{crypto_join::Error as JoinError, rust_verify::constraints_crypto::PendingShake};
use lattica_prover_p3::block_v2::machine::{
    program::{ScopedProgramBuilder, Wire},
    verifier::{self, ProofInputs},
};

#[derive(Clone, Debug)]
pub enum ShakeSegmentAir {
    Single(LaneShakeAir),
    Batch(BatchShakeAir),
}
impl ShakeSegmentAir {
    pub fn first_permutation(&self) -> usize {
        match self {
            Self::Single(a) => a.permutation,
            Self::Batch(a) => a.first_permutation(),
        }
    }
    pub fn permutations(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Batch(a) => a.permutations(),
        }
    }
    pub fn height(&self) -> usize {
        match self {
            Self::Single(_) => HEIGHT,
            Self::Batch(a) => a.height(),
        }
    }
    pub fn generate(&self, input: &[u8]) -> Result<SegmentWitness, Error> {
        match self {
            Self::Single(a) => a.generate(input),
            Self::Batch(a) => a.generate(input),
        }
    }
}
impl BaseAir<Val> for ShakeSegmentAir {
    fn width(&self) -> usize {
        match self {
            Self::Single(a) => a.width(),
            Self::Batch(a) => a.width(),
        }
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        match self {
            Self::Single(a) => a.periodic_columns(),
            Self::Batch(a) => a.periodic_columns(),
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Single(a) => a.max_constraint_degree(),
            Self::Batch(a) => a.max_constraint_degree(),
        }
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ShakeSegmentAir {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Single(a) => a.eval(b),
            Self::Batch(a) => a.eval(b),
        }
    }
}

/// Private contiguous partition: callers cannot insert gaps, overlaps, cross a
/// padding boundary, or change the trusted kind/count after construction.
#[derive(Clone, Debug)]
pub struct ShakeBatchPartition {
    descriptor: Descriptor,
    segments: Vec<ShakeSegmentAir>,
}
impl ShakeBatchPartition {
    pub fn new(descriptor: Descriptor, maximum_batch: usize) -> Result<Self, Error> {
        if !maximum_batch.is_power_of_two() {
            return Err(Error::Segment);
        }
        let last_absorb = descriptor.input_len / RATE;
        let mut result = Self {
            descriptor,
            segments: Vec::new(),
        };
        result.add_range(0, last_absorb, maximum_batch, Kind::FullAbsorb)?;
        result
            .segments
            .push(ShakeSegmentAir::Single(LaneShakeAir::new(
                descriptor,
                last_absorb,
            )?));
        let full_squeeze = (descriptor.output_len / RATE).saturating_sub(1);
        result.add_range(
            last_absorb + 1,
            full_squeeze,
            maximum_batch,
            Kind::FullSqueeze,
        )?;
        if descriptor.output_len > RATE && descriptor.output_len % RATE != 0 {
            result
                .segments
                .push(ShakeSegmentAir::Single(LaneShakeAir::new(
                    descriptor,
                    last_absorb + descriptor.output_len / RATE,
                )?));
        }
        Ok(result)
    }
    fn add_range(
        &mut self,
        mut first: usize,
        mut count: usize,
        maximum: usize,
        kind: Kind,
    ) -> Result<(), Error> {
        while count != 0 {
            let count_here = 1usize << (usize::BITS - 1 - count.min(maximum).leading_zeros());
            if count_here == 1 {
                self.segments
                    .push(ShakeSegmentAir::Single(LaneShakeAir::new(
                        self.descriptor,
                        first,
                    )?));
            } else {
                self.segments
                    .push(ShakeSegmentAir::Batch(BatchShakeAir::new(
                        self.descriptor,
                        first,
                        count_here,
                        kind,
                    )?));
            }
            first += count_here;
            count -= count_here;
        }
        Ok(())
    }
    pub fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    pub fn segments(&self) -> &[ShakeSegmentAir] {
        &self.segments
    }
}

/// Same proof encoding as the single-permutation wrapper. The registered
/// partition selects and authenticates the exact AIR variant and trace height.
pub fn verify_batched_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    request: &PendingShake,
    partition: &ShakeBatchPartition,
    proofs: &[LaneShakeProof],
) -> Result<(), JoinError> {
    verify_committed_batched_request(
        b,
        inputs,
        Descriptor {
            input_len: request.input.len(),
            output_len: request.output.len(),
        },
        &request.input_commitment,
        &request.output_commitment,
        partition,
        proofs,
    )
}
/// Full request proof verification for root-only transcript coordinators.
/// Exact lengths, initial state, segment adjacency and both final roots are
/// constrained; no full input/output byte witnesses are fabricated.
pub fn verify_committed_batched_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    descriptor: Descriptor,
    input_commitment: &[Wire; 4],
    output_commitment: &[Wire; 4],
    partition: &ShakeBatchPartition,
    proofs: &[LaneShakeProof],
) -> Result<(), JoinError> {
    if partition.descriptor.input_len != descriptor.input_len
        || partition.descriptor.output_len != descriptor.output_len
        || partition.segments.len() != proofs.len()
    {
        return Err(JoinError::Shape(
            "batched SHAKE request/partition/proof count",
        ));
    }
    let mut previous: Option<[Wire; PUBLIC_VALUES]> = None;
    for (air, proof) in partition.segments.iter().zip(proofs) {
        let public: [Wire; PUBLIC_VALUES] = inputs
            .bases(b, &proof.public_values)?
            .try_into()
            .map_err(|_| JoinError::Shape("batched SHAKE public width"))?;
        verifier::uni::verify(b, inputs, air, air.height(), &public, &proof.proof)?;
        if let Some(prior) = previous {
            for i in 0..100 {
                b.assert_equal(prior[END_STATE + i], public[START_STATE + i]);
            }
            for i in 0..4 {
                b.assert_equal(prior[INPUT_END + i], public[INPUT_START + i]);
                b.assert_equal(prior[OUTPUT_END + i], public[OUTPUT_START + i]);
            }
        } else {
            let zero = b.constant(Val::ZERO);
            for i in 0..100 {
                b.assert_equal(public[START_STATE + i], zero);
            }
            for (offset, domain, length) in [
                (
                    INPUT_START,
                    SHAKE_INPUT_DOMAIN,
                    partition.descriptor.input_len,
                ),
                (
                    OUTPUT_START,
                    SHAKE_OUTPUT_DOMAIN,
                    partition.descriptor.output_len,
                ),
            ] {
                let domain = b.constant(Val::from_u64(domain));
                let length = b.constant(Val::from_usize(length));
                for (i, value) in [domain, length, zero, zero].into_iter().enumerate() {
                    b.assert_equal(public[offset + i], value);
                }
            }
        }
        previous = Some(public);
    }
    let end = previous.ok_or(JoinError::Shape("empty batched SHAKE proof list"))?;
    for i in 0..4 {
        b.assert_equal(end[INPUT_END + i], input_commitment[i]);
        b.assert_equal(end[OUTPUT_END + i], output_commitment[i]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lane_batch_partition_covers_all_permutations_once() {
        for input_len in [0, 3, 135, 136, 137, RATE * 8 + 3, RATE * 19] {
            for output_len in [0, 1, 135, 136, 137, RATE * 9, RATE * 17 + 1] {
                let descriptor = Descriptor {
                    input_len,
                    output_len,
                };
                let partition = ShakeBatchPartition::new(descriptor, 8).unwrap();
                let mut expected = 0;
                for air in partition.segments() {
                    assert_eq!(air.first_permutation(), expected);
                    assert!(air.permutations() <= 8);
                    expected += air.permutations();
                }
                assert_eq!(expected, descriptor.permutations().unwrap());
            }
        }
        let descriptor = Descriptor {
            input_len: RATE * 8 + 3,
            output_len: 32,
        };
        let partition = ShakeBatchPartition::new(descriptor, 8).unwrap();
        assert_eq!(partition.segments().len(), 2);
        assert!(ShakeBatchPartition::new(descriptor, 3).is_err());
    }
}
