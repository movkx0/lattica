//! Pinned serial-AES proof joining. Every segment authenticates the complete
//! key/request and contributes a contiguous part of one output commitment.
use super::{AesLaneAir, Descriptor, INPUT_COMMITMENT, OUTPUT_END, OUTPUT_START, PUBLIC_VALUES};
use crate::{crypto_join::Error, rust_verify::constraints_crypto::PendingAes};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, ProofInputs},
    },
    profile::Config,
};
use p3_field::PrimeCharacteristicRing;

/// A constructor-checked, contiguous partition with a pinned AIR type.
#[derive(Clone, Debug)]
pub struct AesLanePartition {
    descriptor: Descriptor,
    segments: Vec<AesLaneAir>,
}
impl AesLanePartition {
    pub fn new(descriptor: Descriptor, max_blocks: usize) -> Result<Self, Error> {
        if max_blocks == 0 {
            return Err(Error::Descriptor);
        }
        let mut segments = Vec::new();
        let mut first = 0;
        // Validate even before the loop, including the empty-output case.
        AesLaneAir::new(descriptor).map_err(|_| Error::Descriptor)?;
        while first < descriptor.blocks() {
            let blocks = max_blocks.min(descriptor.blocks() - first);
            segments.push(
                AesLaneAir::segment(descriptor, first, blocks).map_err(|_| Error::Descriptor)?,
            );
            first += blocks;
        }
        Ok(Self {
            descriptor,
            segments,
        })
    }
    pub fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    pub fn segments(&self) -> &[AesLaneAir] {
        &self.segments
    }
}
pub struct AesLaneSegmentProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
pub fn verify_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    request: &PendingAes,
    partition: &AesLanePartition,
    proofs: &[AesLaneSegmentProof],
) -> Result<(), Error> {
    verify_committed_request(
        b,
        inputs,
        Descriptor {
            domain: request.domain,
            start_counter: request.start_counter,
            output_len: request.output.len(),
        },
        &request.input_commitment,
        &request.output_commitment,
        partition,
        proofs,
    )
}
/// Full typed proof verification for an AES request represented only by its
/// exact descriptor and byte commitments. The caller must bind the input root
/// to the key and fixed request framing; no coefficient/byte hints are trusted.
pub fn verify_committed_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    descriptor: Descriptor,
    input_commitment: &[Wire; 4],
    output_commitment: &[Wire; 4],
    partition: &AesLanePartition,
    proofs: &[AesLaneSegmentProof],
) -> Result<(), Error> {
    if partition.descriptor != descriptor || proofs.len() != partition.segments.len() {
        return Err(Error::Shape("serial AES request/partition/proof count"));
    }
    let zero = b.constant(Val::ZERO);
    let mut previous = [
        b.constant(Val::from_u64(super::AES_OUTPUT_DOMAIN)),
        b.constant(Val::from_usize(descriptor.output_len)),
        zero,
        zero,
    ];
    for (air, proof) in partition.segments.iter().zip(proofs) {
        let public: [Wire; PUBLIC_VALUES] = inputs
            .bases(b, &proof.public_values)?
            .try_into()
            .map_err(|_| Error::Shape("serial AES public width"))?;
        verifier::uni::verify(b, inputs, air, air.height, &public, &proof.proof)?;
        for i in 0..4 {
            b.assert_equal(public[INPUT_COMMITMENT + i], input_commitment[i]);
            b.assert_equal(public[OUTPUT_START + i], previous[i]);
            previous[i] = public[OUTPUT_END + i];
        }
    }
    for i in 0..4 {
        b.assert_equal(previous[i], output_commitment[i]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partition_covers_each_block_once() {
        let descriptor = Descriptor {
            domain: 1,
            start_counter: u32::MAX,
            output_len: 4788,
        };
        let partition = AesLanePartition::new(descriptor, 32).unwrap();
        assert_eq!(partition.segments.len(), 10);
        let mut first = 0;
        for air in partition.segments() {
            assert_eq!(air.first_block, first);
            assert!(air.blocks <= 32);
            first += air.blocks;
        }
        assert_eq!(first, descriptor.blocks());
        assert!(AesLanePartition::new(descriptor, 0).is_err());
        assert!(AesLanePartition::new(
            Descriptor {
                output_len: 0,
                ..descriptor
            },
            32
        )
        .is_err());
    }
}
