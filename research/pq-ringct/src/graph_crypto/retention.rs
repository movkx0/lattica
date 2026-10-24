//! Public-shape reservations for retaining fresh serial SHAKE native proofs.
//!
//! These are requested owned capacities, not process RSS or backend workspace
//! bounds. No grouped proof path is enabled by this module. Reserve the public
//! bound before proving; a smaller observed capacity never changes group policy.
use super::{err, require, Error, Partition, Request, Result, SegmentArtifact, Val};
use core::mem::size_of;
use lattica_prover_p3::block_v2::{machine::program::Wire, profile};
use p3_air::BaseAir;
use p3_field::{BasedVectorSpace, TwoAdicField};
use p3_symmetric::MerkleCap;

type NativeProof = p3_uni_stark::Proof<profile::Config>;
type Challenge = profile::Challenge;
type Digest = [Val; 4];
type Cap = MerkleCap<Val, Digest>;

fn overflow() -> Error {
    Error("native retention size overflow".into())
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn capacity_limit(length: usize) -> Result<usize> {
    if length == 0 {
        Ok(0)
    } else {
        Ok(mul(length, 2)?.max(4))
    }
}
fn array_bytes<T>(length: usize) -> Result<usize> {
    mul(capacity_limit(length)?, size_of::<T>())
}
// Infer inaccessible nested upstream types without constructing a proof or
// adding dependencies. The selector is never called and allocates nothing.
fn element_size<T>(_: for<'a> fn(&'a NativeProof) -> &'a Vec<T>) -> usize {
    size_of::<T>()
}

#[derive(Clone, Copy)]
pub struct NativeRetentionShape {
    width: usize,
    degree: usize,
    log_lde: usize,
    quotient_limit: usize,
    queries: usize,
    random_width: usize,
    extension_degree: usize,
    retained_bytes: usize,
    input_values: usize,
}

impl Request {
    /// Public shape only: no witness values, proof decoding, symbolic AIR
    /// evaluation, GPU dispatch or source-artifact allocation is performed.
    pub fn segment_retention_shape(&self, index: usize) -> Result<NativeRetentionShape> {
        let Partition::Shake(partition) = &self.partition else {
            return Err(Error("native retention requires serial SHAKE".into()));
        };
        let info = self
            .segments
            .get(index)
            .ok_or_else(|| Error("native retention segment index".into()))?;
        let air = partition
            .segments()
            .get(index)
            .ok_or_else(|| Error("native retention partition index".into()))?;
        require(
            info.height == air.height() && info.width == air.width(),
            "native retention registered shape mismatch",
        )?;
        NativeRetentionShape::new(info.width, info.height)
    }
}

impl NativeRetentionShape {
    fn new(width: usize, height: usize) -> Result<Self> {
        require(
            width != 0 && height.is_power_of_two(),
            "native retention geometry",
        )?;
        let fri = profile::fri(());
        let extension_degree = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
        require(
            extension_degree == 3
                && fri.max_log_arity == 1
                && fri.log_final_poly_len == 0
                && fri.commit_proof_of_work_bits == 0
                && fri.log_blowup == profile::LOG_BLOWUP
                && fri.num_queries == profile::NUM_QUERIES,
            "native retention unsupported pinned profile",
        )?;
        let degree = add(height.ilog2() as usize, 1)?;
        let log_lde = add(degree, fri.log_blowup)?;
        // Goldilocks' two-adicity is also the existing PCS verifier MAX_LOG.
        require(log_lde <= Val::TWO_ADICITY, "native retention FRI degree")?;
        let quotient_limit = 1usize
            .checked_shl(u32::try_from(add(fri.log_blowup, 1)?).map_err(err)?)
            .ok_or_else(overflow)?;
        let mut shape = Self {
            width,
            degree,
            log_lde,
            quotient_limit,
            queries: fri.num_queries,
            random_width: profile::NUM_RANDOM_CODEWORDS,
            extension_degree,
            retained_bytes: 0,
            input_values: 0,
        };
        shape.retained_bytes = add(shape.heap_bound()?, size_of::<RetainedNativeChild>())?;
        shape.input_values = shape.input_bound()?;
        Ok(shape)
    }

    fn roots(self, log: usize) -> Result<usize> {
        1usize
            .checked_shl(u32::try_from(log.min(profile::CAP_HEIGHT)).map_err(err)?)
            .ok_or_else(overflow)
    }
    fn path(self, log: usize) -> usize {
        log.saturating_sub(profile::CAP_HEIGHT)
    }

    /// Includes inline owner and all allowed spare Vec/Merkle-cap capacities.
    pub fn retained_bytes(self) -> usize {
        self.retained_bytes
    }
    /// Conservative scalar witness cap for a bounded recursive verifier.
    pub fn max_input_values(self) -> usize {
        self.input_values
    }
    /// Old and new ProofInputs buffers can coexist during growth.
    pub fn input_backing_bytes(self) -> Result<usize> {
        mul(mul(self.input_values, 2)?, size_of::<Val>())
    }
    /// Cumulative payload of helper-returned arrays, which bounds their live
    /// overlap. Vec headers, endpoint copies and compiler scratch are separate.
    pub fn returned_wire_bytes(self) -> Result<usize> {
        mul(self.input_values, size_of::<Wire>())
    }

    fn heap_bound(self) -> Result<usize> {
        let mut bytes = mul(3, array_bytes::<Digest>(self.roots(self.log_lde)?)?)?;
        bytes = add(bytes, mul(2, array_bytes::<Challenge>(self.width)?)?)?;
        bytes = add(bytes, array_bytes::<Vec<Challenge>>(self.quotient_limit)?)?;
        bytes = add(
            bytes,
            mul(self.quotient_limit, array_bytes::<Challenge>(3)?)?,
        )?;
        bytes = add(bytes, array_bytes::<Challenge>(3)?)?;
        bytes = add(bytes, array_bytes::<Vec<Vec<Vec<Challenge>>>>(3)?)?;
        for (matrices, points) in [(1, 1), (1, 2), (self.quotient_limit, 1)] {
            bytes = add(bytes, array_bytes::<Vec<Vec<Challenge>>>(matrices)?)?;
            let rows = add(
                array_bytes::<Vec<Challenge>>(points)?,
                mul(points, array_bytes::<Challenge>(self.random_width)?)?,
            )?;
            bytes = add(bytes, mul(matrices, rows)?)?;
        }
        bytes = add(bytes, array_bytes::<Cap>(self.degree)?)?;
        for round in 0..self.degree {
            bytes = add(
                bytes,
                array_bytes::<Digest>(self.roots(self.log_lde - round - 1)?)?,
            )?;
        }
        bytes = add(bytes, array_bytes::<Val>(self.degree)?)?;
        bytes = add(bytes, array_bytes::<Challenge>(1)?)?;
        let query_size = element_size(|proof| &proof.opening_proof.1.query_proofs);
        bytes = add(bytes, mul(capacity_limit(self.queries)?, query_size)?)?;
        let opening_size = element_size(|proof| &proof.opening_proof.1.query_proofs[0].input_proof);
        let mut query = mul(capacity_limit(3)?, opening_size)?;
        for (matrices, width) in [(1, 3), (1, self.width), (self.quotient_limit, 3)] {
            query = add(query, array_bytes::<Vec<Val>>(matrices)?)?;
            query = add(
                query,
                mul(
                    matrices,
                    array_bytes::<Val>(add(width, self.random_width)?)?,
                )?,
            )?;
            query = add(query, array_bytes::<Vec<Val>>(matrices)?)?;
            query = add(query, mul(matrices, array_bytes::<Val>(4)?)?)?;
            query = add(query, array_bytes::<Digest>(self.path(self.log_lde))?)?;
        }
        let step_size =
            element_size(|proof| &proof.opening_proof.1.query_proofs[0].commit_phase_openings);
        query = add(query, mul(capacity_limit(self.degree)?, step_size)?)?;
        for round in 0..self.degree {
            query = add(query, array_bytes::<Challenge>(1)?)?;
            query = add(query, array_bytes::<Vec<Val>>(1)?)?;
            query = add(query, array_bytes::<Val>(4)?)?;
            query = add(
                query,
                array_bytes::<Digest>(self.path(self.log_lde - round - 1))?,
            )?;
        }
        add(bytes, mul(self.queries, query)?)
    }

    fn input_bound(self) -> Result<usize> {
        let mut cap_fields = mul(3, self.roots(self.log_lde)?)?;
        let mut fold_paths = 0;
        for round in 0..self.degree {
            cap_fields = add(cap_fields, self.roots(self.log_lde - round - 1)?)?;
            fold_paths = add(fold_paths, self.path(self.log_lde - round - 1))?;
        }
        let mut values = add(crate::shake_air::PUBLIC_VALUES, mul(4, cap_fields)?)?;
        let opened = add(add(mul(2, self.width)?, mul(3, self.quotient_limit)?)?, 3)?;
        values = add(values, mul(self.extension_degree, opened)?)?;
        let suffix = mul(self.random_width, add(self.quotient_limit, 3)?)?;
        values = add(values, mul(self.extension_degree, suffix)?)?;
        values = add(values, add(self.degree, add(self.extension_degree, 1)?)?)?;
        let mut query = add(self.width, add(3, mul(2, self.random_width)?)?)?;
        query = add(query, mul(self.quotient_limit, add(3, self.random_width)?)?)?;
        query = add(query, mul(4, add(self.quotient_limit, 2)?)?)?;
        query = add(query, mul(12, self.path(self.log_lde))?)?;
        query = add(query, mul(add(self.extension_degree, 4)?, self.degree)?)?;
        query = add(query, mul(4, fold_paths)?)?;
        add(values, mul(self.queries, query)?)
    }

    fn audit(self, artifact: &SegmentArtifact) -> Result<()> {
        let SegmentArtifact::Shake(artifact) = artifact else {
            return Err(Error("native retention artifact family".into()));
        };
        let proof = &artifact.proof;
        require(
            proof.degree_bits == self.degree,
            "native retention proof degree",
        )?;
        let mut audit = CapacityAudit {
            bytes: 0,
            limit: self.heap_bound()?,
        };
        for cap in [&proof.commitments.trace, &proof.commitments.quotient_chunks] {
            audit.cap(cap, self.roots(self.log_lde)?)?;
        }
        audit.cap(
            proof
                .commitments
                .random
                .as_ref()
                .ok_or_else(|| Error("native retention random cap".into()))?,
            self.roots(self.log_lde)?,
        )?;
        let opened = &proof.opened_values;
        audit.vector(&opened.trace_local, self.width, self.width)?;
        let next = if let Some(values) = &opened.trace_next {
            audit.vector(values, self.width, self.width)?;
            1
        } else {
            0
        };
        require(
            opened.preprocessed_local.is_none() && opened.preprocessed_next.is_none(),
            "native retention preprocessing",
        )?;
        let chunks = opened.quotient_chunks.len();
        require(
            chunks.is_power_of_two() && chunks <= self.quotient_limit,
            "native retention quotient shape",
        )?;
        audit.vector(&opened.quotient_chunks, chunks, self.quotient_limit)?;
        for values in &opened.quotient_chunks {
            audit.vector(values, 3, 3)?;
        }
        audit.vector(
            opened
                .random
                .as_ref()
                .ok_or_else(|| Error("native retention random opening".into()))?,
            3,
            3,
        )?;
        let (hiding, fri) = &proof.opening_proof;
        audit.vector(hiding, 3, 3)?;
        for (round, matrices) in hiding.iter().enumerate() {
            let count = if round == 2 { chunks } else { 1 };
            let maximum = if round == 2 { self.quotient_limit } else { 1 };
            let points = if round == 1 { 1 + next } else { 1 };
            let point_limit = if round == 1 { 2 } else { 1 };
            audit.vector(matrices, count, maximum)?;
            for values in matrices {
                audit.vector(values, points, point_limit)?;
                for point in values {
                    audit.vector(point, self.random_width, self.random_width)?;
                }
            }
        }
        audit.vector(&fri.commit_phase_commits, self.degree, self.degree)?;
        for (round, cap) in fri.commit_phase_commits.iter().enumerate() {
            audit.cap(cap, self.roots(self.log_lde - round - 1)?)?;
        }
        audit.vector(&fri.commit_pow_witnesses, self.degree, self.degree)?;
        audit.vector(&fri.final_poly, 1, 1)?;
        audit.vector(&fri.query_proofs, self.queries, self.queries)?;
        for query in &fri.query_proofs {
            audit.vector(&query.input_proof, 3, 3)?;
            for (round, opening) in query.input_proof.iter().enumerate() {
                let count = if round == 2 { chunks } else { 1 };
                let maximum = if round == 2 { self.quotient_limit } else { 1 };
                let width = add(if round == 1 { self.width } else { 3 }, self.random_width)?;
                audit.vector(&opening.opened_values, count, maximum)?;
                for values in &opening.opened_values {
                    audit.vector(values, width, width)?;
                }
                audit.authentication(
                    &opening.opening_proof,
                    count,
                    maximum,
                    self.path(self.log_lde),
                )?;
            }
            audit.vector(&query.commit_phase_openings, self.degree, self.degree)?;
            for (round, opening) in query.commit_phase_openings.iter().enumerate() {
                require(opening.log_arity == 1, "native retention nonbinary FRI")?;
                audit.vector(&opening.sibling_values, 1, 1)?;
                audit.authentication(
                    &opening.opening_proof,
                    1,
                    1,
                    self.path(self.log_lde - round - 1),
                )?;
            }
        }
        Ok(())
    }
}

/// An immutable retained source, not a recursive or complete-request receipt.
/// Native verification is performed by the producing factory before admission.
pub struct RetainedNativeChild {
    index: usize,
    key: [u8; 32],
    shape: NativeRetentionShape,
    artifact: SegmentArtifact,
}
impl RetainedNativeChild {
    pub(super) fn from_fresh(
        index: usize,
        key: [u8; 32],
        shape: NativeRetentionShape,
        artifact: SegmentArtifact,
    ) -> Result<Self> {
        shape.audit(&artifact)?;
        Ok(Self {
            index,
            key,
            shape,
            artifact,
        })
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn shape(&self) -> NativeRetentionShape {
        self.shape
    }
    pub fn artifact(&self) -> &SegmentArtifact {
        &self.artifact
    }
}

struct CapacityAudit {
    bytes: usize,
    limit: usize,
}
impl CapacityAudit {
    fn capacity<T>(&mut self, actual: usize, maximum: usize) -> Result<()> {
        require(
            actual <= capacity_limit(maximum)?,
            "native retention spare capacity",
        )?;
        self.bytes = add(self.bytes, mul(actual, size_of::<T>())?)?;
        require(self.bytes <= self.limit, "native retention owned capacity")
    }
    fn vector<T>(&mut self, values: &Vec<T>, expected: usize, maximum: usize) -> Result<()> {
        require(
            expected <= maximum && values.len() == expected,
            "native retention vector shape",
        )?;
        self.capacity::<T>(values.capacity(), maximum)
    }
    fn cap(&mut self, cap: &Cap, expected: usize) -> Result<()> {
        require(cap.roots().len() == expected, "native retention cap shape")?;
        self.capacity::<Digest>(cap.root_capacity(), expected)
    }
    fn authentication(
        &mut self,
        proof: &(Vec<Vec<Val>>, Vec<Digest>),
        matrices: usize,
        maximum: usize,
        path: usize,
    ) -> Result<()> {
        self.vector(&proof.0, matrices, maximum)?;
        for salt in &proof.0 {
            self.vector(salt, 4, 4)?;
        }
        self.vector(&proof.1, path, path)
    }
}

#[cfg(test)]
mod tests;
