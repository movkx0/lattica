//! Fixed native g_bound output backing, derived before allocation. This is the
//! retained-capacity inventory from research NativeRetentionShape specialized
//! to the closed 850-column G_BOUND relation and the pinned cubic hiding profile.
//! Temporary PCS/opening construction has an additive phase reservation.
use super::{Error, Result};
use crate::block_v2::{native_gpu::g_bound_preparation::{GBoundGeometry, GBoundDescriptor}, profile};
use crate::config::Val;
use core::mem::size_of;
use p3_field::{BasedVectorSpace, TwoAdicField};
use p3_symmetric::MerkleCap;

type NativeProof = p3_uni_stark::Proof<profile::Config>;
type Challenge = profile::Challenge;
type Digest = [Val; 4];
type Cap = MerkleCap<Val, Digest>;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Overflow)
}
fn require(condition: bool, _: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Capacity)
    }
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
// The selector is never called; no proof or temporary vector is constructed.
fn element_size<T>(_: for<'a> fn(&'a NativeProof) -> &'a Vec<T>) -> usize {
    size_of::<T>()
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Census {
    width: usize,
    degree: usize,
    log_lde: usize,
    quotient_limit: usize,
    queries: usize,
    random_width: usize,
}

impl Census {
    pub(super) fn new(g: GBoundGeometry) -> Result<Self> {
        let fri = profile::fri(());
        if !cfg!(all(
            not(debug_assertions),
            target_os = "linux",
            target_arch = "x86_64"
        )) || (g.rows(), g.width(), g.public_values(), g.periodic_columns()) != g.kind().geometry_tuple()
            || g.periodic_length() != 128 || g.rows() != 4096
            || profile::LOG_BLOWUP != 4
            || profile::CAP_HEIGHT != 6
            || profile::NUM_QUERIES != 128
            || profile::NUM_RANDOM_CODEWORDS != 4
            || profile::QUERY_POW_BITS != 16
            || <Challenge as BasedVectorSpace<Val>>::DIMENSION != 3
            || fri.log_blowup != 4
            || fri.num_queries != 128
            || fri.max_log_arity != 1
            || fri.log_final_poly_len != 0
            || fri.commit_proof_of_work_bits != 0
            || fri.query_proof_of_work_bits != 16
        {
            return Err(Error::Geometry);
        }
        let degree = add(g.rows().ilog2() as usize, 1)?;
        let log_lde = add(degree, 4)?;
        if log_lde > Val::TWO_ADICITY {
            return Err(Error::Geometry);
        }
        Ok(Self {
            width: g.width(),
            degree,
            log_lde,
            quotient_limit: 32,
            queries: 128,
            random_width: 4,
        })
    }

    fn roots(self, log: usize) -> Result<usize> {
        Ok(1 << log.min(profile::CAP_HEIGHT))
    }
    fn path(self, log: usize) -> usize {
        log.saturating_sub(profile::CAP_HEIGHT)
    }

    pub(super) fn heap_bound(self) -> Result<usize> {
        let mut bytes = mul(3, array_bytes::<Digest>(self.roots(self.log_lde)?)?)?;
        // hiding_pcs::open drains its suffix from these vectors without
        // shrinking. Reserve their source allocation width, not final length.
        bytes = add(
            bytes,
            mul(
                2,
                array_bytes::<Challenge>(add(self.width, self.random_width)?)?,
            )?,
        )?;
        bytes = add(bytes, array_bytes::<Vec<Challenge>>(self.quotient_limit)?)?;
        bytes = add(
            bytes,
            mul(
                self.quotient_limit,
                array_bytes::<Challenge>(add(3, self.random_width)?)?,
            )?,
        )?;
        bytes = add(bytes, array_bytes::<Challenge>(add(3, self.random_width)?)?)?;
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
        // FRI truncates the final blowup-sized folded vector in place before
        // its IDFT. Logical final length1 can retain the original16 backing.
        bytes = add(bytes, array_bytes::<Challenge>(1 << profile::LOG_BLOWUP)?)?;
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

    pub(super) fn audit(self, proof: &NativeProof) -> Result<()> {
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
            proof.commitments.random.as_ref().ok_or(Error::Geometry)?,
            self.roots(self.log_lde)?,
        )?;
        let opened = &proof.opened_values;
        audit.vector(
            &opened.trace_local,
            self.width,
            add(self.width, self.random_width)?,
        )?;
        let next = if let Some(values) = &opened.trace_next {
            audit.vector(values, self.width, add(self.width, self.random_width)?)?;
            1
        } else {
            return Err(Error::Geometry);
        };
        require(
            opened.preprocessed_local.is_none() && opened.preprocessed_next.is_none(),
            "native retention preprocessing",
        )?;
        let chunks = opened.quotient_chunks.len();
        require(
            chunks == 16 && chunks <= self.quotient_limit,
            "native retention quotient shape",
        )?;
        audit.vector(&opened.quotient_chunks, chunks, self.quotient_limit)?;
        for values in &opened.quotient_chunks {
            audit.vector(values, 3, add(3, self.random_width)?)?;
        }
        audit.vector(
            opened.random.as_ref().ok_or(Error::Geometry)?,
            3,
            add(3, self.random_width)?,
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
        audit.vector(&fri.final_poly, 1, 1 << profile::LOG_BLOWUP)?;
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
