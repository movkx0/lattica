//! Opt-in CPU MMCS. The reference verifier and serialized opening are unchanged.
//! Binary tree construction follows p3-merkle-tree 0.6.1 (MIT OR Apache-2.0).
//! Private replay checkpoints belong to this commitment and are never serialized.
use super::compact_salts::Checkpoints;
use crate::config::{MyCompress, MyHash, Val, ValMmcs as Reference};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{Field, PackedValue};
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::{CryptographicHasher, MerkleCap, PseudoCompressionFunction};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::{sync::Mutex, time::Instant};

type Packed = <Val as Field>::Packing;
type Digest = [Val; 4];
const SALT_WIDTH: usize = 4;
pub const HASH_SCRATCH_BYTES: usize = 64 << 20;
pub const TILE_ROWS: usize = 256;
pub const SALT_CHECKPOINT_BYTES: usize = size_of::<ChaCha20Rng>();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Variant {
    #[default]
    Reference,
    Hash,
    Memory,
    Combined,
}
impl Variant {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "reference" => Ok(Self::Reference),
            "hash" => Ok(Self::Hash),
            "memory" => Ok(Self::Memory),
            "combined" => Ok(Self::Combined),
            _ => Err("CPU variant must be reference, hash, memory, or combined".into()),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Hash => "hash",
            Self::Memory => "memory",
            Self::Combined => "combined",
        }
    }
    pub fn replay(self) -> bool {
        matches!(self, Self::Memory | Self::Combined)
    }
    pub fn tiled(self) -> bool {
        matches!(self, Self::Hash | Self::Combined)
    }
}

pub struct CpuMmcs {
    reference: Reference,
    hash: MyHash,
    compress: MyCompress,
    cap_height: usize,
    rng: Mutex<ChaCha20Rng>,
    variant: Variant,
    tile_rows: usize,
}
impl Clone for CpuMmcs {
    fn clone(&self) -> Self {
        Self {
            reference: self.reference.clone(),
            hash: self.hash.clone(),
            compress: self.compress.clone(),
            cap_height: self.cap_height,
            rng: Mutex::new(self.rng.lock().unwrap().clone()),
            variant: self.variant,
            tile_rows: self.tile_rows,
        }
    }
}
impl CpuMmcs {
    pub fn new(hash: MyHash, compress: MyCompress, cap_height: usize, rng: ChaCha20Rng) -> Self {
        Self {
            reference: Reference::new(hash.clone(), compress.clone(), cap_height, rng.clone()),
            hash,
            compress,
            cap_height,
            rng: Mutex::new(rng),
            variant: Variant::Reference,
            tile_rows: TILE_ROWS,
        }
    }
    pub fn with_variant(mut self, variant: Variant) -> Self {
        self.variant = variant;
        // Keep the memory-only control aligned with its replay checkpoint;
        // the tiled candidates use the separately screened hash tile.
        self.tile_rows = if variant.tiled() { TILE_ROWS } else { 1024 };
        self
    }
    /// Explicit research-only tile selection; never a process-global switch.
    pub fn with_tile_rows(mut self, rows: usize) -> Self {
        assert!(
            matches!(rows, 256 | 1024 | 4096),
            "unsupported CPU hash tile"
        );
        self.tile_rows = rows;
        self
    }
}

enum Salts {
    Dense(Vec<Val>),
    Replay(Checkpoints),
}
impl Salts {
    fn fill(&self, first: usize, output: &mut [Val]) {
        match self {
            Self::Dense(values) => output
                .copy_from_slice(&values[first * SALT_WIDTH..first * SALT_WIDTH + output.len()]),
            Self::Replay(checkpoints) => checkpoints.fill(first, output),
        }
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Dense(v) => v.capacity() * size_of::<Val>(),
            Self::Replay(c) => c.bytes(),
        }
    }
}
pub enum Data<M> {
    Reference(<Reference as Mmcs<Val>>::ProverData<M>),
    Compact(Tree<M>),
}
pub struct Tree<M> {
    matrices: Vec<M>,
    salts: Vec<Salts>,
    layers: Vec<Vec<Digest>>,
    cap_height: usize,
}

impl Data<p3_matrix::dense::RowMajorMatrix<Val>> {
    /// Owned backing only. Program source and auxiliary symbolic metadata are
    /// separately reserved by the registered-program owner.
    pub fn retained_backing_bytes(&self) -> Option<usize> {
        let Self::Compact(tree) = self else {
            return None;
        };
        let mut bytes = tree
            .matrices
            .capacity()
            .checked_mul(size_of::<p3_matrix::dense::RowMajorMatrix<Val>>())?;
        for matrix in &tree.matrices {
            bytes = bytes.checked_add(matrix.values.capacity().checked_mul(size_of::<Val>())?)?;
        }
        bytes = bytes.checked_add(tree.salts.capacity().checked_mul(size_of::<Salts>())?)?;
        for salts in &tree.salts {
            bytes = bytes.checked_add(salts.bytes())?;
        }
        bytes = bytes.checked_add(
            tree.layers
                .capacity()
                .checked_mul(size_of::<Vec<Digest>>())?,
        )?;
        for layer in &tree.layers {
            bytes = bytes.checked_add(layer.capacity().checked_mul(size_of::<Digest>())?)?;
        }
        Some(bytes)
    }
}

impl CpuMmcs {
    /// Hash a same-height group. Scratch is bounded across the entire pool;
    /// each task owns one tile and never publishes its private salt material.
    fn leaves<M: Matrix<Val>>(
        &self,
        matrices: &[M],
        salts: &[Salts],
        group: &[usize],
    ) -> Vec<Digest> {
        let height = matrices[group[0]].height();
        let columns: usize = group
            .iter()
            .map(|&i| matrices[i].width() + SALT_WIDTH)
            .sum();
        let threads = rayon::current_num_threads().max(1);
        let packed_width = Packed::WIDTH;
        // Packed row storage plus the largest salt tile. No worker-local cache.
        let row_bytes = columns
            .checked_add(SALT_WIDTH)
            .and_then(|n| n.checked_mul(size_of::<Val>()))
            .expect("CPU hash width overflow");
        let allowance = HASH_SCRATCH_BYTES / threads;
        let available_rows = allowance / row_bytes;
        assert!(
            available_rows >= packed_width,
            "CPU hash tile exceeds scratch allowance"
        );
        let rows =
            self.tile_rows.min(available_rows).max(packed_width) / packed_width * packed_width;
        let mut output = vec![[Val::default(); 4]; height];
        output
            .par_chunks_mut(rows)
            .enumerate()
            .for_each(|(tile, out)| {
                let first = tile * rows;
                let batches = out.len().div_ceil(packed_width);
                let mut packed = vec![Packed::default(); batches * columns];
                let mut salt_rows = vec![Val::default(); out.len() * SALT_WIDTH];
                let mut column = 0;
                for &index in group {
                    let matrix = &matrices[index];
                    salts[index].fill(first, &mut salt_rows);
                    for batch in 0..batches {
                        let row = batch * packed_width;
                        let valid = (out.len() - row).min(packed_width);
                        if self.variant.tiled() {
                            // Read each source row contiguously, then pack its lanes.
                            // Avoid heap-backed row copies and nested matrix iterators.
                            for lane in 0..valid {
                                for (col, value) in matrix
                                    .row(first + row + lane)
                                    .unwrap()
                                    .into_iter()
                                    .enumerate()
                                {
                                    packed[batch * columns + column + col].as_slice_mut()[lane] =
                                        value;
                                }
                            }
                        } else {
                            for col in 0..matrix.width() {
                                packed[batch * columns + column + col] = Packed::from_fn(|lane| {
                                    if lane < valid {
                                        matrix.get(first + row + lane, col).unwrap()
                                    } else {
                                        Val::default()
                                    }
                                });
                            }
                        }
                        for col in 0..SALT_WIDTH {
                            packed[batch * columns + column + matrix.width() + col] =
                                Packed::from_fn(|lane| {
                                    if lane < valid {
                                        salt_rows[(row + lane) * SALT_WIDTH + col]
                                    } else {
                                        Val::default()
                                    }
                                });
                        }
                    }
                    column += matrix.width() + SALT_WIDTH;
                }
                for (batch, dest) in out.chunks_mut(packed_width).enumerate() {
                    let digest: [Packed; 4] = self.hash.hash_iter(
                        packed[batch * columns..(batch + 1) * columns]
                            .iter()
                            .copied(),
                    );
                    for (lane, value) in dest.iter_mut().enumerate() {
                        *value = std::array::from_fn(|col| digest[col].as_slice()[lane]);
                    }
                }
            });
        output
    }

    fn build<M: Matrix<Val>>(&self, matrices: Vec<M>) -> (MerkleCap<Val, Digest>, Tree<M>) {
        assert!(!matrices.is_empty());
        assert!(
            matrices.iter().all(|m| m.height().is_power_of_two()),
            "CPU candidate requires power-of-two matrices"
        );
        let max_height = matrices.iter().map(Matrix::height).max().unwrap();
        let cap_height = self.cap_height.min(max_height.ilog2() as usize);
        let start = Instant::now();
        let salts: Vec<_> = {
            let mut rng = self.rng.lock().unwrap();
            matrices
                .iter()
                .map(|m| {
                    if self.variant.replay() {
                        Salts::Replay(
                            Checkpoints::capture(&mut *rng, m.height())
                                .expect("CPU salt checkpoints"),
                        )
                    } else {
                        Salts::Dense(
                            p3_matrix::dense::RowMajorMatrix::<Val>::rand(
                                &mut *rng,
                                m.height(),
                                SALT_WIDTH,
                            )
                            .values,
                        )
                    }
                })
                .collect()
        };
        let salt_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        let group: Vec<_> = (0..matrices.len())
            .filter(|&i| matrices[i].height() == max_height)
            .collect();
        let mut layers = vec![self.leaves(&matrices, &salts, &group)];
        let mut leaf_ns = start.elapsed().as_nanos();
        while layers.last().unwrap().len() > 1 {
            let previous = layers.last().unwrap();
            let height = previous.len() / 2;
            let group: Vec<_> = (0..matrices.len())
                .filter(|&i| matrices[i].height() == height)
                .collect();
            let injected = if group.is_empty() {
                None
            } else {
                let start = Instant::now();
                let result = self.leaves(&matrices, &salts, &group);
                leaf_ns += start.elapsed().as_nanos();
                Some(result)
            };
            let mut next = vec![[Val::default(); 4]; height];
            next.par_chunks_mut(Packed::WIDTH)
                .enumerate()
                .for_each(|(batch, out)| {
                    let first = batch * Packed::WIDTH;
                    if out.len() == Packed::WIDTH {
                        let left = std::array::from_fn(|col| {
                            Packed::from_fn(|lane| previous[2 * (first + lane)][col])
                        });
                        let right = std::array::from_fn(|col| {
                            Packed::from_fn(|lane| previous[2 * (first + lane) + 1][col])
                        });
                        let mut digest: [Packed; 4] = self.compress.compress([left, right]);
                        if let Some(values) = &injected {
                            let injected = std::array::from_fn(|col| {
                                Packed::from_fn(|lane| values[first + lane][col])
                            });
                            digest = self.compress.compress([digest, injected]);
                        }
                        Packed::unpack_into(&digest, out);
                    } else {
                        for (offset, out) in out.iter_mut().enumerate() {
                            let index = first + offset;
                            let mut digest = self
                                .compress
                                .compress([previous[2 * index], previous[2 * index + 1]]);
                            if let Some(values) = &injected {
                                digest = self.compress.compress([digest, values[index]]);
                            }
                            *out = digest;
                        }
                    }
                });
            layers.push(next);
        }
        let cap = MerkleCap::new(layers[layers.len() - 1 - cap_height].clone());
        eprintln!("CPU_COMMITMENT {{\"variant\":\"{}\",\"height\":{},\"matrices\":{},\"salt_bytes\":{},\"tree_bytes\":{},\"salt_ns\":{},\"leaf_ns\":{},\"hash_scratch_limit\":{}}}",
            self.variant.name(),max_height,matrices.len(),salts.iter().map(Salts::bytes).sum::<usize>(),
            layers.iter().map(|v| v.capacity()*size_of::<Digest>()).sum::<usize>(),salt_ns,leaf_ns,HASH_SCRATCH_BYTES);
        (
            cap,
            Tree {
                matrices,
                salts,
                layers,
                cap_height,
            },
        )
    }
}

impl Mmcs<Val> for CpuMmcs {
    type ProverData<M> = Data<M>;
    type Commitment = <Reference as Mmcs<Val>>::Commitment;
    type Proof = <Reference as Mmcs<Val>>::Proof;
    type Error = <Reference as Mmcs<Val>>::Error;
    fn commit<M: Matrix<Val>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        if self.variant == Variant::Reference {
            let (cap, data) = self.reference.commit(inputs);
            (cap, Data::Reference(data))
        } else {
            let (cap, data) = self.build(inputs);
            (cap, Data::Compact(data))
        }
    }
    fn get_matrices<'a, M: Matrix<Val>>(&self, data: &'a Data<M>) -> Vec<&'a M> {
        match data {
            Data::Reference(d) => self.reference.get_matrices(d),
            Data::Compact(d) => d.matrices.iter().collect(),
        }
    }
    fn open_batch<M: Matrix<Val>>(&self, index: usize, data: &Data<M>) -> BatchOpening<Val, Self> {
        match data {
            Data::Reference(d) => {
                let (values, proof) = self.reference.open_batch(index, d).unpack();
                BatchOpening::new(values, proof)
            }
            Data::Compact(d) => {
                let max_height = d.layers[0].len();
                assert!(index < max_height);
                let mut values = Vec::with_capacity(d.matrices.len());
                let mut salts = Vec::with_capacity(d.matrices.len());
                for (matrix, saved) in d.matrices.iter().zip(&d.salts) {
                    let row = index >> (max_height.ilog2() - matrix.height().ilog2());
                    values.push(matrix.row(row).unwrap().into_iter().collect());
                    let mut salt = vec![Val::default(); SALT_WIDTH];
                    saved.fill(row, &mut salt);
                    salts.push(salt);
                }
                let siblings = (0..d.layers.len() - 1 - d.cap_height)
                    .map(|level| d.layers[level][(index >> level) ^ 1])
                    .collect();
                BatchOpening::new(values, (salts, siblings))
            }
        }
    }
    fn verify_batch(
        &self,
        cap: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, Val, Self>,
    ) -> Result<(), Self::Error> {
        let (values, proof) = opening.unpack();
        self.reference
            .verify_batch(cap, dimensions, index, BatchOpeningRef::new(values, proof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::SeedableRng;
    fn config(variant: Variant, tile: usize) -> CpuMmcs {
        let p = default_goldilocks_poseidon2_8();
        CpuMmcs::new(
            MyHash::new(p.clone()),
            MyCompress::new(p),
            0,
            ChaCha20Rng::from_seed([29; 32]),
        )
        .with_variant(variant)
        .with_tile_rows(tile)
    }
    #[test]
    fn tiled_and_replayed_commitments_match_reference_across_boundaries() {
        for threads in [1, 4] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    for tile in [256, 1024, 4096] {
                        for variant in [Variant::Hash, Variant::Memory, Variant::Combined] {
                            let reference = config(Variant::Reference, tile);
                            let candidate = config(variant, tile);
                            // Successive commitments also verify the continuing salt stream.
                            for heights in [vec![1], vec![4, 2], vec![2048, 1024, 2048]] {
                                let matrices: Vec<_> = heights
                                    .iter()
                                    .enumerate()
                                    .map(|(i, &h)| {
                                        RowMajorMatrix::new(
                                            (0..h * (i + 3))
                                                .map(|v| Val::from_u64(v as u64 + 17))
                                                .collect(),
                                            i + 3,
                                        )
                                    })
                                    .collect();
                                let dimensions: Vec<_> =
                                    matrices.iter().map(Matrix::dimensions).collect();
                                let (expected, ed) = reference.commit(matrices.clone());
                                let (actual, ad) = candidate.commit(matrices);
                                assert_eq!(expected, actual);
                                let max = *heights.iter().max().unwrap();
                                for index in
                                    [0, max - 1, 1023.min(max - 1), 1024.min(max - 1), max - 1]
                                {
                                    let a = reference.open_batch(index, &ed);
                                    let b = candidate.open_batch(index, &ad);
                                    assert_eq!(a.opened_values, b.opened_values);
                                    assert_eq!(a.opening_proof, b.opening_proof);
                                    reference
                                        .verify_batch(
                                            &actual,
                                            &dimensions,
                                            index,
                                            BatchOpeningRef::new(
                                                &b.opened_values,
                                                &b.opening_proof,
                                            ),
                                        )
                                        .unwrap();
                                }
                            }
                        }
                    }
                });
        }
    }
}

#[cfg(test)]
mod pcs_tests {
    use super::*;
    use crate::block_v2::profile::{self, Challenge};
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::{Pcs, PolynomialSpace};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::StarkGenericConfig;
    #[test]
    fn bounded_openings_match_complete_reference_transcript() {
        let run = |variant| {
            // Fixed public seeds only for differential testing, not proving APIs.
            let config = profile::cpu_preprocessing_config(variant);
            let reference = profile::cpu_preprocessing_config(Variant::Reference);
            let pcs = config.pcs();
            let domains: Vec<_> = [8, 16, 4]
                .into_iter()
                .map(|n| pcs.natural_domain_for_degree(n))
                .collect();
            let matrices: Vec<_> = domains
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    (
                        *d,
                        RowMajorMatrix::new(
                            (0..(d.size() / 2) * (i + 3))
                                .map(|v| Val::from_usize(v + 1))
                                .collect(),
                            i + 3,
                        ),
                    )
                })
                .collect();
            let (cap, data) = pcs.commit(matrices);
            let mut challenger = config.initialise_challenger();
            challenger.observe(cap.clone());
            let point: Challenge = challenger.sample_algebra_element();
            let other = point + Challenge::ONE;
            let (values, proof) =
                pcs.open(vec![(&data, vec![vec![point, other]; 3])], &mut challenger);
            let mut verifier = reference.initialise_challenger();
            verifier.observe(cap.clone());
            let sampled: Challenge = verifier.sample_algebra_element();
            assert_eq!(sampled, point);
            let claims = domains
                .into_iter()
                .zip(values[0].iter())
                .map(|(d, v)| (d, vec![(point, v[0].clone()), (other, v[1].clone())]))
                .collect();
            reference
                .pcs()
                .verify(vec![(cap.clone(), claims)], &proof, &mut verifier)
                .unwrap();
            postcard::to_allocvec(&(cap, values, proof)).unwrap()
        };
        let expected = run(Variant::Reference);
        for variant in [Variant::Hash, Variant::Memory, Variant::Combined] {
            assert_eq!(run(variant), expected);
        }
    }
}
