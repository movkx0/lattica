//! Salted quadratic/cubic FRI layers, retained entirely in their proof session.
use super::*;
use crate::block_v2::profile::{Challenge, ChallengeMmcs};
use device::{
    DeviceCommitment, DeviceMatrix, DeviceSession, Extension, MatrixSpec, ReplaySalts, RowOrder,
};
use p3_field::PrimeCharacteristicRing;

pub(crate) type FriExtensionMmcs<F> =
    crate::block_v2::extension_mmcs::CandidateExtensionMmcs<Val, F, CandidateMmcs>;

/// Only the two pinned Goldilocks extension bases implemented by the kernels.
pub trait FriExtension: p3_field::ExtensionField<Val> {
    const DEVICE_EXTENSION: Extension;
}
impl FriExtension for crate::config::Challenge {
    const DEVICE_EXTENSION: Extension = Extension::Quadratic;
}
impl FriExtension for Challenge {
    const DEVICE_EXTENSION: Extension = Extension::Cubic;
}

pub(crate) struct FriData {
    leaves: DeviceMatrix,
    salts: FriSalts,
    commitment: DeviceCommitment,
}

enum FriSalts {
    Device(DeviceMatrix),
    Replay(ReplaySalts),
}

impl CandidateMmcs {
    pub(crate) fn commit_fri_device(
        &self,
        session: &DeviceSession,
        vector: &DeviceMatrix,
        host_allowance: usize,
    ) -> Result<(<Self as Mmcs<Val>>::Commitment, FriData), String> {
        if vector.spec().extension() != Extension::Cubic {
            return Err("binary candidate FRI requires cubic inputs".into());
        }
        self.commit_fri_device_arity(session, vector, 1, host_allowance)
    }

    pub(crate) fn commit_fri_device_arity(
        &self,
        session: &DeviceSession,
        vector: &DeviceMatrix,
        log_arity: usize,
        host_allowance: usize,
    ) -> Result<(<Self as Mmcs<Val>>::Commitment, FriData), String> {
        if !self.gpu || self.cap_height != crate::block_v2::profile::CAP_HEIGHT {
            return Err("device FRI requires the candidate GPU MMCS".into());
        }
        let leaves = session.fri_leaves_with_arity(vector, log_arity)?;
        let spec = MatrixSpec::new(
            leaves.spec().rows().ilog2(),
            4,
            Extension::Base,
            RowOrder::BitReversed,
            1,
        )?;
        // Raw random fields and their canonical upload vector coexist briefly.
        if self.rng.is_device()? {
            session.preflight_commit(&leaves, self.cap_height)?;
            self.rng
                .with_device(|rng| rng.preflight_salt_replay(&[spec.words()], &[]))?;
            let guard = self.rng.begin()?;
            let (salts, recipe) = self
                .rng
                .with_device(|rng| rng.sample_salt_with_replay(spec))?;
            let commitment = session.commit(&leaves, &salts, self.cap_height)?;
            // The original draw was consumed by the commitment; only replay
            // metadata survives until queries, never the full salt matrix.
            drop(salts);
            let cap = <Self as Mmcs<Val>>::Commitment::new(commitment.cap().to_vec());
            let result = (
                cap,
                FriData {
                    leaves,
                    salts: FriSalts::Replay(recipe),
                    commitment,
                },
            );
            guard.complete();
            eprintln!(
                "bounded_gpu_random_stage stage=fri salt_replay=true retained_salt_sample_bytes=0 sample_upload_bytes=0 sample_readback_bytes=0"
            );
            return Ok(result);
        }
        if spec
            .bytes()
            .checked_mul(2)
            .is_none_or(|n| n > host_allowance)
        {
            return Err("FRI salt staging exceeds host allowance".into());
        }
        session.preflight_commit(&leaves, self.cap_height)?;
        let random = {
            let mut rng = self.rng.lock().map_err(|_| "FRI salt stream poisoned")?;
            RowMajorMatrix::<Val>::rand(&mut *rng, spec.rows(), 4)
        };
        let words: Vec<_> = random.values.iter().map(|v| v.as_canonical_u64()).collect();
        drop(random);
        let salts = session.upload(spec, &words)?;
        drop(words);
        self.finish_fri_commit(session, leaves, salts)
    }

    pub(crate) fn commit_fri_with_device_salts(
        &self,
        session: &DeviceSession,
        vector: &DeviceMatrix,
        salts: DeviceMatrix,
    ) -> Result<(<Self as Mmcs<Val>>::Commitment, FriData), String> {
        if !self.gpu || self.cap_height != crate::block_v2::profile::CAP_HEIGHT {
            return Err("device FRI requires the candidate GPU MMCS".into());
        }
        let leaves = session.fri_leaves(vector)?;
        self.finish_fri_commit(session, leaves, salts)
    }

    fn finish_fri_commit(
        &self,
        session: &DeviceSession,
        leaves: DeviceMatrix,
        salts: DeviceMatrix,
    ) -> Result<(<Self as Mmcs<Val>>::Commitment, FriData), String> {
        let commitment = session.commit(&leaves, &salts, self.cap_height)?;
        let cap = <Self as Mmcs<Val>>::Commitment::new(commitment.cap().to_vec());
        Ok((
            cap,
            FriData {
                leaves,
                salts: FriSalts::Device(salts),
                commitment,
            },
        ))
    }
}

impl FriData {
    /// Exact backing storage after the enclosing query plan has been admitted.
    pub(crate) fn proof_vector<T>(count: usize) -> Result<Vec<T>, String> {
        if count > 1 << 26
            || count
                .checked_mul(core::mem::size_of::<T>())
                .is_none_or(|n| n > 1 << 30)
        {
            return Err("FRI proof vector exceeds storage bound".into());
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| "FRI proof vector allocation failed")?;
        if core::mem::size_of::<T>() != 0 && values.capacity() != count {
            return Err("FRI proof vector capacity exceeds plan".into());
        }
        Ok(values)
    }

    /// Returned rows, salts, paths and descriptors plus gather staging. Engine
    /// staging, device handles and allocator overhead have separate lifetimes.
    pub(crate) fn query_host_bytes<F: FriExtension>(
        log_height: usize,
        arity: usize,
        queries: usize,
    ) -> Result<usize, String> {
        if log_height > 25
            || !(2..=16).contains(&arity)
            || !arity.is_power_of_two()
            || queries == 0
            || queries > crate::block_v2::profile::NUM_QUERIES
            || core::mem::size_of::<F>() != F::DIMENSION * 8
        {
            return Err("FRI proof query geometry exceeds bound".into());
        }
        let path = log_height.saturating_sub(crate::block_v2::profile::CAP_HEIGHT) * 32;
        // Both raw gathers and converted row/salt outputs coexist. Each gather
        // also uploads its own index words. Paths are already returned as Val.
        let per_query = 2 * (arity * core::mem::size_of::<F>() + 4 * 8)
            + 2 * 8
            + path
            + core::mem::size_of::<BatchOpening<F, FriExtensionMmcs<F>>>()
            + core::mem::size_of::<Vec<F>>()
            + core::mem::size_of::<Vec<Val>>();
        Ok(queries * per_query)
    }

    pub(crate) fn open_rows(
        &self,
        session: &DeviceSession,
        indices: &[usize],
    ) -> Result<Vec<BatchOpening<Challenge, ChallengeMmcs>>, String> {
        self.open_rows_extension::<Challenge>(session, indices)
    }

    pub(crate) fn open_rows_extension<F: FriExtension>(
        &self,
        session: &DeviceSession,
        indices: &[usize],
    ) -> Result<Vec<BatchOpening<F, FriExtensionMmcs<F>>>, String> {
        self.open_rows_extension_with_allowance::<F>(session, indices, 1 << 20)
    }

    pub(crate) fn open_rows_extension_with_allowance<F: FriExtension>(
        &self,
        session: &DeviceSession,
        indices: &[usize],
        host_allowance: usize,
    ) -> Result<Vec<BatchOpening<F, FriExtensionMmcs<F>>>, String> {
        let host_allowance = host_allowance.min(1 << 20);
        if self.leaves.spec().extension() != F::DEVICE_EXTENSION {
            return Err("FRI query extension does not match its commitment".into());
        }
        // Query count is fixed by the profile; only queried field values,
        // four salts and Merkle authentication paths are proof material.
        let host_bytes = Self::query_host_bytes::<F>(
            self.leaves.spec().rows().ilog2() as usize,
            self.leaves.spec().columns(),
            indices.len(),
        )?;
        if host_bytes > host_allowance {
            return Err("FRI query batch exceeds host proof allowance".into());
        }
        let mut openings = Self::proof_vector(indices.len())?;
        let values = session.gather_rows(&self.leaves, indices, host_allowance)?;
        let salts = match &self.salts {
            FriSalts::Device(matrix) => session.gather_rows(matrix, indices, host_allowance)?,
            FriSalts::Replay(recipe) => {
                let matrix = recipe.materialize(session)?;
                session.gather_rows(&matrix, indices, host_allowance)?
            }
        };
        let paths = self.commitment.open_many(indices)?;
        for (query, path) in paths.into_iter().enumerate() {
            let width = self.leaves.spec().columns() * F::DIMENSION;
            let mut row = Self::proof_vector(self.leaves.spec().columns())?;
            for v in values[query * width..query * width + width].chunks_exact(F::DIMENSION) {
                row.push(F::from_basis_coefficients_fn(|i| Val::from_u64(v[i])));
            }
            let mut salt = Self::proof_vector(4)?;
            salt.extend(
                salts[query * 4..query * 4 + 4]
                    .iter()
                    .map(|n| Val::from_u64(*n)),
            );
            let mut rows = Self::proof_vector(1)?;
            rows.push(row);
            let mut salts = Self::proof_vector(1)?;
            salts.push(salt);
            openings.push(BatchOpening::new(rows, (salts, path)));
        }
        Ok(openings)
    }
}
