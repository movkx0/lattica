//! Retained salt ownership. Device salts stay private to one proof session;
//! only final queried rows may be copied to host proof material.
use super::*;
use device::{DeviceMatrix, DeviceSession, Extension, PublicSalts, ReplaySalts, RowOrder};

pub enum SaltStore {
    Host(Vec<RowMajorMatrix<Val>>),
    Device(Vec<DeviceMatrix>),
    PublicDevice(Vec<PublicSalts>),
    Replay(Vec<ReplaySalts>),
}

#[derive(Clone, Copy)]
pub(super) enum SaltView<'a> {
    Host(&'a [RowMajorMatrix<Val>]),
    Device(&'a [DeviceMatrix]),
    PublicDevice(&'a [PublicSalts]),
    Replay(&'a [ReplaySalts]),
}
impl SaltStore {
    pub(super) fn retained_host_backing(&self) -> Result<usize, String> {
        use super::cache_metadata::{add, capacity};
        let mut bytes;
        match self {
            Self::Host(matrices) => {
                bytes = capacity::<RowMajorMatrix<Val>>(matrices.capacity())?;
                for matrix in matrices {
                    bytes = add(bytes, capacity::<Val>(matrix.values.capacity())?)?;
                }
            }
            Self::Device(matrices) => {
                bytes = capacity::<DeviceMatrix>(matrices.capacity())?;
                for matrix in matrices {
                    bytes = add(bytes, matrix.retained_host_backing())?;
                }
            }
            Self::PublicDevice(matrices) => {
                bytes = capacity::<PublicSalts>(matrices.capacity())?;
                for matrix in matrices {
                    bytes = add(bytes, matrix.cached_host_backing())?;
                }
            }
            Self::Replay(recipes) => {
                bytes = capacity::<ReplaySalts>(recipes.capacity())?;
                for recipe in recipes {
                    bytes = add(bytes, recipe.retained_host_backing())?;
                }
            }
        }
        Ok(bytes)
    }

    pub(super) fn cached_public_backing(
        &self,
        height: usize,
        count: usize,
    ) -> Result<(usize, bool), String> {
        use super::cache_metadata::{add, capacity};
        match self {
            Self::Host(matrices) => {
                let words = height
                    .checked_mul(4)
                    .ok_or("cached PCS host salt height overflow")?;
                if matrices.len() != count
                    || matrices
                        .iter()
                        .any(|m| m.width != 4 || m.values.len() != words)
                {
                    return Err("cached PCS host salt geometry".into());
                }
                let mut bytes = capacity::<RowMajorMatrix<Val>>(matrices.capacity())?;
                for matrix in matrices {
                    bytes = add(bytes, capacity::<Val>(matrix.values.capacity())?)?;
                }
                Ok((bytes, false))
            }
            Self::PublicDevice(matrices) => {
                if matrices.len() != count
                    || matrices
                        .iter()
                        .any(|m| m.spec().rows() != height || m.spec().columns() != 4)
                {
                    return Err("cached PCS public salt geometry".into());
                }
                let mut bytes = capacity::<PublicSalts>(matrices.capacity())?;
                for matrix in matrices {
                    bytes = add(bytes, matrix.cached_host_backing())?;
                }
                Ok((bytes, true))
            }
            Self::Device(_) | Self::Replay(_) => {
                Err("private salts cannot enter preprocessing cache".into())
            }
        }
    }
    pub(super) fn view(&self) -> SaltView<'_> {
        match self {
            Self::Host(m) => SaltView::Host(m),
            Self::Device(m) => SaltView::Device(m),
            Self::PublicDevice(m) => SaltView::PublicDevice(m),
            Self::Replay(m) => SaltView::Replay(m),
        }
    }
}

#[cfg(all(test, feature = "stream"))]
#[test]
fn retained_salt_backing_counts_host_and_empty_device_capacities() {
    use crate::spill_alloc::allocation_requests::measure;
    let (host, allocated) = measure(|| {
        let mut matrices = Vec::with_capacity(3);
        let mut values = Vec::with_capacity(67);
        values.resize(32, Val::default());
        matrices.push(RowMajorMatrix::new(values, 4));
        SaltStore::Host(matrices)
    });
    let (bytes, census) = measure(|| host.retained_host_backing().unwrap());
    assert_eq!(bytes, allocated.bytes);
    assert_eq!(census.calls, 0);
    assert!(!allocated.overflow && !census.overflow);
    for variant in 0..3 {
        let (store, allocated) = measure(|| match variant {
            0 => SaltStore::Device(Vec::with_capacity(5)),
            1 => SaltStore::PublicDevice(Vec::with_capacity(5)),
            _ => SaltStore::Replay(Vec::with_capacity(5)),
        });
        let (bytes, census) = measure(|| store.retained_host_backing().unwrap());
        assert_eq!(bytes, allocated.bytes);
        assert_eq!(allocated.calls, 1);
        assert_eq!(census.calls, 0);
    }
}
impl SaltView<'_> {
    pub(super) fn validate(
        self,
        session: &DeviceSession,
        height: usize,
        count: usize,
    ) -> Result<(), String> {
        match self {
            Self::Host(salts) => {
                if salts.len() != count
                    || salts
                        .iter()
                        .any(|s| s.width != 4 || height.checked_mul(4) != Some(s.values.len()))
                {
                    return Err("owned PCS salt geometry mismatch".into());
                }
            }
            Self::Device(salts) => {
                if salts.len() != count {
                    return Err("owned PCS device salt count mismatch".into());
                }
                for salt in salts {
                    salt.check_session(session)?;
                    let s = salt.spec();
                    if s.rows() != height
                        || s.columns() != 4
                        || s.extension() != Extension::Base
                        || s.order() != RowOrder::BitReversed
                        || s.shift() != 1
                    {
                        return Err("owned PCS device salt geometry mismatch".into());
                    }
                }
            }
            Self::Replay(salts) => {
                if salts.len() != count {
                    return Err("owned PCS replay salt count mismatch".into());
                }
                for salt in salts {
                    salt.check_session(session)?;
                    let s = salt.spec();
                    if s.rows() != height
                        || s.columns() != 4
                        || s.extension() != Extension::Base
                        || s.order() != RowOrder::BitReversed
                        || s.shift() != 1
                    {
                        return Err("owned PCS replay salt geometry mismatch".into());
                    }
                }
            }
            Self::PublicDevice(salts) => {
                if salts.len() != count {
                    return Err("owned PCS public salt count mismatch".into());
                }
                for salt in salts {
                    salt.check_context(session)?;
                    let s = salt.spec();
                    if s.rows() != height
                        || s.columns() != 4
                        || s.extension() != Extension::Base
                        || s.order() != RowOrder::BitReversed
                        || s.shift() != 1
                    {
                        return Err("owned PCS public salt geometry mismatch".into());
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn gather(
        self,
        session: &DeviceSession,
        indices: &[usize],
        allowance: usize,
    ) -> Result<Vec<Vec<Vec<Val>>>, String> {
        let count = match self {
            Self::Host(m) => m.len(),
            Self::Device(m) => m.len(),
            Self::PublicDevice(m) => m.len(),
            Self::Replay(m) => m.len(),
        };
        let bytes = count
            .checked_mul(indices.len())
            .and_then(|n| n.checked_mul(64))
            .ok_or("salt query size overflow")?;
        if indices.is_empty() || indices.len() > 256 || bytes > allowance {
            return Err("salt queries exceed their host allowance".into());
        }
        let mut rows: Vec<_> = (0..indices.len())
            .map(|_| Vec::with_capacity(count))
            .collect();
        match self {
            Self::Host(matrices) => {
                for m in matrices {
                    for (row, &index) in rows.iter_mut().zip(indices) {
                        row.push(
                            m.values
                                .get(index * 4..index * 4 + 4)
                                .ok_or("salt row outside commitment")?
                                .to_vec(),
                        );
                    }
                }
            }
            Self::Device(matrices) => {
                for m in matrices {
                    let words = session.gather_rows(m, indices, allowance)?;
                    for (row, salt) in rows.iter_mut().zip(words.chunks_exact(4)) {
                        row.push(salt.iter().map(|&n| Val::new(n)).collect());
                    }
                }
            }
            Self::Replay(recipes) => {
                for recipe in recipes {
                    let matrix = recipe.materialize(session)?;
                    let words = session.gather_rows(&matrix, indices, allowance)?;
                    for (row, salt) in rows.iter_mut().zip(words.chunks_exact(4)) {
                        row.push(salt.iter().map(|&n| Val::new(n)).collect());
                    }
                    // Wipe this output before materializing the next recipe.
                    drop(matrix);
                }
            }
            Self::PublicDevice(matrices) => {
                for m in matrices {
                    let alias = session.import_public_salts(m)?;
                    let words = session.gather_rows(&alias, indices, allowance)?;
                    for (row, salt) in rows.iter_mut().zip(words.chunks_exact(4)) {
                        row.push(salt.iter().map(|&n| Val::new(n)).collect());
                    }
                }
            }
        }
        Ok(rows)
    }
}

impl CandidateMmcs {
    pub(crate) fn activate_private_randomness(
        &self,
        session: &DeviceSession,
        failure: &crate::block_v2::randomness::Failure,
    ) -> Result<(), String> {
        if !self.gpu
            || self.public_preprocessing
            || self.cap_height != crate::block_v2::profile::CAP_HEIGHT
        {
            return Err("private GPU salts require a private GPU MMCS".into());
        }
        self.rng.activate(session, failure)
    }

    pub(crate) fn preflight_private_salts(
        &self,
        shapes: &[LdeInputShape],
        host_budget: usize,
        capture_bits: usize,
        pending: &[usize],
    ) -> Result<LdeCommitPlan, String> {
        self.require_device_salts()?;
        if !self.rng.is_device()? || shapes.is_empty() || shapes.len() > 256 {
            return Err("private GPU salt stream or commitment geometry is unavailable".into());
        }
        let height = shapes[0]
            .height
            .checked_shl(
                shapes[0]
                    .added_bits
                    .try_into()
                    .map_err(|_| "salt height overflow")?,
            )
            .filter(|h| *h <= 1 << 25)
            .ok_or("private salt height exceeds its bound")?;
        let mut extra = pending.to_vec();
        // Private salts are replayed one matrix at a time. Include both the
        // temporary output and rejection sampler scratch during commitment.
        extra.push(device::salt_replay_workspace_bytes(height * 4)?);
        let plan = engine::plan_lde_commit_storage(
            shapes,
            self.cap_height,
            host_budget,
            engine::lde_plan::LdeRetention::DeviceOnly,
            Some(capture_bits),
            &extra,
        )?;
        self.rng.with_device(|rng| {
            rng.preflight_salt_replay(&vec![height * 4; shapes.len()], pending)
        })?;
        Ok(plan)
    }

    pub(crate) fn private_device_salts(
        &self,
        height: usize,
        count: usize,
    ) -> Result<Vec<ReplaySalts>, String> {
        if count == 0 || count > 256 || !height.is_power_of_two() || height > 1 << 25 {
            return Err("private GPU salt batch geometry exceeds its bound".into());
        }
        let spec =
            device::MatrixSpec::new(height.ilog2(), 4, Extension::Base, RowOrder::BitReversed, 1)?;
        self.rng
            .with_device(|rng| rng.prepare_salt_replay(spec, count))
    }

    pub(crate) fn preflight_public_preprocessing_salts(
        &self,
        shapes: &[device::TraceCommitShape],
        host_budget: usize,
    ) -> Result<LdeCommitPlan, String> {
        self.require_device_salts()?;
        if shapes.is_empty()
            || shapes.len() > 256
            || shapes
                .iter()
                .any(|s| s.random_columns != 0 || s.random_words != 0)
        {
            return Err("public salt admission requires preprocessing shapes".into());
        }
        let height = shapes[0]
            .height
            .checked_shl(super::super::profile::LOG_BLOWUP as u32)
            .filter(|h| *h <= 1 << 25)
            .ok_or("public salt commitment height exceeds its bound")?;
        let mut extra: Vec<_> = shapes.iter().flat_map(|s| s.allocation_bytes()).collect();
        extra.extend(core::iter::repeat_n(height * 4 * 8, shapes.len()));
        engine::plan_lde_commit_storage(
            &shapes.iter().map(|s| s.lde_shape()).collect::<Vec<_>>(),
            self.cap_height,
            host_budget,
            engine::lde_plan::LdeRetention::DeviceOnly,
            Some(0),
            &extra,
        )
    }

    pub(crate) fn commit_preprocessing_with_public_salts(
        &self,
        inputs: &[device::TraceCommitInput],
        salts: Vec<PublicSalts>,
        session: &DeviceSession,
        host_budget: usize,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.require_device_salts()?;
        if inputs.is_empty() || inputs.iter().any(|input| !input.is_preprocessing()) {
            return Err("public salts require trusted preprocessing inputs".into());
        }
        let aliases: Vec<_> = salts
            .iter()
            .map(|s| session.import_public_salts(s))
            .collect::<Result<_, _>>()?;
        let borrowed: Vec<_> = aliases
            .iter()
            .map(engine::lde_execute::SaltInput::Device)
            .collect();
        let output = engine::lde_execute::commit_traces_with_salts(
            inputs,
            &borrowed,
            session,
            self.cap_height,
            host_budget,
            engine::lde_plan::LdeRetention::DeviceOnly,
        )?;
        self.finish_salted_commit(output, SaltStore::PublicDevice(salts), session, true)
    }

    pub(crate) fn commit_traces_with_device_salts(
        &self,
        inputs: &[device::TraceCommitInput],
        salts: Vec<ReplaySalts>,
        session: &DeviceSession,
        host_budget: usize,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.require_device_salts()?;
        if inputs.iter().any(|input| input.is_preprocessing()) {
            return Err("private device salts cannot enter reusable public preprocessing".into());
        }
        let borrowed: Vec<_> = salts
            .iter()
            .map(engine::lde_execute::SaltInput::Replay)
            .collect();
        let output = engine::lde_execute::commit_traces_with_salts(
            inputs,
            &borrowed,
            session,
            self.cap_height,
            host_budget,
            engine::lde_plan::LdeRetention::DeviceOnly,
        )?;
        self.finish_device_salts(output, salts, session)
    }

    pub(crate) fn commit_quotient_with_device_salts(
        &self,
        input: &device::QuotientCommitInput,
        salts: Vec<ReplaySalts>,
        session: &DeviceSession,
        host_budget: usize,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.commit_quotients_with_device_salts(&[input], salts, session, host_budget)
    }

    pub(crate) fn commit_quotients_with_device_salts(
        &self,
        inputs: &[&device::QuotientCommitInput],
        salts: Vec<ReplaySalts>,
        session: &DeviceSession,
        host_budget: usize,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.require_device_salts()?;
        let borrowed: Vec<_> = salts
            .iter()
            .map(engine::lde_execute::SaltInput::Replay)
            .collect();
        let output = engine::lde_execute::commit_quotient_batch_with_salts(
            inputs,
            &borrowed,
            self.cap_height,
            host_budget,
            engine::lde_plan::LdeRetention::DeviceOnly,
            Some(session),
        )?;
        self.finish_device_salts(output, salts, session)
    }

    pub(crate) fn commit_evaluations_with_device_salts(
        &self,
        inputs: &[device::EvaluationInput],
        added_bits: usize,
        salts: Vec<ReplaySalts>,
        session: &DeviceSession,
        host_budget: usize,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.require_device_salts()?;
        if added_bits != crate::block_v2::profile::LOG_BLOWUP {
            return Err("device evaluation commitments require the profile blowup".into());
        }
        let borrowed: Vec<_> = salts
            .iter()
            .map(engine::lde_execute::SaltInput::Replay)
            .collect();
        let output = engine::lde_execute::commit_owned_evaluations(
            inputs,
            added_bits,
            &borrowed,
            session,
            self.cap_height,
            host_budget,
            engine::lde_plan::LdeRetention::DeviceOnly,
        )?;
        self.finish_device_salts(output, salts, session)
    }

    fn require_device_salts(&self) -> Result<(), String> {
        if !self.gpu || !self.device_only || self.cap_height != crate::block_v2::profile::CAP_HEIGHT
        {
            return Err("device salts require the candidate device-only GPU PCS".into());
        }
        Ok(())
    }

    fn finish_device_salts(
        &self,
        output: engine::lde_execute::LdeCommitOutput,
        salts: Vec<ReplaySalts>,
        session: &DeviceSession,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.finish_salted_commit(output, SaltStore::Replay(salts), session, false)
    }

    fn finish_salted_commit(
        &self,
        output: engine::lde_execute::LdeCommitOutput,
        salts: SaltStore,
        session: &DeviceSession,
        preprocessing: bool,
    ) -> Result<(Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        if output.plan.retention != engine::lde_plan::LdeRetention::DeviceOnly
            || !output.matrices.is_empty()
            || output.plan.host_output_bytes != 0
            || output.device_matrices.is_empty()
        {
            return Err("device salt commitment unexpectedly materialized host storage".into());
        }
        salts.view().validate(
            session,
            output.plan.output_height(),
            output.device_matrices.len(),
        )?;
        let cap = Commitment::new(output.cap().to_vec());
        let owned = OwnedInputs::new(
            output.device_matrices,
            preprocessing,
            output.plan.output_height(),
        );
        Ok((
            cap,
            ProverData::DeviceOnly {
                owned,
                salts,
                tree: output.tree,
            },
        ))
    }
}

type Commitment = <CandidateMmcs as Mmcs<Val>>::Commitment;
