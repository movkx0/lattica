//! Candidate-only GPU commitments; verification always uses the upstream CPU MMCS.
//! No parameter, salt distribution, serialized proof, or production ABI change.
//! Only equal-height, power-of-two batches are admitted by the selected GPU path.
pub(crate) mod cache_metadata;
mod compact_data;
mod device_data;
mod fri_data;
mod owned_data;
mod owned_queries;
pub(crate) use fri_data::{FriData, FriExtension, FriExtensionMmcs};
pub use owned_data::OwnedInputs;
pub(crate) mod engine;
pub(crate) use engine::begin_memory_window;
mod compact_salts;
#[cfg(feature = "gpu-metal")]
mod shared_preprocessing;
mod prefix_storage;
pub(crate) use engine::fri_fold::fold as fold_fri;
pub(crate) use engine::host_storage::RETAINED_HOST_BYTES as ENGINE_RETAINED_HOST_BYTES;
pub(crate) use engine::opening_reduce::{
    reduce_lde as reduce_openings, OpeningMatrix, OpeningTerm,
};
pub(crate) use engine::quotient::evaluate as evaluate_cubic_quotient;
#[cfg(test)]
#[path = "resident_pcs_tests.rs"]
mod resident_pcs_tests;

use crate::config::{MyCompress, MyHash, Val, ValMmcs};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::PrimeField64;
use p3_matrix::{dense::RowMajorMatrix, Dimensions, Matrix};
use rand_chacha::ChaCha20Rng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

pub use super::resident_pcs::initialize_research_from_env as initialize_resident_from_env;
pub use engine::{
    device, drain,
    lde_execute::{coset_lde_commit, LdeCommitOutput, LdeInput},
    lde_plan::{ColumnTile as LdeColumnTile, InputShape as LdeInputShape, LdeCommitPlan},
    plan_coset_lde_commit, report, shutdown, Limits, Snapshot,
};
static ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) use engine::TestShutdownGuard;

#[cfg(test)]
pub(crate) fn initialize_quotient_test_engine(limits: Limits) -> Result<(), String> {
    engine::initialize_mode(limits, engine::TransferMode::Serial)
}

pub(super) fn require_resident_backend() -> Result<(), String> {
    if !ENABLED.load(Ordering::Acquire) || !engine::retention_enabled()? {
        return Err("resident PCS requires LATTICA_V2_GPU_HASH=1 and retained trees".into());
    }
    Ok(())
}

/// Called by explicit Rust or native startup, before proving. Merely compiling `gpu`
/// never selects this path, and verification never initializes a GPU context.
pub fn initialize_from_env() -> Result<(), String> {
    initialize_tracked_from_env().map(|_| ())
}

pub(crate) fn initialize_tracked_from_env() -> Result<bool, String> {
    match std::env::var("LATTICA_V2_GPU_HASH") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(v) if v == "0" => Ok(false),
        Ok(v) if v == "1" => {
            let mut limits = Limits::default();
            limits.managed_bytes =
                engine::env_bytes("LATTICA_V2_GPU_MANAGED_BYTES", limits.managed_bytes)?;
            #[cfg(feature = "gpu-metal")]
            if crate::metal_compute::resident::enabled() {
                // Leave 512 MiB inside the 8 GiB temporary allowance for tables
                // and the bounded quotient interpreter's code/input/registers.
                limits.managed_bytes = limits.managed_bytes.min((8usize << 30) - (512 << 20));
            }
            let created = engine::initialize(limits)?;
            ENABLED.store(true, Ordering::Release);
            Ok(created)
        }
        _ => Err("LATTICA_V2_GPU_HASH must be 0 or 1".into()),
    }
}

pub struct CandidateMmcs {
    cpu: Arc<ValMmcs>,
    rng: super::randomness::ProofRng,
    cap_height: usize,
    gpu: bool,
    device_only: bool,
    public_preprocessing: bool,
}

mod salt_data;
pub use salt_data::SaltStore;

impl CandidateMmcs {
    pub fn new(hash: MyHash, compress: MyCompress, cap_height: usize, rng: ChaCha20Rng) -> Self {
        Self {
            cpu: Arc::new(ValMmcs::new(hash, compress, cap_height, rng.clone())),
            rng: super::randomness::ProofRng::new(rng),
            cap_height,
            gpu: ENABLED.load(Ordering::Acquire),
            device_only: false,
            public_preprocessing: false,
        }
    }
}

// Explicitly share only the input-MMCS state used by one resident PCS attempt.
// Ordinary Clone above/below retains the prior independent-clone semantics.
impl CandidateMmcs {
    /// Only this constructor grants the fixed public seed capability.
    pub(crate) fn new_public_preprocessing(
        hash: MyHash,
        compress: MyCompress,
        cap_height: usize,
    ) -> Self {
        use rand::SeedableRng;
        let mut result = Self::new(hash, compress, cap_height, ChaCha20Rng::from_seed([0; 32]));
        result.public_preprocessing = true;
        result
    }

    pub(crate) fn require_fresh_public_preprocessing(&self) -> Result<(), String> {
        if !self.public_preprocessing || !self.device_only {
            return Err(
                "GPU public salts require a trusted device-only preprocessing configuration".into(),
            );
        }
        let rng = self
            .rng
            .lock()
            .map_err(|_| "public preprocessing RNG poisoned")?;
        if rng.get_seed() != [0; 32] || rng.get_stream() != 0 || rng.get_word_pos() != 0 {
            return Err("GPU public salts must be selected before preprocessing draws".into());
        }
        Ok(())
    }

    pub(crate) fn share_for_resident(&self) -> Result<Self, String> {
        if !self.gpu || !engine::retention_enabled()? {
            return Err("resident PCS requires initialized GPU hashing and retained trees".into());
        }
        if self.cap_height != super::profile::CAP_HEIGHT {
            return Err("resident PCS requires the registered candidate cap height".into());
        }
        Ok(Self {
            cpu: Arc::clone(&self.cpu),
            rng: self.rng.clone(),
            cap_height: self.cap_height,
            gpu: self.gpu,
            device_only: super::quotient_pcs::gpu_pcs_device_only_enabled(),
            public_preprocessing: self.public_preprocessing,
        })
    }

    pub(crate) fn preflight_resident(
        &self,
        shapes: &[LdeInputShape],
        host_output_budget_bytes: usize,
    ) -> Result<LdeCommitPlan, String> {
        if !self.gpu {
            return Err("resident PCS has no GPU commitment backend".into());
        }
        engine::plan_coset_lde_commit(shapes, self.cap_height, host_output_budget_bytes)
    }

    pub(crate) fn commit_resident(
        &self,
        inputs: Vec<(
            p3_field::coset::TwoAdicMultiplicativeCoset<Val>,
            RowMajorMatrix<Val>,
        )>,
        added_bits: usize,
        host_output_budget_bytes: usize,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        self.commit_resident_retained(
            inputs,
            added_bits,
            host_output_budget_bytes,
            None,
            usize::from(super::resident_pcs::compact_prover_data()),
        )
    }

    pub(crate) fn commit_resident_with_masks(
        &self,
        inputs: Vec<(
            p3_field::coset::TwoAdicMultiplicativeCoset<Val>,
            RowMajorMatrix<Val>,
        )>,
        added_bits: usize,
        host_output_budget_bytes: usize,
        masks: Option<&[RowMajorMatrix<Val>]>,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        self.commit_resident_retained(
            inputs,
            added_bits,
            host_output_budget_bytes,
            masks,
            if super::resident_pcs::compact_prover_data() {
                super::profile::LOG_BLOWUP
            } else {
                0
            },
        )
    }

    pub(crate) fn preflight_owned_traces(
        &self,
        shapes: &[device::TraceCommitShape],
        host_budget: usize,
        samples_pending: bool,
    ) -> Result<LdeCommitPlan, String> {
        let bits = if super::resident_pcs::compact_prover_data() {
            super::profile::LOG_BLOWUP
        } else {
            0
        };
        let extra: Vec<_> = if samples_pending {
            shapes
                .iter()
                .flat_map(|shape| shape.allocation_bytes())
                .collect()
        } else {
            vec![]
        };
        self.plan_resident_storage(
            &shapes
                .iter()
                .map(|shape| shape.lde_shape())
                .collect::<Vec<_>>(),
            host_budget,
            bits,
            Some(0),
            &extra,
        )
    }

    pub(crate) fn commit_owned_traces(
        &self,
        inputs: &[device::TraceCommitInput],
        session: &device::DeviceSession,
        host_budget: usize,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        let preprocessing = inputs
            .first()
            .ok_or("empty device trace batch")?
            .is_preprocessing();
        if inputs
            .iter()
            .any(|input| input.is_preprocessing() != preprocessing)
        {
            return Err("cannot mix private traces with public preprocessing".into());
        }
        for input in inputs {
            input.check_session(session)?;
        }
        let bits = if super::resident_pcs::compact_prover_data() {
            super::profile::LOG_BLOWUP
        } else {
            0
        };
        let plan = self.preflight_owned_traces(
            &inputs.iter().map(|input| input.shape).collect::<Vec<_>>(),
            host_budget,
            false,
        )?;
        let salts: Vec<_> = {
            let mut rng = self
                .rng
                .lock()
                .map_err(|_| "resident salt stream poisoned")?;
            inputs
                .iter()
                .map(|_| RowMajorMatrix::rand(&mut *rng, plan.output_height(), 4))
                .collect()
        };
        let output = engine::lde_execute::commit_owned_traces(
            inputs,
            &salts,
            session,
            self.cap_height,
            host_budget,
            self.lde_retention(bits),
        )?;
        self.finish_lde_commit(output, salts, preprocessing)
    }

    pub(crate) fn preflight_owned_quotient(
        &self,
        shape: device::QuotientCommitShape,
        host_budget: usize,
        capture: bool,
    ) -> Result<LdeCommitPlan, String> {
        self.preflight_owned_quotients(&[shape], host_budget, capture)
    }

    pub(crate) fn quotient_batch_shapes(
        &self,
        shapes: &[device::QuotientCommitShape],
    ) -> Result<Vec<LdeInputShape>, String> {
        let chunks = shapes.iter().try_fold(0usize, |count, shape| {
            if shape.chunks == 0 || shape.chunks > super::profile::MAX_QUOTIENT_CHUNKS {
                return Err("quotient AIR chunk bound exceeded");
            }
            count
                .checked_add(shape.chunks)
                .ok_or("quotient batch count overflow")
        })?;
        if shapes.is_empty() || chunks > 256 {
            return Err("quotient batch matrix count exceeded".into());
        }
        Ok(shapes
            .iter()
            .flat_map(|shape| {
                std::iter::repeat_n(
                    LdeInputShape {
                        height: shape.height,
                        width: shape.width,
                        added_bits: super::profile::LOG_BLOWUP + 1,
                    },
                    shape.chunks,
                )
            })
            .collect())
    }

    pub(crate) fn preflight_owned_quotients(
        &self,
        shapes: &[device::QuotientCommitShape],
        host_budget: usize,
        capture: bool,
    ) -> Result<LdeCommitPlan, String> {
        let bits = if super::resident_pcs::compact_prover_data() {
            super::profile::LOG_BLOWUP
        } else {
            0
        };
        let inputs = self.quotient_batch_shapes(shapes)?;
        let pending: Vec<_> = shapes
            .iter()
            .flat_map(|shape| shape.allocation_words().map(|words| words * 8))
            .collect();
        let plan =
            self.plan_resident_storage(&inputs, host_budget, bits, capture.then_some(1), &pending)?;
        plan.validate_quotient_batch_storage(inputs.len())?;
        Ok(plan)
    }

    pub(crate) fn commit_owned_quotient(
        &self,
        input: &device::QuotientCommitInput,
        host_budget: usize,
        capture: Option<&device::DeviceSession>,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        self.commit_owned_quotients(&[input], host_budget, capture)
    }

    pub(crate) fn commit_owned_quotients(
        &self,
        inputs: &[&device::QuotientCommitInput],
        host_budget: usize,
        capture: Option<&device::DeviceSession>,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        let bits = if super::resident_pcs::compact_prover_data() {
            super::profile::LOG_BLOWUP
        } else {
            0
        };
        if let Some(session) = capture {
            for input in inputs {
                input.check_session(session)?;
            }
        }
        let shapes: Vec<_> = inputs.iter().map(|input| input.shape).collect();
        let lde_shapes = self.quotient_batch_shapes(&shapes)?;
        let plan =
            self.plan_resident_storage(&lde_shapes, host_budget, bits, capture.map(|_| 1), &[])?;
        plan.validate_quotient_batch_storage(lde_shapes.len())?;
        let salts: Vec<_> = {
            let mut rng = self
                .rng
                .lock()
                .map_err(|_| "resident salt stream poisoned")?;
            (0..lde_shapes.len())
                .map(|_| RowMajorMatrix::rand(&mut *rng, plan.output_height(), 4))
                .collect()
        };
        let output = engine::lde_execute::commit_owned_quotients(
            inputs,
            &salts,
            self.cap_height,
            host_budget,
            self.lde_retention(bits),
            capture,
        )?;
        self.finish_lde_commit(output, salts, false)
    }

    pub(crate) fn commit_resident_retained(
        &self,
        inputs: Vec<(
            p3_field::coset::TwoAdicMultiplicativeCoset<Val>,
            RowMajorMatrix<Val>,
        )>,
        added_bits: usize,
        host_output_budget_bytes: usize,
        masks: Option<&[RowMajorMatrix<Val>]>,
        retention_bits: usize,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        self.commit_resident_retained_owned_with_preprocessing(
            inputs,
            added_bits,
            host_output_budget_bytes,
            masks,
            retention_bits,
            None,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_resident_retained_owned(
        &self,
        inputs: Vec<(p3_field::coset::TwoAdicMultiplicativeCoset<Val>, RowMajorMatrix<Val>)>,
        added_bits: usize,
        host_output_budget_bytes: usize,
        masks: Option<&[RowMajorMatrix<Val>]>,
        retention_bits: usize,
        capture: Option<(&device::DeviceSession, bool)>,
    ) -> Result<(<Self as Mmcs<Val>>::Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        self.commit_resident_retained_owned_with_preprocessing(inputs, added_bits,
            host_output_budget_bytes, masks, retention_bits, capture, false)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_resident_retained_owned_with_preprocessing(
        &self,
        inputs: Vec<(
            p3_field::coset::TwoAdicMultiplicativeCoset<Val>,
            RowMajorMatrix<Val>,
        )>,
        added_bits: usize,
        host_output_budget_bytes: usize,
        masks: Option<&[RowMajorMatrix<Val>]>,
        retention_bits: usize,
        capture: Option<(&device::DeviceSession, bool)>,
        public_preprocessing: bool,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        use p3_field::Field;
        let mut shapes = Vec::with_capacity(inputs.len());
        for (domain, matrix) in &inputs {
            if matrix.width == 0
                || matrix.values.len() % matrix.width != 0
                || matrix.values.len() / matrix.width != domain.size()
            {
                return Err("resident commitment domain/matrix mismatch".into());
            }
            shapes.push(LdeInputShape {
                height: domain.size(),
                width: matrix.width,
                added_bits,
            });
        }
        // The executor repeats this validation, but malformed masks must also
        // reject here before the commitment salt stream advances.
        if let Some(masks) = masks {
            if masks.len() != inputs.len()
                || added_bits != super::profile::LOG_BLOWUP + 1
                || masks.iter().zip(&inputs).any(|(mask, (_, matrix))| {
                    mask.width != matrix.width || mask.values.len() != matrix.values.len()
                })
            {
                return Err("quotient mask dimensions or hiding blowup mismatch".into());
            }
        }
        // First check precedes salt draws/allocations; the executor then replans
        // and reserves atomically under the same engine lock.
        let plan = self.plan_resident_storage(
            &shapes,
            host_output_budget_bytes,
            retention_bits,
            capture.map(|_| usize::from(masks.is_some())),
            &[],
        )?;
        if masks.is_some() {
            plan.validate_quotient_storage()?;
        }
        let replay_salts = retention_bits != 0 && compact_salts::enabled()?;
        let (salts, salt_checkpoints) = {
            let mut rng = self.rng.lock().map_err(|_| "resident salt stream poisoned")?;
            compact_salts::generate(&mut rng, plan.output_height(), inputs.len(), replay_salts)?
        };
        let requests: Vec<_> = inputs
            .iter()
            .zip(&salts)
            .map(|((domain, evaluations), salts)| LdeInput {
                evaluations,
                salts,
                added_bits,
                shift: Val::GENERATOR / domain.shift(),
            })
            .collect();
        let output = if public_preprocessing && capture.is_none() {
            engine::lde_execute::public_preprocessing_lde_commit(
                &requests, self.cap_height, host_output_budget_bytes, retention_bits,
            )?
        } else { engine::lde_execute::retained_lde_commit_storage(
            &requests,
            masks,
            self.cap_height,
            host_output_budget_bytes,
            self.lde_retention(retention_bits),
            capture.map(|(session, _)| session),
        )? };
        self.finish_lde_commit_with_salts(
            output,
            salts,
            capture.is_some_and(|(_, preprocessing)| preprocessing),
            salt_checkpoints,
        )
    }
}

impl Clone for CandidateMmcs {
    fn clone(&self) -> Self {
        Self {
            cpu: Arc::new((*self.cpu).clone()),
            rng: self
                .rng
                .snapshot()
                .expect("MMCS construction snapshot failed"),
            cap_height: self.cap_height,
            gpu: self.gpu,
            device_only: self.device_only,
            public_preprocessing: self.public_preprocessing,
        }
    }
}

pub enum ProverData<M> {
    Cpu(<ValMmcs as Mmcs<Val>>::ProverData<M>),
    Gpu {
        matrices: Vec<M>,
        salts: Vec<RowMajorMatrix<Val>>,
        layers: Vec<Vec<[Val; 4]>>,
    },
    Compact(compact_data::CompactData),
    /// No host LDE or prefix exists. Queries require an owning device session.
    DeviceOnly {
        owned: OwnedInputs,
        salts: SaltStore,
        tree: engine::RetainedTree,
    },
    GpuRetained {
        matrices: Vec<M>,
        salts: Vec<RowMajorMatrix<Val>>,
        tree: engine::RetainedTree,
        owned: Option<OwnedInputs>,
    },
}

impl<M> ProverData<M> {
    /// Retained device-only commitment metadata, including inline descriptors.
    /// Repeated references and shared allocation/stream Arcs are conservatively
    /// counted per occurrence. Other PCS representations retain their existing
    /// explicit host/hybrid admission path and return None here.
    pub(crate) fn opening_host_backing(&self) -> Result<Option<usize>, String> {
        let Self::DeviceOnly { owned, salts, tree } = self else { return Ok(None) };
        use cache_metadata::add;
        let mut bytes = core::mem::size_of::<Self>();
        bytes = add(bytes, owned.retained_host_backing()?)?;
        bytes = add(bytes, salts.retained_host_backing()?)?;
        bytes = add(bytes, tree.cached_host_backing()?)?;
        Ok(Some(bytes))
    }
}

impl Mmcs<Val> for CandidateMmcs {
    type ProverData<M> = ProverData<M>;
    type Commitment = <ValMmcs as Mmcs<Val>>::Commitment;
    type Proof = <ValMmcs as Mmcs<Val>>::Proof;
    type Error = <ValMmcs as Mmcs<Val>>::Error;

    fn commit<M: Matrix<Val>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        assert!(
            !self.device_only,
            "device-only PCS requires the explicit owned commitment interface"
        );
        if !self.gpu {
            let (cap, data) = self.cpu.commit(inputs);
            return (cap, ProverData::Cpu(data));
        }
        let _span = tracing::info_span!(target: "lattica_block_v2_perf", "bounded GPU commitment")
            .entered();
        let height = inputs.first().expect("GPU MMCS: empty batch").height();
        assert!(
            height.is_power_of_two() && inputs.iter().all(|m| m.height() == height),
            "GPU MMCS: requires equal power-of-two heights; no implicit backend fallback"
        );
        let width = inputs
            .iter()
            .try_fold(0usize, |n, m| n.checked_add(m.width())?.checked_add(4))
            .expect("GPU MMCS: row width overflow");
        // Resource preflight happens BEFORE salts or device work are allocated.
        engine::preflight(height, width).expect("GPU MMCS: resource admission failed");
        let retain = engine::retention_enabled().expect("GPU MMCS: retention mode unavailable");
        let salts: Vec<RowMajorMatrix<Val>> = {
            let mut rng = self.rng.lock().unwrap();
            inputs
                .iter()
                .map(|m| RowMajorMatrix::rand(&mut *rng, m.height(), 4))
                .collect()
        };
        let fill = |row, output: &mut [u64]| {
            let mut offset = 0;
            for (matrix, salt) in inputs.iter().zip(&salts) {
                for value in matrix.row(row).expect("admitted row") {
                    output[offset] = value.as_canonical_u64();
                    offset += 1;
                }
                for value in &salt.values[row * 4..row * 4 + 4] {
                    output[offset] = value.as_canonical_u64();
                    offset += 1;
                }
            }
            assert_eq!(offset, output.len());
        };
        if retain {
            let tree = engine::hash_rows_retained(height, width, self.cap_height, fill)
                .expect("GPU MMCS: retained hashing failed; refusing to emit a commitment");
            let cap = Self::Commitment::new(tree.cap().to_vec());
            return (
                cap,
                ProverData::GpuRetained {
                    matrices: inputs,
                    salts,
                    tree,
                    owned: None,
                },
            );
        }
        let layers = engine::hash_rows(height, width, fill)
            .expect("GPU MMCS: hashing failed; refusing to emit a commitment");
        let depth = layers.len() - 1;
        let cap = Self::Commitment::new(layers[depth - self.cap_height.min(depth)].clone());
        (
            cap,
            ProverData::Gpu {
                matrices: inputs,
                salts,
                layers,
            },
        )
    }

    fn open_batch<M: Matrix<Val>>(
        &self,
        index: usize,
        data: &Self::ProverData<M>,
    ) -> BatchOpening<Val, Self> {
        match data {
            ProverData::DeviceOnly { .. } => {
                panic!("device-only PCS queries require the owned query interface")
            }
            ProverData::Compact(data) => data.open(index, self.cap_height),
            ProverData::Cpu(data) => {
                let (values, proof) = self.cpu.open_batch(index, data).unpack();
                BatchOpening::new(values, proof)
            }
            ProverData::GpuRetained {
                matrices,
                salts,
                tree,
                ..
            } => {
                assert!(
                    index < matrices[0].height(),
                    "GPU MMCS: opening index out of range"
                );
                let values = matrices
                    .iter()
                    .map(|m| m.row(index).unwrap().into_iter().collect())
                    .collect();
                let salts = salts
                    .iter()
                    .map(|s| s.values[index * 4..index * 4 + 4].to_vec())
                    .collect();
                let siblings = tree
                    .open(index, self.cap_height)
                    .expect("GPU MMCS: retained query failed; refusing to emit an opening");
                BatchOpening::new(values, (salts, siblings))
            }
            ProverData::Gpu {
                matrices,
                salts,
                layers,
            } => {
                assert!(
                    index < matrices[0].height(),
                    "GPU MMCS: opening index out of range"
                );
                let values = matrices
                    .iter()
                    .map(|m| m.row(index).unwrap().into_iter().collect())
                    .collect();
                let salts = salts
                    .iter()
                    .map(|s| s.values[index * 4..index * 4 + 4].to_vec())
                    .collect();
                let path_len = layers.len() - 1 - self.cap_height.min(layers.len() - 1);
                let mut at = index;
                let siblings = layers[..path_len]
                    .iter()
                    .map(|layer| {
                        let sibling = layer[at ^ 1];
                        at >>= 1;
                        sibling
                    })
                    .collect();
                BatchOpening::new(values, (salts, siblings))
            }
        }
    }

    fn get_matrices<'a, M: Matrix<Val>>(&self, data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        match data {
            ProverData::Cpu(d) => self.cpu.get_matrices(d),
            ProverData::Compact(_) => {
                panic!("compact data requires explicit prefix/logical geometry access")
            }
            ProverData::DeviceOnly { .. } => panic!("device-only PCS has no host matrices"),
            ProverData::Gpu { matrices, .. } | ProverData::GpuRetained { matrices, .. } => {
                matrices.iter().collect()
            }
        }
    }

    fn get_matrix_heights<M: Matrix<Val>>(&self, data: &Self::ProverData<M>) -> Vec<usize> {
        match data {
            ProverData::DeviceOnly { .. } => data
                .owned_dimensions()
                .expect("device-only dimensions")
                .iter()
                .map(|d| d.height)
                .collect(),
            ProverData::Compact(data) => vec![data.height; data.prefixes.len()],
            _ => self.get_matrices(data).iter().map(|m| m.height()).collect(),
        }
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, Val, Self>,
    ) -> Result<(), Self::Error> {
        let (values, proof) = opening.unpack();
        // Always retain the upstream width, batch-size, index, salt and path checks.
        self.cpu.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::new(values, proof),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::bitrev::BitReversibleMatrix;
    use rand::SeedableRng;

    fn mmcs(cap: usize, gpu: bool) -> CandidateMmcs {
        let p = default_goldilocks_poseidon2_8();
        let mut m = CandidateMmcs::new(
            MyHash::new(p.clone()),
            MyCompress::new(p),
            cap,
            ChaCha20Rng::from_seed([37; 32]),
        );
        m.gpu = gpu;
        m
    }
    fn matrix(h: usize, w: usize, salt: u64) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(
            (0..h * w)
                .map(|i| {
                    Val::from_u64(match i % 5 {
                        0 => 0,
                        1 => 1,
                        2 => 0xffff_ffff_0000_0000,
                        3 => u64::MAX,
                        _ => (i as u64)
                            .wrapping_mul(0x9e3779b97f4a7c15)
                            .wrapping_add(salt),
                    })
                })
                .collect(),
            w,
        )
    }
    fn initialize_test_gpu_mode(mode: engine::TransferMode) {
        engine::initialize_mode(
            Limits {
                managed_bytes: 256 << 20,
                tile_bytes: 1 << 20,
                staging_bytes: 64 << 10,
            },
            mode,
        )
        .unwrap();
    }

    #[test]
    fn verification_is_cpu_only_and_keeps_strict_dimensions() {
        let mut candidate = mmcs(1, false);
        let input = matrix(8, 3, 5);
        let dims = [input.dimensions()];
        let (cap, data) = candidate.commit(vec![input]);
        let opening = candidate.open_batch(3, &data);
        candidate.gpu = true; // Verification must not require an initialized device.
        candidate
            .verify_batch(&cap, &dims, 3, (&opening).into())
            .unwrap();
        let mut wrong = opening.clone();
        wrong.opened_values[0].push(wrong.opening_proof.0[0].remove(0));
        assert!(candidate
            .verify_batch(&cap, &dims, 3, (&wrong).into())
            .is_err());
        let bad_dims = [Dimensions {
            height: 8,
            width: 4,
        }];
        assert!(candidate
            .verify_batch(&cap, &bad_dims, 3, (&opening).into())
            .is_err());
        assert!(candidate
            .verify_batch(&cap, &dims, 8, (&opening).into())
            .is_err());
        assert!(candidate
            .verify_batch(&cap, &[], 3, (&opening).into())
            .is_err());
    }

    fn compare<M: Matrix<Val>>(make_inputs: impl Fn() -> Vec<M>, cap_height: usize) {
        let inputs = make_inputs();
        let cpu = mmcs(cap_height, false);
        let gpu = mmcs(cap_height, true);
        let dims: Vec<_> = inputs.iter().map(Matrix::dimensions).collect();
        let h = inputs[0].height();
        // Repeated commits also check the RNG draw schedule, not just its first use.
        for _ in 0..2 {
            let (cpu_cap, cpu_data) = cpu.commit(make_inputs());
            let (gpu_cap, gpu_data) = gpu.commit(make_inputs());
            assert_eq!(cpu_cap, gpu_cap);
            for index in [0, h / 2, h - 1] {
                let a = cpu.open_batch(index, &cpu_data);
                let b = gpu.open_batch(index, &gpu_data);
                assert_eq!(a.opened_values, b.opened_values);
                assert_eq!(a.opening_proof, b.opening_proof);
                // Direct upstream verifier, without the candidate verifier adapter.
                gpu.cpu
                    .verify_batch(
                        &gpu_cap,
                        &dims,
                        index,
                        BatchOpeningRef::new(&b.opened_values, &b.opening_proof),
                    )
                    .unwrap();
                let mut wrong = b.clone();
                wrong.opened_values[0][0] += Val::ONE;
                assert!(gpu
                    .verify_batch(&gpu_cap, &dims, index, (&wrong).into())
                    .is_err());
                let mut wrong = b.clone();
                wrong.opening_proof.0[0][0] += Val::ONE;
                assert!(gpu
                    .verify_batch(&gpu_cap, &dims, index, (&wrong).into())
                    .is_err());
                let mut wrong = b;
                if let Some(sibling) = wrong.opening_proof.1.first_mut() {
                    sibling[0] += Val::ONE;
                    assert!(gpu
                        .verify_batch(&gpu_cap, &dims, index, (&wrong).into())
                        .is_err());
                }
            }
        }
    }

    #[test]
    #[ignore = "requires an OpenCL GPU; run serially in a <=3 GiB service"]
    fn gpu_commitments_openings_salts_order_caps_and_tiles_match_cpu() {
        let _shutdown = engine::TestShutdownGuard;
        for mode in engine::test_transfer_modes() {
            initialize_test_gpu_mode(mode);
            for h in [1, 2, 8, 64, 4096] {
                for widths in [vec![1], vec![7, 3, 5], vec![98], vec![7; 16]] {
                    let inputs: Vec<_> = widths
                        .iter()
                        .enumerate()
                        .map(|(i, &w)| matrix(h, w, i as u64))
                        .collect();
                    for cap in [0, 6, 10] {
                        compare(|| inputs.clone(), cap);
                    }
                }
            }
            compare(|| vec![matrix(4096, 98, 17).bit_reverse_rows()], 6);
            let gpu = mmcs(6, true);
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                gpu.commit(vec![matrix(8, 1, 0), matrix(4, 1, 0)])
            }))
            .is_err());
            let stats = report("GPU compatibility test").unwrap();
            assert!(stats.commits == 122);
            assert!(stats.managed_peak_bytes <= 256 << 20);
            assert!(stats.uploaded_bytes > 0 && stats.downloaded_bytes > 0);
            shutdown().unwrap();
        }
    }

    #[test]
    #[ignore = "requires OpenCL GPU and LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB"]
    fn gpu_retained_trees_keep_context_alive_and_survive_workspace_reuse() {
        let _shutdown = engine::TestShutdownGuard;
        initialize_test_gpu_mode(engine::test_transfer_mode());
        assert!(engine::retention_enabled().unwrap());
        let gpu = mmcs(6, true);
        let cpu = mmcs(6, false);
        let inputs = vec![matrix(4096, 33, 19)];
        let dims = inputs.iter().map(|m| m.dimensions()).collect::<Vec<_>>();
        let (cap, data) = gpu.commit(inputs.clone());
        let (expected_cap, expected_data) = cpu.commit(inputs);
        assert_eq!(cap, expected_cap);
        let mut others = Vec::new();
        for height in [2, 8192, 128, 16384] {
            let (_, other) = gpu.commit(vec![matrix(height, 98, height as u64)]);
            others.push(other);
        }
        assert!(shutdown().is_err()); // Must retain the context and process lease.
        for index in [0, 63, 64, 2048, 4095] {
            let actual = gpu.open_batch(index, &data);
            let expected = cpu.open_batch(index, &expected_data);
            assert_eq!(actual.opened_values, expected.opened_values);
            assert_eq!(actual.opening_proof, expected.opening_proof);
            cpu.verify_batch(&cap, &dims, index, (&actual).into())
                .unwrap();
        }
        let before = report("retained admission before")
            .unwrap()
            .managed_live_bytes;
        assert!(engine::preflight(1 << 24, 33).is_err());
        assert_eq!(
            report("retained admission after")
                .unwrap()
                .managed_live_bytes,
            before
        );
        drop(others);
        assert!(shutdown().is_err());
        drop(data);
        shutdown().unwrap();
        initialize_test_gpu_mode(engine::test_transfer_mode());
        compare(|| vec![matrix(4096, 7, 25)], 6);
        shutdown().unwrap();
    }

    #[test]
    #[ignore = "requires an OpenCL GPU; run serially in a <=3 GiB service"]
    fn gpu_process_death_releases_job_lease() {
        let _shutdown = engine::TestShutdownGuard;
        use std::io::{BufRead, Write};
        use std::process::{Child, Command, Stdio};
        const CHILD: &str = "LATTICA_GPU_LEASE_DEATH_TEST_CHILD";
        if std::env::var(CHILD).as_deref() == Ok("1") {
            initialize_test_gpu_mode(engine::test_transfer_mode());
            // With retention enabled, keep a real device-tree handle alive
            // across process death. This does not simulate every in-flight
            // driver instruction or claim physical GPU-memory isolation.
            let _held = mmcs(6, true).commit(vec![matrix(4096, 33, 41)]);
            println!("gpu_worker_lease_ready");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        struct Worker(Child);
        impl Drop for Worker {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        shutdown().unwrap();
        let mut worker = Worker(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "block_v2::gpu_hash::tests::gpu_process_death_releases_job_lease",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = worker.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if line.unwrap_or_default().contains("gpu_worker_lease_ready") {
                    let _ = tx.send(());
                    return;
                }
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
        // Kill only the child this test created, not any discovered GPU process.
        worker.0.kill().unwrap();
        assert!(!worker.0.wait().unwrap().success());
        reader.join().unwrap();
        initialize_test_gpu_mode(engine::test_transfer_mode());
        compare(|| vec![matrix(4096, 33, 29)], 6);
        shutdown().unwrap();
    }

    #[test]
    #[ignore = "requires an OpenCL GPU; run serially in a <=3 GiB service"]
    #[cfg(feature = "stream")]
    fn gpu_spill_backed_bit_reversed_inputs_match_resident_cpu_openings() {
        let _shutdown = engine::TestShutdownGuard;
        use crate::spill_alloc::{spill_stats, SpillScope};
        // Just above the allocator's 64 MiB threshold, including a tiled remainder.
        let resident = matrix(131_072, 65, 23);
        let cpu = mmcs(6, false);
        let (expected, cpu_data) = cpu.commit(vec![resident.bit_reverse_rows()]);
        let before = spill_stats();
        for mode in engine::test_transfer_modes() {
            initialize_test_gpu_mode(mode);
            let scope = SpillScope::arm();
            let input = matrix(131_072, 65, 23);
            assert!(spill_stats().1 >= before.1 + (131_072 * 65 * 8) as u64);
            drop(scope);
            let gpu = mmcs(6, true);
            let dims = [input.dimensions()];
            let (cap, data) = gpu.commit(vec![input.bit_reverse_rows()]);
            assert_eq!(cap, expected);
            for index in [0, 65_535, 131_071] {
                let a = cpu.open_batch(index, &cpu_data);
                let b = gpu.open_batch(index, &data);
                assert_eq!(a.opened_values, b.opened_values);
                assert_eq!(a.opening_proof, b.opening_proof);
                gpu.cpu
                    .verify_batch(
                        &cap,
                        &dims,
                        index,
                        BatchOpeningRef::new(&b.opened_values, &b.opening_proof),
                    )
                    .unwrap();
            }
            drop(data);
            assert_eq!(spill_stats(), before);
            let stats = report("spill-backed compatibility test").unwrap();
            assert_eq!(stats.upload_device_ns > 0, engine::test_device_transfers());
            assert_eq!(
                stats.download_device_ns > 0,
                engine::test_device_transfers()
            );
            assert!(stats.upload_wall_ns > 0 && stats.download_wall_ns > 0);
            shutdown().unwrap();
        }
    }

    #[test]
    #[ignore = "requires an OpenCL GPU; run serially in a <=3 GiB service"]
    fn gpu_cubic_wallet_proof_cross_verifies_with_unmodified_cpu_types() {
        let _shutdown = engine::TestShutdownGuard;
        use crate::block_v2::{commitment::Context, leaf::ContextJoinSplitAir, profile, recursive};
        use crate::config::{Challenger, Dft};
        use p3_commit::ExtensionMmcs;
        use p3_fri::HidingFriPcs;
        use p3_uni_stark::{Proof, StarkConfig};
        type CpuChallengeMmcs = ExtensionMmcs<Val, profile::Challenge, ValMmcs>;
        type CpuPcs = HidingFriPcs<Val, Dft, ValMmcs, CpuChallengeMmcs, ChaCha20Rng>;
        type CpuConfig = StarkConfig<CpuPcs, profile::Challenge, Challenger>;
        for mode in engine::test_transfer_modes() {
            initialize_test_gpu_mode(mode);
            ENABLED.store(true, Ordering::Release);
            let wallet = recursive::demo_wallet(0).unwrap();
            let p = default_goldilocks_poseidon2_8();
            let mmcs = ValMmcs::new(
                MyHash::new(p.clone()),
                MyCompress::new(p.clone()),
                profile::CAP_HEIGHT,
                ChaCha20Rng::from_seed([3; 32]),
            );
            let pcs = CpuPcs::new(
                Dft::default(),
                mmcs.clone(),
                profile::fri(CpuChallengeMmcs::new(mmcs)),
                profile::NUM_RANDOM_CODEWORDS,
                ChaCha20Rng::from_seed([4; 32]),
            );
            let cpu = CpuConfig::new(pcs, Challenger::new(p));
            let proof: Proof<CpuConfig> =
                postcard::from_bytes(&postcard::to_allocvec(&wallet.proof).unwrap()).unwrap();
            let mut public = wallet.public.clone();
            public.extend(
                Context {
                    profile_id: profile::CANDIDATE_PROFILE_ID,
                    chain_id: wallet.chain,
                }
                .to_fields()
                .map(Val::from_u64),
            );
            p3_uni_stark::verify(&cpu, &ContextJoinSplitAir, &proof, &public).unwrap();
            public[0] += Val::ONE;
            assert!(p3_uni_stark::verify(&cpu, &ContextJoinSplitAir, &proof, &public).is_err());
            report("GPU cubic wallet test");
            shutdown().unwrap();
            assert!(report("after GPU shutdown").is_none());
            // A fresh context must be able to reacquire the process lease after all
            // previous managed buffers have been released.
            initialize_test_gpu_mode(mode);
            shutdown().unwrap();
        }
    }
}
