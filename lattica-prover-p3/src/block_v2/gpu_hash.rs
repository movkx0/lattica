//! Candidate-only GPU commitments; verification always uses the upstream CPU MMCS.
//! No parameter, salt distribution, serialized proof, or production ABI change.
//! Only equal-height, power-of-two batches are admitted by the selected GPU path.
mod compact_data;
pub(crate) mod engine;
mod prefix_storage;
pub(crate) use engine::opening_reduce::{
    reduce_lde as reduce_openings, OpeningMatrix, OpeningTerm,
};
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
    drain,
    lde_execute::{coset_lde_commit, LdeCommitOutput, LdeInput},
    lde_plan::{ColumnTile as LdeColumnTile, InputShape as LdeInputShape, LdeCommitPlan},
    plan_coset_lde_commit, report, shutdown, Limits, Snapshot,
};
static ENABLED: AtomicBool = AtomicBool::new(false);

pub(super) fn require_resident_backend() -> Result<(), String> {
    if !ENABLED.load(Ordering::Acquire) || !engine::retention_enabled()? {
        return Err("resident PCS requires LATTICA_V2_GPU_HASH=1 and retained trees".into());
    }
    Ok(())
}

/// Called only by the research runner, before proving. Merely compiling `gpu`
/// never selects this path, and verification never initializes a GPU context.
pub fn initialize_from_env() -> Result<(), String> {
    match std::env::var("LATTICA_V2_GPU_HASH") {
        Err(std::env::VarError::NotPresent) => Ok(()),
        Ok(v) if v == "0" => Ok(()),
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
            engine::initialize(limits)?;
            ENABLED.store(true, Ordering::Release);
            Ok(())
        }
        _ => Err("LATTICA_V2_GPU_HASH must be 0 or 1".into()),
    }
}

pub struct CandidateMmcs {
    cpu: Arc<ValMmcs>,
    rng: Arc<Mutex<ChaCha20Rng>>,
    cap_height: usize,
    gpu: bool,
}

impl CandidateMmcs {
    pub fn new(hash: MyHash, compress: MyCompress, cap_height: usize, rng: ChaCha20Rng) -> Self {
        Self {
            cpu: Arc::new(ValMmcs::new(hash, compress, cap_height, rng.clone())),
            rng: Arc::new(Mutex::new(rng)),
            cap_height,
            gpu: ENABLED.load(Ordering::Acquire),
        }
    }
}

// Explicitly share only the input-MMCS state used by one resident PCS attempt.
// Ordinary Clone above/below retains the prior independent-clone semantics.
impl CandidateMmcs {
    pub(crate) fn share_for_resident(&self) -> Result<Self, String> {
        if !self.gpu || !engine::retention_enabled()? {
            return Err("resident PCS requires initialized GPU hashing and retained trees".into());
        }
        if self.cap_height != super::profile::CAP_HEIGHT {
            return Err("resident PCS requires the registered candidate cap height".into());
        }
        Ok(Self {
            cpu: Arc::clone(&self.cpu),
            rng: Arc::clone(&self.rng),
            cap_height: self.cap_height,
            gpu: self.gpu,
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
        // First check precedes salt draws/allocations; the executor then replans
        // and reserves atomically under the same engine lock.
        let plan = engine::plan_retained_lde_commit(
            &shapes,
            self.cap_height,
            host_output_budget_bytes,
            retention_bits,
        )?;
        if masks.is_some() {
            plan.validate_quotient_storage()?;
        }
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
        let output = engine::lde_execute::retained_lde_commit(
            &requests,
            masks,
            self.cap_height,
            host_output_budget_bytes,
            retention_bits,
        )?;
        let cap = <Self as Mmcs<Val>>::Commitment::new(output.cap().to_vec());
        let data = if retention_bits == 0 {
            ProverData::GpuRetained {
                matrices: output.matrices,
                salts,
                tree: output.tree,
            }
        } else {
            ProverData::Compact(compact_data::CompactData::new(
                output.prefixes,
                plan.output_height(),
                salts,
                output.tree,
            ))
        };
        Ok((cap, data))
    }
}

impl Clone for CandidateMmcs {
    fn clone(&self) -> Self {
        Self {
            cpu: Arc::new((*self.cpu).clone()),
            rng: Arc::new(Mutex::new(self.rng.lock().unwrap().clone())),
            cap_height: self.cap_height,
            gpu: self.gpu,
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
    GpuRetained {
        matrices: Vec<M>,
        salts: Vec<RowMajorMatrix<Val>>,
        tree: engine::RetainedTree,
    },
}

impl Mmcs<Val> for CandidateMmcs {
    type ProverData<M> = ProverData<M>;
    type Commitment = <ValMmcs as Mmcs<Val>>::Commitment;
    type Proof = <ValMmcs as Mmcs<Val>>::Proof;
    type Error = <ValMmcs as Mmcs<Val>>::Error;

    fn commit<M: Matrix<Val>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
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
            ProverData::Compact(data) => data.open(index, self.cap_height),
            ProverData::Cpu(data) => {
                let (values, proof) = self.cpu.open_batch(index, data).unpack();
                BatchOpening::new(values, proof)
            }
            ProverData::GpuRetained {
                matrices,
                salts,
                tree,
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
            ProverData::Gpu { matrices, .. } | ProverData::GpuRetained { matrices, .. } => {
                matrices.iter().collect()
            }
        }
    }

    fn get_matrix_heights<M: Matrix<Val>>(&self, data: &Self::ProverData<M>) -> Vec<usize> {
        match data {
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
