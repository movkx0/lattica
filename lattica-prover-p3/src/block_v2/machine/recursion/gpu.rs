//! Reusable GPU preprocessing and fresh GPU proof attempts. Witness generation
//! is currently an explicit CPU stage; the GPU-required receipt covers only
//! proving from uploaded traces. It never claims a GPU-only whole workflow.
use super::*;
use crate::block_v2::{gpu_hash, gpu_quotient_prover, profile, quotient_pcs};
use crate::proving::{CoverageScope, Policy, Request, Run, Stage};
use gpu_hash::device::{
    DeviceSession, DomainSpec, Extension, MatrixSpec, PreprocessingTrace, RowOrder,
};
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta, ProverOnlyData};
use p3_batch_stark::{verify_batch, CommonData, ProverData};
use p3_field::PrimeField64;
use p3_lookup::{LogUpGadget, Lookups};
use p3_uni_stark::StarkGenericConfig;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuTemplateLimits {
    /// Includes retained program, host witness materialization, staging and PCS.
    pub host_bytes: usize,
    /// Assigned PCS host workspace, including retained public/private trees.
    pub pcs_host_bytes: usize,
    pub max_rows: usize,
}

#[derive(serde::Serialize)]
pub struct GpuProofMeasurement {
    pub geometry: ArchitectureGeometry,
    pub public_prefix_host_bytes: usize,
    pub public_salt_host_bytes: usize,
    pub host_witness_seconds: f64,
    pub upload_seconds: f64,
    pub gpu_prove_seconds: f64,
    pub cpu_verify_seconds: f64,
    pub proof_json_bytes: usize,
    pub query_opened_fields: usize,
    pub preprocessing_reused: bool,
    pub gpu_backend_only: bool,
    pub verified: bool,
    pub backend_report: crate::proving::Report,
}

pub struct PreparedGpuRecursionTemplate {
    template: RecursionTemplate,
    state: GpuRecursionState,
}
// The proving state owns no SSA program or instruction-index tables. Consuming
// callers can retire those allocations before the GPU starts its private work.
struct GpuRecursionState {
    geometry: ArchitectureGeometry,
    airs: Vec<air::VerifierAir>,
    data: ProverData<profile::Config>,
    limits: GpuTemplateLimits,
    public_prefix_host_bytes: usize,
    public_salt_host_bytes: usize,
}

#[derive(Default, Clone, Copy, Debug, serde::Serialize)]
pub struct GpuRecursionCacheStats {
    pub hits: usize,
    pub misses: usize,
}
/// One public preprocessing entry in the already-reserved backend partition.
/// A miss retires the old entry before allocating its replacement. Neither
/// compiler programs, witnesses nor private randomness enter this cache.
#[derive(Default)]
pub struct GpuRecursionCache {
    entry: Option<([u8; 32], GpuRecursionState)>,
    stats: GpuRecursionCacheStats,
}
pub struct CachedGpuRecursionTemplate<'a> {
    template: RecursionTemplate,
    state: &'a GpuRecursionState,
    reused: bool,
}
impl GpuRecursionCache {
    pub fn stats(&self) -> GpuRecursionCacheStats {
        self.stats
    }
    pub fn clear(&mut self) {
        self.entry = None;
    }
    pub fn prepare(
        &mut self,
        template: RecursionTemplate,
        limits: GpuTemplateLimits,
    ) -> Result<CachedGpuRecursionTemplate<'_>, String> {
        limits.admit(&template)?;
        let reused = self
            .entry
            .as_ref()
            .is_some_and(|(id, state)| *id == template.identity() && state.limits == limits);
        if reused {
            self.stats.hits += 1;
        } else {
            self.clear();
            let PreparedGpuRecursionTemplate {
                template: source,
                state,
            } = template.prepare_gpu(limits)?;
            drop(source);
            self.entry = Some((template.identity(), state));
            self.stats.misses += 1;
        }
        Ok(CachedGpuRecursionTemplate {
            template,
            state: &self.entry.as_ref().unwrap().1,
            reused,
        })
    }
}
impl CachedGpuRecursionTemplate<'_> {
    pub fn verifier(&self) -> RecursionVerifier {
        RecursionVerifier::new(
            self.template.clone(),
            self.state
                .data
                .common
                .preprocessed
                .as_ref()
                .unwrap()
                .commitment
                .clone(),
        )
    }
    pub fn into_prove(
        self,
        public: &[Val],
        witness: &[Val],
        source_released: impl FnOnce(),
    ) -> Result<(RecursionExecutionProof, GpuProofMeasurement), String> {
        let _phase = crate::block_v2::worker_memory::PhaseGuard::acquire("cached recursion proof")?;
        let started = Instant::now();
        let traces = self
            .template
            .traces(public, witness)
            .map_err(|e| format!("cached recursion witness: {e:?}"))?;
        let seconds = started.elapsed().as_secs_f64();
        let Self {
            template,
            state,
            reused,
        } = self;
        drop(template);
        source_released();
        let (proof, mut measurement) = state.prove_traces(public, traces, seconds)?;
        measurement.preprocessing_reused = reused;
        Ok((proof, measurement))
    }
}

// Keep small setups resident. Large immutable prefixes and fixed public salts
// are charged to host storage and uploaded only when their phase borrows them.
fn public_prefix_allowance(geometry: &ArchitectureGeometry) -> Result<usize, String> {
    let bytes = geometry
        .tables
        .iter()
        .try_fold(0usize, |sum, table| {
            table
                .height
                .checked_mul(table.preprocessed_width)?
                .checked_mul(16)?
                .checked_add(sum)
        })
        .ok_or("public prefix host overflow")?;
    if bytes > 512 << 20 {
        let salts = geometry
            .tables
            .iter()
            .try_fold(0usize, |sum, table| {
                table
                    .height
                    .checked_mul(2 << profile::LOG_BLOWUP)?
                    .checked_mul(32)?
                    .checked_add(sum)
            })
            .ok_or("public salt host overflow")?;
        bytes
            .checked_add(salts)
            .ok_or("public preprocessing host overflow")?
            .checked_add(64 << 10)
            .ok_or("public prefix host overflow".into())
    } else {
        Ok(0)
    }
}

impl GpuTemplateLimits {
    fn admit(&self, template: &RecursionTemplate) -> Result<(), String> {
        if self.pcs_host_bytes == 0
            || self.host_bytes > 24usize << 30
            || self.pcs_host_bytes >= self.host_bytes
            || self.max_rows > 1 << 20
        {
            return Err("recursion GPU host/row allowance".into());
        }
        let geometry = template.geometry()?;
        if !geometry.degree_gate
            || !geometry.quotient_gate
            || geometry.tables.len() > 8
            || geometry.tables.iter().any(|t| t.height > self.max_rows)
        {
            return Err(format!(
                "recursion GPU geometry exceeds admitted prototype: tables={} (limit 8), degree_gate={}, quotient_gate={}, max_height={} (limit {})",
                geometry.tables.len(), geometry.degree_gate, geometry.quotient_gate,
                geometry.tables.iter().map(|t| t.height).max().unwrap_or(0), self.max_rows,
            ));
        }
        let mut trace_bytes = 0usize;
        let mut staging = 0usize;
        for t in &geometry.tables {
            let main = t
                .height
                .checked_mul(t.main_width)
                .and_then(|n| n.checked_mul(8))
                .ok_or("trace overflow")?;
            let pre = t
                .height
                .checked_mul(t.preprocessed_width)
                .and_then(|n| n.checked_mul(16))
                .ok_or("preprocessing overflow")?;
            trace_bytes = trace_bytes.checked_add(main).ok_or("trace sum overflow")?;
            staging = staging.max(main).max(pre);
        }
        // Includes the shared immutable source, all CPU traces, wire values,
        // input values, one conversion buffer and bounded symbolic scratch.
        let indices = template
            .rows
            .iter()
            .try_fold(0usize, |total, rows| {
                total.checked_add(rows.len().checked_mul(core::mem::size_of::<u32>())?)
            })
            .ok_or("recursion index storage overflow")?;
        let source = template
            .program
            .construction_host_bytes()
            .checked_add(
                indices
                    .checked_add(template.typed.backing_bytes())
                    .and_then(|bytes| {
                        bytes.checked_add(
                            template
                                .tables
                                .len()
                                .checked_mul(core::mem::size_of::<super::layout::TableSpan>())?,
                        )
                    })
                    .ok_or("typed backing overflow")?,
            )
            .ok_or("recursion source storage overflow")?;
        let values = template
            .program
            .wire_count()
            .checked_add(template.program.witness_values())
            .and_then(|n| n.checked_add(template.program.public_values()))
            .and_then(|n| n.checked_mul(8))
            .ok_or("witness overflow")?;
        let required = [
            source,
            values,
            trace_bytes,
            staging,
            1 << 30,
            self.pcs_host_bytes,
            public_prefix_allowance(&geometry)?,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or("host sum overflow")?;
        if required > self.host_bytes {
            return Err(format!(
                "recursion GPU host allowance: required={required} limit={}",
                self.host_bytes
            ));
        }
        Ok(())
    }
}

impl RecursionTemplate {
    pub fn prepare_gpu(
        &self,
        limits: GpuTemplateLimits,
    ) -> Result<PreparedGpuRecursionTemplate, String> {
        limits.admit(self)?;
        if !gpu_hash::is_enabled()
            || !quotient_pcs::gpu_quotient_resident_enabled()
            || !quotient_pcs::gpu_lookup_enabled()
            || !quotient_pcs::gpu_randomness_enabled()
        {
            return Err("recursion GPU backend must be explicitly initialized".into());
        }
        let _phase =
            crate::block_v2::worker_memory::PhaseGuard::acquire("recursion preprocessing")?;
        let config = profile::preprocessing_config_with_host_budget(limits.pcs_host_bytes)
            .map_err(|e| format!("recursion setup config: {e:?}"))?;
        let session = config.pcs().quotient_session()?;
        let airs = self.airs();
        let mut lookups = Vec::new();
        let mut instances = Vec::new();
        let mut matrices = Vec::new();
        let gadget = LogUpGadget::new();
        for (index, air) in airs.iter().enumerate() {
            let unpacked = Lookups::<Val>::from_air::<profile::Challenge, _>(air);
            let chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
                Val,
                profile::Challenge,
                _,
                _,
            >(air, AirLayout::from_air(air), &unpacked, 1, &gadget);
            lookups.push(unpacked.pack_same_bus(&gadget, 1 << chunks));
            let degree = air.height.ilog2() as usize + 1;
            instances.push(Some(PreprocessedInstanceMeta {
                matrix_index: index,
                width: air.preprocessed_width(),
                degree_bits: degree,
            }));
            let matrix = PreprocessingTrace::from_recursion_template(
                &session,
                self,
                index,
                limits.host_bytes - limits.pcs_host_bytes,
            )?;
            matrices.push((DomainSpec::new(1, degree)?, matrix));
        }
        let (commitment, mut data) = config.pcs().commit_preprocessing_device(matrices)?;
        let geometry = self.geometry()?;
        let allowance = public_prefix_allowance(&geometry)?;
        let public_prefix_host_bytes = if allowance > 0 {
            data.park_public_prefixes(&session, allowance)?
        } else {
            0
        };
        let public_salt_host_bytes = if allowance > 0 {
            data.park_public_salts(&session, allowance - public_prefix_host_bytes)?
        } else {
            0
        };
        session.aggregation_memory_checkpoint("recursion reusable preprocessing")?;
        let data = ProverData {
            common: CommonData {
                preprocessed: Some(GlobalPreprocessed {
                    commitment,
                    instances,
                    matrix_to_instance: (0..airs.len()).collect(),
                }),
                lookups,
            },
            prover_only: ProverOnlyData {
                preprocessed_prover_data: Some(data),
            },
        };
        Ok(PreparedGpuRecursionTemplate {
            template: self.clone(),
            state: GpuRecursionState {
                geometry,
                airs: airs.iter().map(air::TableAir::verifier_air).collect(),
                data,
                limits,
                public_prefix_host_bytes,
                public_salt_host_bytes,
            },
        })
    }
}

impl PreparedGpuRecursionTemplate {
    #[cfg(test)]
    pub(super) fn park_preprocessing_for_test(
        &mut self,
        allowance: usize,
    ) -> Result<usize, String> {
        let config =
            profile::preprocessing_config_with_host_budget(self.state.limits.pcs_host_bytes)
                .map_err(|e| format!("test preprocessing config: {e:?}"))?;
        let session = config.pcs().quotient_session()?;
        let data = self
            .state
            .data
            .prover_only
            .preprocessed_prover_data
            .as_mut()
            .ok_or("missing preprocessing data")?;
        self.state.public_prefix_host_bytes = data.park_public_prefixes(&session, allowance)?;
        self.state.public_salt_host_bytes =
            data.park_public_salts(&session, allowance - self.state.public_prefix_host_bytes)?;
        self.state
            .public_prefix_host_bytes
            .checked_add(self.state.public_salt_host_bytes)
            .ok_or_else(|| "public preprocessing host size overflow".into())
    }
    pub fn verifier(&self) -> RecursionVerifier {
        RecursionVerifier::new(self.template.clone(), self.preprocessing_cap().clone())
    }

    pub fn compile_verifier(
        &self,
        proof: &RecursionExecutionProof,
        limits: super::super::program::ConstructionLimits,
    ) -> Result<CompiledRecursionVerifier, String> {
        parent::compile(&self.template, self.preprocessing_cap(), proof, limits)
    }
    pub fn preprocessing_cap(&self) -> &p3_batch_stark::Commitment<profile::Config> {
        &self
            .state
            .data
            .common
            .preprocessed
            .as_ref()
            .expect("trusted preprocessing")
            .commitment
    }
    pub fn prove(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<(RecursionExecutionProof, GpuProofMeasurement), String> {
        self.state.limits.admit(&self.template)?;
        let _phase = crate::block_v2::worker_memory::PhaseGuard::acquire("recursion proof")?;
        let started = Instant::now();
        let traces = self
            .template
            .traces(public, witness)
            .map_err(|e| format!("recursion host witness: {e:?}"))?;
        let host_witness_seconds = started.elapsed().as_secs_f64();
        self.state
            .prove_traces(public, traces, host_witness_seconds)
    }
    /// Retire the complete compiler source after evaluating the witness. The
    /// callback may release its weighted preparation permit; the GPU state and
    /// traces remain charged to the separate backend allowance.
    pub fn into_prove(
        self,
        public: &[Val],
        witness: &[Val],
        source_released: impl FnOnce(),
    ) -> Result<(RecursionExecutionProof, GpuProofMeasurement), String> {
        self.state.limits.admit(&self.template)?;
        let _phase = crate::block_v2::worker_memory::PhaseGuard::acquire("recursion proof")?;
        let started = Instant::now();
        let traces = self
            .template
            .traces(public, witness)
            .map_err(|e| format!("recursion host witness: {e:?}"))?;
        let host_witness_seconds = started.elapsed().as_secs_f64();
        let Self { template, state } = self;
        drop(template);
        source_released();
        state.prove_traces(public, traces, host_witness_seconds)
    }
    pub fn verify(&self, proof: &RecursionExecutionProof, public: &[Val]) -> Result<(), String> {
        self.state.verify(proof, public)
    }
}
impl GpuRecursionState {
    fn prove_traces(
        &self,
        public: &[Val],
        traces: Vec<RowMajorMatrix<Val>>,
        host_witness_seconds: f64,
    ) -> Result<(RecursionExecutionProof, GpuProofMeasurement), String> {
        let config = profile::make_proving_config_with_host_budget(self.limits.pcs_host_bytes)
            .map_err(|e| format!("recursion proof config: {e:?}"))?;
        let session = config.pcs().quotient_session()?;
        let public_values = self
            .airs
            .iter()
            .map(|a| if a.kind == 3 { public.to_vec() } else { vec![] })
            .collect::<Vec<_>>();
        let started = Instant::now();
        let mut uploaded = Vec::new();
        for trace in traces {
            let spec = MatrixSpec::new(
                (trace.values.len() / trace.width).ilog2(),
                trace.width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?;
            let words = trace
                .values
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>();
            uploaded.push(session.upload(spec, &words)?);
        }
        let upload_seconds = started.elapsed().as_secs_f64();
        session.aggregation_memory_checkpoint("recursion uploaded private traces")?;
        let stages = Stage::ARITHMETIC
            .into_iter()
            .filter(|s| !matches!(s, Stage::PublicValues | Stage::WitnessTrace))
            .collect::<Vec<_>>();
        let capabilities =
            profile::registered_proof_capabilities().scoped(CoverageScope::Operation, &stages);
        let run = Run::new(
            "recursion_gpu_backend",
            Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            },
            capabilities,
        )
        .map_err(|e| format!("recursion GPU policy: {e:?}"))?;
        let instances = uploaded
            .into_iter()
            .zip(&self.airs)
            .zip(&public_values)
            .map(|((trace, air), public)| {
                gpu_quotient_prover::ProvingInstance::from_device(air, trace, public)
            })
            .collect();
        let started = Instant::now();
        let inner = gpu_quotient_prover::prove_batch(
            &config,
            instances,
            &self.data,
            gpu_hash::CandidateMmcs::release_quotient_prefix,
            |_, _| panic!("recursion GPU backend cannot fall back to host quotient commitment"),
            &run,
        );
        let gpu_prove_seconds = started.elapsed().as_secs_f64();
        let backend_report = run
            .finish(true)
            .map_err(|e| format!("recursion GPU coverage: {e:?}"))?;
        session.aggregation_memory_checkpoint("recursion GPU proof complete")?;
        let proof = RecursionExecutionProof { inner };
        let started = Instant::now();
        self.verify(&proof, public)?;
        let cpu_verify_seconds = started.elapsed().as_secs_f64();
        let proof_json_bytes = serde_json::to_vec(&proof.inner)
            .map_err(|e| e.to_string())?
            .len();
        let query_opened_fields = proof
            .inner
            .opening_proof
            .1
            .query_proofs
            .iter()
            .flat_map(|q| &q.input_proof)
            .flat_map(|p| &p.opened_values)
            .map(Vec::len)
            .sum();
        Ok((
            proof,
            GpuProofMeasurement {
                geometry: self.geometry.clone(),
                public_prefix_host_bytes: self.public_prefix_host_bytes,
                public_salt_host_bytes: self.public_salt_host_bytes,
                host_witness_seconds,
                upload_seconds,
                gpu_prove_seconds,
                cpu_verify_seconds,
                proof_json_bytes,
                query_opened_fields,
                preprocessing_reused: true,
                gpu_backend_only: true,
                verified: true,
                backend_report,
            },
        ))
    }
    pub fn verify(&self, proof: &RecursionExecutionProof, public: &[Val]) -> Result<(), String> {
        if self.airs.iter().find(|a| a.kind == 3).map(|a| a.publics) != Some(public.len())
            || proof.inner.degree_bits
                != self
                    .airs
                    .iter()
                    .map(|a| a.height.ilog2() as usize + 1)
                    .collect::<Vec<_>>()
        {
            return Err("recursion GPU trusted shape mismatch".into());
        }
        let publics = self
            .airs
            .iter()
            .map(|a| if a.kind == 3 { public.to_vec() } else { vec![] })
            .collect::<Vec<_>>();
        verify_batch(
            &profile::make_cpu_config(),
            &self.airs,
            &proof.inner,
            &publics,
            &self.data.common,
        )
        .map_err(|e| format!("recursion independent CPU verification: {e:?}"))
    }
}
