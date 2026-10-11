//! Native backend for registered execution programs. Not an aggregate verifier.
use super::program::Val;
use super::{ExecutionError, MachineAir};
use crate::block_v2::profile::{self, Config};
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;

/// One independent registered-verification lifecycle alongside the worker's
/// proving cache. The qualified phase derivation is in verification_lifetimes.
pub(crate) const NATIVE_VERIFIER_COMPONENT_BYTES: u64 = 257 << 20;

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) mod cache_storage;
mod verification_call;
pub(crate) fn verification_error(error: &impl core::fmt::Debug) -> String {
    verification_call::error(error)
}
mod verification_envelope;
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
pub(crate) mod verification_lifetimes;
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
mod verification_scratch;

pub struct RegisteredProgram {
    air: MachineAir,
    data: ProverData<Config>,
    id: [u64; 4],
    analysis: super::analysis::MachineAnalysis,
    preprocessing_receipt: crate::proving::CachedScope,
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    gpu_witness: Option<super::super::gpu_hash::device::PreparedWitness>,
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    gpu_host_allowance: usize,
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    gpu_pcs_host_allowance: usize,
}

/// Verification-only state. It contains no preprocessing LDE, program witness,
/// inner proof, or wallet data. The caller must authenticate the supplied cap.
pub struct RegisteredVerifier {
    air: MachineAir,
    common: p3_batch_stark::CommonData<Config>,
    quotient_chunks: usize,
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    storage: verification_lifetimes::Plan,
}

impl RegisteredVerifier {
    /// Bound already-owned proof backing storage before constructing independent
    /// verifier metadata. This is not proof-shape or numerical verification.
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn admit_proof_storage(proof: &BatchProof<Config>) -> Result<usize, String> {
        verification_call::proof_bytes(proof).map_err(str::to_owned)
    }

    pub(crate) fn from_trusted_cap(
        publics: usize,
        height: usize,
        cap: p3_batch_stark::Commitment<Config>,
    ) -> Result<Self, ExecutionError> {
        Self::with_metadata_limits(
            publics,
            height,
            cap,
            super::symbolic::verifier::Limits::default(),
        )
    }

    fn with_metadata_limits(
        publics: usize,
        height: usize,
        cap: p3_batch_stark::Commitment<Config>,
        limits: super::symbolic::verifier::Limits,
    ) -> Result<Self, ExecutionError> {
        limits.validate().map_err(|_| ExecutionError::TooLarge)?;
        #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
        let storage = verification_lifetimes::Plan::new(publics, height, &cap, limits)?;
        let air = MachineAir::new(super::ProgramBuilder::new(publics)?.finish(Some(height))?);
        // Cap geometry is rejected before AIR callbacks or graph allocation.
        let degree = air.program().height().ilog2() as usize + 1;
        if cap.roots().len() != 1 << (degree + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT) {
            return Err(ExecutionError::InvalidHeight);
        }
        let symbolic = super::symbolic::verifier::prepare(&air, limits)
            .map_err(|_| ExecutionError::CompilerBackend)?;
        let quotient_chunks = 1 << (symbolic.log_chunks + 1);
        let common = common_from_prepared(&air, cap, symbolic)?;
        Ok(Self {
            air,
            common,
            quotient_chunks,
            #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
            storage,
        })
    }

    /// Source-derived storage for this independently constructed verifier and
    /// one admitted proof. This does not reserve the enclosing worker's memory.
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn storage_plan(&self) -> verification_lifetimes::Plan {
        self.storage
    }

    pub fn verify(&self, proof: &BatchProof<Config>, public: &[Val]) -> Result<(), String> {
        #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
        self.admit_storage(verification_lifetimes::LIMIT_BYTES)?;
        verify_registered(&self.air, &self.common, self.quotient_chunks, proof, public)
    }

    /// The scheduler can reserve this component separately from its caller's
    /// cache, transport buffers, registry and process overhead.
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn admit_storage(&self, allowance: usize) -> Result<(), String> {
        if self.storage_plan().peak_bytes > allowance {
            return Err("native verifier lifecycle exceeds allowance".into());
        }
        Ok(())
    }
}

/// Frozen upstream reference for metadata parity tests. Production verification
/// and device preprocessing transfer bounded metadata through the owned path.
#[cfg(test)]
pub(super) fn common_from_cap(
    air: &MachineAir,
    cap: p3_batch_stark::Commitment<Config>,
) -> Result<p3_batch_stark::CommonData<Config>, ExecutionError> {
    let height = air.program().height();
    use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
    use p3_lookup::{LogUpGadget, Lookups};
    let degree = height.ilog2() as usize + 1;
    if cap.roots().len() != 1 << (degree + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT) {
        return Err(ExecutionError::InvalidHeight);
    }
    let gadget = LogUpGadget::new();
    let unpacked = Lookups::from_air::<profile::Challenge, _>(air);
    let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
        Val,
        profile::Challenge,
        _,
        _,
    >(air, AirLayout::from_air::<Val>(air), &unpacked, 1, &gadget);
    if log_chunks > profile::LOG_BLOWUP {
        return Err(ExecutionError::InvalidHeight);
    }
    Ok(p3_batch_stark::CommonData {
        preprocessed: Some(GlobalPreprocessed {
            commitment: cap,
            instances: vec![Some(PreprocessedInstanceMeta {
                matrix_index: 0,
                width: air.preprocessed_width(),
                degree_bits: degree,
            })],
            matrix_to_instance: vec![0],
        }),
        lookups: vec![unpacked.pack_same_bus(&gadget, 1 << log_chunks)],
    })
}

pub(super) fn common_from_prepared(
    air: &MachineAir,
    cap: p3_batch_stark::Commitment<Config>,
    symbolic: super::symbolic::LookupLayout,
) -> Result<p3_batch_stark::CommonData<Config>, ExecutionError> {
    let mut metadata = metadata_vector(1)?;
    metadata.push(symbolic);
    common_batch_from_prepared(&[air], cap, metadata)
}

fn metadata_vector<T>(count: usize) -> Result<Vec<T>, ExecutionError> {
    if count > 256 {
        return Err(ExecutionError::TooLarge);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ExecutionError::TooLarge)?;
    if core::mem::size_of::<T>() != 0 && values.capacity() != count {
        return Err(ExecutionError::TooLarge);
    }
    Ok(values)
}

pub(super) fn common_batch_from_prepared(
    airs: &[&MachineAir],
    cap: p3_batch_stark::Commitment<Config>,
    symbolic: Vec<super::symbolic::LookupLayout>,
) -> Result<p3_batch_stark::CommonData<Config>, ExecutionError> {
    use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
    if airs.is_empty() || airs.len() > 256 || airs.len() != symbolic.len() {
        return Err(ExecutionError::InvalidHeight);
    }
    let mut degrees = [0usize; 256];
    for (slot, air) in degrees.iter_mut().zip(airs) {
        *slot = air.program().height().ilog2() as usize + 1;
    }
    let degree = *degrees[..airs.len()].iter().max().unwrap();
    if symbolic.iter().any(|s| s.log_chunks > profile::LOG_BLOWUP)
        || cap.roots().len() != 1 << (degree + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT)
    {
        return Err(ExecutionError::InvalidHeight);
    }
    let mut instances = metadata_vector(airs.len())?;
    let mut matrix_to_instance = metadata_vector(airs.len())?;
    let mut lookups = metadata_vector(airs.len())?;
    for (index, ((air, degree), symbolic)) in airs.iter().zip(degrees).zip(symbolic).enumerate() {
        instances.push(Some(PreprocessedInstanceMeta {
            matrix_index: index,
            width: air.preprocessed_width(),
            degree_bits: degree,
        }));
        matrix_to_instance.push(index);
        // Move nested lookup arrays and names without duplicating them.
        lookups.push(symbolic.lookups);
    }
    Ok(p3_batch_stark::CommonData {
        preprocessed: Some(GlobalPreprocessed {
            commitment: cap,
            instances,
            matrix_to_instance,
        }),
        lookups,
    })
}

fn program_identity_fields(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    analysis: &super::analysis::MachineAnalysis,
) -> Vec<u64> {
    let lookup = &common.lookups[0];
    let constraints =
        p3_batch_stark::symbolic::get_symbolic_constraints::<Val, profile::Challenge, _, _>(
            air,
            AirLayout::from_air::<Val>(air),
            lookup,
            &p3_lookup::LogUpGadget::new(),
        );
    let layout = p3_batch_stark::symbolic::get_constraint_layout::<Val, profile::Challenge, _, _>(
        air,
        AirLayout::from_air::<Val>(air),
        lookup,
        &p3_lookup::LogUpGadget::new(),
    );
    program_identity_fields_prepared(
        air,
        common,
        analysis,
        &super::symbolic::Constraints {
            base: constraints.0,
            extension: constraints.1,
            order: layout,
        },
    )
}

fn program_identity_fields_prepared(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    analysis: &super::analysis::MachineAnalysis,
    constraints: &super::symbolic::Constraints,
) -> Vec<u64> {
    let fingerprint = super::fingerprint::encode(
        &constraints.base,
        &constraints.extension,
        &constraints.order,
    );
    let mut fields = Vec::new();
    emit_program_identity(air, common, analysis, &fingerprint, &mut |field| {
        fields.push(field);
        Ok(())
    })
    .expect("infallible identity collection");
    fields
}

fn emit_program_identity(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    analysis: &super::analysis::MachineAnalysis,
    fingerprint: &[u64],
    emit: &mut dyn FnMut(u64) -> Result<(), String>,
) -> Result<(), String> {
    // An execution-program identity, NOT the not-yet-defined recursive
    // profile identity. Bind parameters, program, AIR and lookup constraints,
    // including their emission order, and deterministic preprocessing key.
    for field in [
        1,
        super::WIDTH as u64,
        air.preprocessed_width() as u64,
        profile::LOG_BLOWUP as u64,
        profile::NUM_QUERIES as u64,
        profile::CAP_HEIGHT as u64,
        profile::NUM_RANDOM_CODEWORDS as u64,
        profile::QUERY_POW_BITS as u64,
        3,
        1,
    ] {
        emit(field)?;
    }
    air.program().emit_manifest(emit)?;
    // Goldilocks modulus (u32 limbs), cubic X^3-X-1, hash geometry,
    // MMCS salt width, zero commit PoW and prefix-free duplex revision.
    for field in [
        1,
        0xffff_ffff,
        3,
        crate::block_v2::commitment::MODULUS - 1,
        crate::block_v2::commitment::MODULUS - 1,
        0,
        1,
        8,
        4,
        4,
        4,
        0,
        1,
        analysis.permutation_width_base as u64,
        analysis.quotient_chunks as u64,
        analysis.constraints as u64,
        analysis.max_constraint_degree as u64,
        analysis.query_multiplicity_bound,
    ] {
        emit(field)?;
    }
    for &field in fingerprint {
        emit(field)?;
    }
    let prep = common
        .preprocessed
        .as_ref()
        .expect("machine always has preprocessing");
    for root in prep.commitment.roots() {
        for x in root {
            emit(x.as_canonical_u64())?;
        }
    }
    Ok(())
}

fn program_identity(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    analysis: &super::analysis::MachineAnalysis,
) -> [u64; 4] {
    crate::block_v2::commitment::hash_fields(
        0x4c42563210,
        &program_identity_fields(air, common, analysis),
    )
    .expect("canonical program metadata")
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn program_identity_device(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    analysis: &super::analysis::MachineAnalysis,
    constraints: &super::symbolic::Constraints,
    config: &Config,
    run: &crate::proving::Run,
) -> Result<[u64; 4], String> {
    use p3_uni_stark::StarkGenericConfig;
    let fingerprint = super::fingerprint::bounded::encode(
        &constraints.base,
        &constraints.extension,
        &constraints.order,
        super::fingerprint::bounded::HOST_BYTES,
    )?;
    let session = config.pcs().quotient_session()?;
    let before = session.stats();
    let id = session.hash_public_stream_reported(
        0x4c42563210,
        |emit| emit_program_identity(air, common, analysis, &fingerprint, emit),
        run,
        crate::proving::Stage::Preprocessing,
    )?;
    let after = session.stats();
    eprintln!("bounded_gpu_program_identity fields={} batches={} device_ns={} uploaded_bytes={} downloaded_bytes={}",
        after.public_hash_fields - before.public_hash_fields, after.public_hash_batches - before.public_hash_batches,
        after.public_hash_device_ns - before.public_hash_device_ns,
        after.uploaded_bytes - before.uploaded_bytes, after.downloaded_bytes - before.downloaded_bytes);
    eprintln!("bounded_gpu_manifest host_batch_bytes={} fingerprint_capacity_bytes={} fingerprint_allowance_bytes={}",
        4096 * 8, fingerprint.capacity() * 8, super::fingerprint::bounded::HOST_BYTES);
    Ok(id)
}

fn verify_registered(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    quotient_chunks: usize,
    proof: &BatchProof<Config>,
    public: &[Val],
) -> Result<(), String> {
    if public.len() != air.program().public_values() {
        return Err("public input count".into());
    }
    if proof.degree_bits != [air.program().height().ilog2() as usize + 1] {
        return Err("unregistered degree".into());
    }
    if proof.lookup_terminals.len() != 1
        || !proof.lookup_terminals[0]
            .as_ref()
            .is_some_and(|t| t.0 == profile::Challenge::ZERO)
    {
        return Err("single-table lookup terminal must be zero".into());
    }
    // Bound attacker-controlled lengths before configuration construction,
    // public-value copying, transcript work, or upstream proof-data cloning.
    // This is a structural envelope, not numerical verification or a complete
    // host-memory reservation for the unchanged upstream verifier.
    verification_envelope::check(air, common, quotient_chunks, proof).map_err(str::to_owned)?;
    // Source-derived temporary requests and caller proof backing capacities.
    // Enclosing worker/scheduler lifetimes remain separately admitted.
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    verification_call::Plan::new(air, common, quotient_chunks, proof)
        .and_then(verification_call::Plan::admit)
        .map_err(str::to_owned)?;
    let config = profile::verification::make_config().map_err(str::to_owned)?;
    let public = verification_call::copy_public(public).map_err(str::to_owned)?;
    verify_batch(
        &config,
        core::slice::from_ref(air),
        proof,
        &[public],
        common,
    )
    .map_err(|e| verification_call::error(&e))
}

impl RegisteredProgram {
    pub fn new(air: MachineAir) -> Result<Self, super::analysis::AdmissionError> {
        Self::new_with_memory_budget(air, super::super::feasibility::RAM_BUDGET_BYTES)
    }

    /// Research callers pass the admitted worker allocation. This lower-bound
    /// check does not replace phase-aware host/spill/GPU admission.
    pub fn new_with_memory_budget(
        air: MachineAir,
        budget: u64,
    ) -> Result<Self, super::analysis::AdmissionError> {
        Self::new_with_request(
            air,
            budget,
            crate::proving::Request::from_env()
                .map_err(super::analysis::AdmissionError::ProvingPolicy)?,
        )
    }

    pub fn new_with_request(
        air: MachineAir,
        budget: u64,
        request: crate::proving::Request,
    ) -> Result<Self, super::analysis::AdmissionError> {
        let run = crate::proving::Run::new(
            "block_v2_preprocessing",
            request,
            profile::preprocessing_capabilities(),
        )
        .map_err(super::analysis::AdmissionError::ProvingPolicy)?;
        Self::new_in_run(air, budget, run)
    }

    pub(crate) fn new_in_run(
        air: MachineAir,
        budget: u64,
        run: crate::proving::Run,
    ) -> Result<Self, super::analysis::AdmissionError> {
        use crate::proving::{Backend, Stage};
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        super::gpu_backend::check_selected().map_err(super::analysis::AdmissionError::Gpu)?;
        let capabilities = profile::preprocessing_capabilities();
        let backend = if capabilities
            .stages()
            .iter()
            .all(|s| s.backend == Backend::Cpu)
        {
            Backend::Cpu
        } else {
            Backend::Mixed
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let backend = if super::super::quotient_pcs::gpu_witness_enabled() {
            Backend::OpenCl
        } else {
            backend
        };
        let _phase =
            tracing::info_span!(target: "lattica_block_v2_perf", "preprocessing setup").entered();
        // Configuring the PCS records the actual storage mode before selecting
        // a payload bound. No preprocessing matrices are allocated until after
        // admission. CPU/full-storage paths retain the existing full-LDE guard.
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let gpu_host_allowance = usize::try_from(budget)
            .map_err(|_| super::analysis::AdmissionError::Overflow)?
            .min(super::super::resident_pcs::host_output_budget());
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let gpu_pcs_host_allowance = if super::super::quotient_pcs::gpu_witness_enabled() {
            let bounds = super::gpu_backend::resources::Bounds::for_program_with_device_salts(
                air.program(),
                super::super::quotient_pcs::gpu_randomness_enabled(),
            )
            .map_err(super::analysis::AdmissionError::Gpu)?;
            let partition = bounds
                .partition_host(gpu_host_allowance as u64)
                .map_err(super::analysis::AdmissionError::Gpu)?;
            super::gpu_backend::resources::check_worker(true, Some(&bounds))
                .map_err(super::analysis::AdmissionError::Gpu)?;
            super::super::randomness::resources::check_worker(
                super::super::quotient_pcs::gpu_randomness_enabled(),
                None,
            )
            .map_err(super::analysis::AdmissionError::Gpu)?;
            super::super::challenger::resources::check_worker(
                super::super::quotient_pcs::gpu_transcript_enabled(),
            )
            .map_err(super::analysis::AdmissionError::Gpu)?;
            if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
                eprintln!(
                    "bounded_registered_host_budget {}",
                    serde_json::json!({
                        "schema": "lattica-registered-host-budget-v1",
                        "total_host_bytes": partition.total_bytes,
                        "reserved_host_bytes": partition.reserved_bytes,
                        "pcs_host_bytes": partition.pcs_bytes,
                    })
                );
            }
            usize::try_from(partition.pcs_bytes)
                .map_err(|_| super::analysis::AdmissionError::Overflow)?
        } else {
            gpu_host_allowance
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let preprocessing_config = if super::super::quotient_pcs::gpu_witness_enabled() {
            profile::preprocessing_config_with_host_budget(gpu_pcs_host_allowance)
                .map_err(super::analysis::AdmissionError::ProvingPolicy)?
        } else {
            profile::preprocessing_config()
        };
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let preprocessing_config = profile::preprocessing_config();
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let symbolic = if super::super::quotient_pcs::gpu_witness_enabled() {
            use p3_uni_stark::StarkGenericConfig;
            let session = preprocessing_config
                .pcs()
                .quotient_session()
                .map_err(super::analysis::AdmissionError::Gpu)?;
            Some(
                super::symbolic::prepare_machine(
                    &air,
                    super::compiler_constants::Constants::device(&session, &run),
                )
                .map_err(|e| {
                    super::analysis::AdmissionError::Gpu(format!("GPU setup analysis: {e:?}"))
                })?,
            )
        } else {
            None
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let analysis = match &symbolic {
            Some(prepared) => super::analysis::analyze_prepared(&air, prepared)?,
            None => super::analysis::analyze(&air)?,
        };
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let analysis = super::analysis::analyze(&air)?;
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let compact = super::super::resident_pcs::compact_prover_data();
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let compact = false;
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let host_preprocessing = symbolic.is_none();
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let host_preprocessing = true;
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let (symbolic_layout, symbolic_constraints) = match symbolic {
            Some(prepared) => {
                let (layout, constraints) = prepared.into_parts();
                (Some(layout), Some(constraints))
            }
            None => (None, None),
        };
        // The owned witness path constructs preprocessing directly on device.
        // Its source/compiler/staging and worker reservations were admitted
        // above; the device allocator also enforces its managed allowance.
        // Host LDE payload bounds apply only to the host preprocessing branch.
        if host_preprocessing {
            if compact {
                analysis.check_compact_ram_lower_bound_with_budget(budget)?;
            } else {
                analysis.check_ram_lower_bound_with_budget(budget)?;
            }
        }
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let mut gpu_witness = None;
        let data = run
            .measure(Stage::Preprocessing, backend, || {
                #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
                let _execution_observation =
                    p3_uni_stark::StarkGenericConfig::pcs(&preprocessing_config)
                        .observe_execution(&run)
                        .map_err(super::analysis::AdmissionError::Gpu)?;
                #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
                let _randomness_observation =
                    p3_uni_stark::StarkGenericConfig::pcs(&preprocessing_config)
                        .observe_randomness(&run)
                        .map_err(super::analysis::AdmissionError::Gpu)?;
                #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
                if let Some(symbolic) = symbolic_layout {
                    let prepared = super::gpu_backend::prepare_with_symbolic(
                        &air,
                        &preprocessing_config,
                        gpu_host_allowance,
                        symbolic,
                    )
                    .map_err(super::analysis::AdmissionError::Gpu)?;
                    gpu_witness = Some(prepared.witness);
                    return Ok(prepared.data);
                }
                Ok::<_, super::analysis::AdmissionError>(ProverData::from_airs_and_degrees(
                    &preprocessing_config,
                    core::slice::from_ref(&air),
                    &[air.program().height().ilog2() as usize + 1],
                ))
            })
            .map_err(super::analysis::AdmissionError::ProvingPolicy)??;
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let id = if let Some(constraints) = symbolic_constraints {
            program_identity_device(
                &air,
                &data.common,
                &analysis,
                &constraints,
                &preprocessing_config,
                &run,
            )
            .map_err(super::analysis::AdmissionError::Gpu)?
        } else {
            program_identity(&air, &data.common, &analysis)
        };
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let id = program_identity(&air, &data.common, &analysis);
        drop(preprocessing_config);
        let report = run
            .finish(true)
            .map_err(super::analysis::AdmissionError::ProvingPolicy)?;
        let preprocessing_receipt = crate::proving::CachedScope::preprocessing(&report)
            .map_err(super::analysis::AdmissionError::ProvingPolicy)?;
        let registered = Self {
            air,
            data,
            id,
            analysis,
            preprocessing_receipt,
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            gpu_witness,
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            gpu_host_allowance,
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            gpu_pcs_host_allowance,
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if registered.gpu_witness.is_some() {
            cache_storage::admit_registered(&registered)
                .map_err(super::analysis::AdmissionError::Gpu)?;
        }
        Ok(registered)
    }
    pub(crate) fn reuse_preprocessing(
        &self,
        request: &crate::proving::Run,
    ) -> Result<(), crate::proving::Error> {
        request.reuse_preprocessing("preprocessing", &self.preprocessing_receipt)
    }

    pub fn air(&self) -> &MachineAir {
        &self.air
    }
    pub fn id(&self) -> [u64; 4] {
        self.id
    }
    /// Trusted public preprocessing key. Recursive callers must authenticate
    /// this cap against their registered-program policy, never a proof header.
    pub fn preprocessing_cap(&self) -> &p3_batch_stark::Commitment<Config> {
        &self
            .data
            .common
            .preprocessed
            .as_ref()
            .expect("machine preprocessing")
            .commitment
    }
    pub fn analysis(&self) -> &super::analysis::MachineAnalysis {
        &self.analysis
    }
    pub fn verifier(&self) -> RegisteredVerifier {
        RegisteredVerifier::from_trusted_cap(
            self.air.program().public_values(),
            self.air.program().height(),
            self.preprocessing_cap().clone(),
        )
        .expect("registered program has validated geometry")
    }
    pub fn prove(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<BatchProof<Config>, ExecutionError> {
        self.prove_with_request(
            public,
            witness,
            crate::proving::Request::from_env().map_err(|_| ExecutionError::ProvingPolicy)?,
        )
    }

    pub fn prove_with_request(
        &self,
        public: &[Val],
        witness: &[Val],
        request: crate::proving::Request,
    ) -> Result<BatchProof<Config>, ExecutionError> {
        let run = crate::proving::Run::new(
            "block_v2_registered_program",
            request,
            profile::registered_proof_capabilities(),
        )
        .map_err(|_| ExecutionError::ProvingPolicy)?;
        self.prove_in_run(public, witness, run)
    }

    pub(crate) fn prove_in_run(
        &self,
        public: &[Val],
        witness: &[Val],
        run: crate::proving::Run,
    ) -> Result<BatchProof<Config>, ExecutionError> {
        use crate::proving::{Backend, Stage};
        let capabilities = profile::registered_proof_capabilities();
        let backend = if capabilities
            .stages()
            .iter()
            .all(|s| s.backend == Backend::Cpu)
        {
            Backend::Cpu
        } else {
            Backend::Mixed
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        {
            super::gpu_backend::check_selected().map_err(|_| ExecutionError::GpuFailure)?;
            if self.gpu_witness.is_some() != super::super::quotient_pcs::gpu_witness_enabled() {
                return Err(ExecutionError::GpuFailure);
            }
            if let Some(prepared) = &self.gpu_witness {
                use p3_uni_stark::StarkGenericConfig;
                if public.len() != self.air.program().public_values() {
                    return Err(ExecutionError::PublicInputCount);
                }
                if witness.len() != self.air.program().witness_values() {
                    return Err(ExecutionError::WitnessCount);
                }
                super::super::randomness::resources::check_worker(
                    super::super::quotient_pcs::gpu_randomness_enabled(),
                    None,
                )
                .map_err(|_| ExecutionError::GpuFailure)?;
                super::super::challenger::resources::check_worker(
                    super::super::quotient_pcs::gpu_transcript_enabled(),
                )
                .map_err(|_| ExecutionError::GpuFailure)?;
                let config =
                    profile::make_proving_config_with_host_budget(self.gpu_pcs_host_allowance)
                        .map_err(|_| ExecutionError::GpuFailure)?;
                let session = config
                    .pcs()
                    .quotient_session()
                    .map_err(|_| ExecutionError::GpuFailure)?;
                let trace = run
                    .measure(Stage::WitnessTrace, Backend::OpenCl, || {
                        let _witness_observation = session
                            .observe_witness(&run)
                            .map_err(|_| ExecutionError::GpuFailure)?;
                        tracing::info_span!(target: "lattica_block_v2_perf", "GPU execution trace")
                            .in_scope(|| {
                                super::gpu_backend::trace(
                                    prepared,
                                    &session,
                                    public,
                                    witness,
                                    self.gpu_host_allowance,
                                )
                            })
                    })
                    .map_err(|_| ExecutionError::ProvingPolicy)??;
                // Owned operations record execution directly; checked completion rejects gaps.
                let proof = {
                    super::super::gpu_quotient_prover::prove_batch(
                        &config,
                        vec![
                            super::super::gpu_quotient_prover::ProvingInstance::from_device(
                                &self.air, trace, public,
                            ),
                        ],
                        &self.data,
                        super::super::gpu_hash::CandidateMmcs::release_quotient_prefix,
                        |_, _| panic!("GPU witness mode cannot use host quotient commitment"),
                        &run,
                    )
                };
                run.finish(true)
                    .map_err(|_| ExecutionError::ProvingPolicy)?;
                return Ok(proof);
            }
        }
        let trace = run
            .measure(Stage::WitnessTrace, Backend::Cpu, || {
                tracing::info_span!(target: "lattica_block_v2_perf", "execution trace")
                    .in_scope(|| self.air.trace(public, witness))
            })
            .map_err(|_| ExecutionError::ProvingPolicy)??;
        let instance = StarkInstance {
            air: &self.air,
            trace: &trace,
            public_values: public.to_vec(),
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if super::super::quotient_pcs::gpu_quotient_enabled() {
            let proof = run
                .measure(Stage::UpstreamProver, backend, || {
                    tracing::info_span!(target: "lattica_block_v2_perf", "native batch prove")
                        .in_scope(|| {
                            super::super::gpu_quotient_prover::prove_batch(
                                &profile::make_proving_config(),
                                vec![
                                    super::super::gpu_quotient_prover::ProvingInstance::from_host(
                                        &instance,
                                    ),
                                ],
                                &self.data,
                                |data| {
                                    super::super::gpu_hash::CandidateMmcs::release_quotient_prefix(
                                        data,
                                    )
                                },
                                |pcs, groups| {
                                    pcs.commit_quotient_evaluations(groups).expect(
                                        "GPU quotient commitment failed; no silent fallback",
                                    )
                                },
                                &run,
                            )
                        })
                })
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            run.finish(true)
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            return Ok(proof);
        }
        let proof = run
            .measure(Stage::UpstreamProver, backend, || {
                tracing::info_span!(target: "lattica_block_v2_perf", "native batch prove").in_scope(
                    || prove_batch(&profile::make_proving_config(), &[instance], &self.data),
                )
            })
            .map_err(|_| ExecutionError::ProvingPolicy)?;
        run.finish(true)
            .map_err(|_| ExecutionError::ProvingPolicy)?;
        Ok(proof)
    }
    pub fn verify(&self, proof: &BatchProof<Config>, public: &[Val]) -> Result<(), String> {
        verify_registered(
            &self.air,
            &self.data.common,
            self.analysis.quotient_chunks,
            proof,
            public,
        )
    }
}

#[cfg(test)]
#[cfg(feature = "gpu")]
#[path = "gpu_registered_tests.rs"]
mod gpu_registered_tests;

#[cfg(test)]
mod metadata_tests;

#[cfg(all(test, feature = "stream"))]
mod inverse_tests;
#[cfg(test)]
mod verifier_tests;

#[cfg(test)]
mod tests {
    use super::super::air::{a_column, b_column, c_column};
    use super::*;
    use crate::block_v2::machine::ProgramBuilder;
    use p3_field::{BasedVectorSpace, Field};
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_symmetric::Permutation;

    #[test]
    fn standalone_verifier_uses_only_the_trusted_cap_and_public_statement() {
        // Exercise both public-count banks, including the highest supported slot.
        let mut b = ProgramBuilder::new(64).unwrap();
        for i in 0..64 {
            let public = b.public(i).unwrap();
            let input = b.input();
            b.assert_equal(public, input);
        }
        let registered = RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
        let public: Vec<_> = (17..81).map(Val::from_u64).collect();
        let proof = registered.prove(&public, &public).unwrap();
        let verifier = registered.verifier();
        drop(registered); // No prover state, preprocessed LDE, or program is retained.
        assert_eq!(verifier.air.program().active_rows(), 2);
        verifier.verify(&proof, &public).unwrap();
        let mut wrong = public;
        wrong[63] += Val::ONE;
        assert!(verifier.verify(&proof, &wrong).is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires OpenCL GPU, resident quotient flags, <=3 GiB service and zero swap"]
    fn gpu_quotient_registered_program_uses_the_unchanged_cpu_verifier() {
        use crate::block_v2::{gpu_hash, quotient_pcs};
        let _shutdown = gpu_hash::TestShutdownGuard;
        let fusion = quotient_pcs::initialize_research_from_env().unwrap();
        quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
        assert!(quotient_pcs::gpu_quotient_eval_enabled());
        gpu_hash::initialize_from_env().unwrap();
        assert!(gpu_hash::initialize_resident_from_env().unwrap());
        standalone_verifier_uses_only_the_trusted_cap_and_public_statement();
        gpu_hash::shutdown().unwrap();
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires OpenCL GPU, owned quotient flags, <=3 GiB service and zero swap"]
    fn gpu_owned_registered_preprocessing_reuses_public_buffers_and_releases_private_inputs() {
        use crate::block_v2::{gpu_hash, quotient_pcs};
        let _shutdown = gpu_hash::TestShutdownGuard;
        let fusion = quotient_pcs::initialize_research_from_env().unwrap();
        quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
        assert!(quotient_pcs::gpu_quotient_resident_enabled());
        gpu_hash::initialize_from_env().unwrap();
        assert!(gpu_hash::initialize_resident_from_env().unwrap());
        let initial = gpu_hash::report("owned_registration_before").unwrap();
        assert_eq!(initial.device_matrix_live_bytes, 0);

        let mut b = ProgramBuilder::new(64).unwrap();
        for i in 0..64 {
            let public = b.public(i).unwrap();
            let input = b.input();
            b.assert_equal(public, input);
        }
        let registered = RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
        let verifier = registered.verifier();
        let public_buffers = gpu_hash::report("owned_registration_public").unwrap();
        assert!(public_buffers.device_matrix_live_bytes > 0);
        assert!(public_buffers.device_matrices > 0);
        if quotient_pcs::gpu_pcs_device_only_enabled() {
            assert_eq!(
                public_buffers.lde_host_output_bytes,
                initial.lde_host_output_bytes
            );
            assert_eq!(
                public_buffers.lde_host_reordered_bytes,
                initial.lde_host_reordered_bytes
            );
            assert_eq!(
                public_buffers.lde_commits - initial.lde_commits,
                public_buffers.lde_device_only_commits - initial.lde_device_only_commits
            );
        }
        let mut proofs = Vec::new();
        for offset in [17, 117, 217] {
            let public: Vec<_> = (offset..offset + 64).map(Val::from_u64).collect();
            // Each call builds a fresh proving configuration and device session.
            let proof = registered.prove(&public, &public).unwrap();
            verifier.verify(&proof, &public).unwrap();
            let mut wrong = public.clone();
            wrong[63] += Val::ONE;
            assert!(verifier.verify(&proof, &wrong).is_err());
            let after = gpu_hash::report("owned_registration_proof_complete").unwrap();
            assert_eq!(
                after.device_matrix_live_bytes,
                public_buffers.device_matrix_live_bytes
            );
            assert_eq!(after.device_matrices, public_buffers.device_matrices);
            assert!(after.device_matrix_peak_bytes > public_buffers.device_matrix_live_bytes);
            if quotient_pcs::gpu_pcs_device_only_enabled() {
                assert_eq!(after.lde_host_output_bytes, initial.lde_host_output_bytes);
                assert_eq!(
                    after.lde_host_reordered_bytes,
                    initial.lde_host_reordered_bytes
                );
                assert!(after.lde_device_only_commits > public_buffers.lde_device_only_commits);
                assert_eq!(
                    after.lde_commits - initial.lde_commits,
                    after.lde_device_only_commits - initial.lde_device_only_commits
                );
            }
            proofs.push((proof, public));
        }
        drop(registered);
        let released = gpu_hash::report("owned_registration_released").unwrap();
        assert_eq!(
            released.device_matrix_live_bytes,
            initial.device_matrix_live_bytes
        );
        assert_eq!(released.device_matrices, initial.device_matrices);
        gpu_hash::shutdown().unwrap();
        // Verification keeps only public cap/statement data, even after shutdown.
        for (proof, public) in proofs {
            verifier.verify(&proof, &public).unwrap();
        }
    }

    #[test]
    fn hinted_merkle_cap_paths_are_constrained_in_the_proof() {
        use super::super::program::{Op, Row};
        use p3_symmetric::CryptographicHasher;
        let leaf = crate::config::MyHash::new(default_goldilocks_poseidon2_8()).hash_iter([
            Val::ONE,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
        ]);
        let mut b = ProgramBuilder::new(1).unwrap();
        let bit = b.public(0).unwrap();
        let row = b.input();
        let zero = b.constant(Val::ZERO);
        let cap = [leaf.map(|v| b.constant(v)), [zero; 4]];
        b.authenticate_equal_height_mmcs(&cap, &[bit], &[vec![row]], &[[zero; 4]], &[])
            .unwrap();
        let registered = RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
        let public = [Val::ZERO];
        let proof = registered.prove(&public, &[Val::ONE]).unwrap();
        registered.verify(&proof, &public).unwrap();
        assert!(registered.verify(&proof, &[Val::ONE]).is_err());
        let clean = registered.air.trace(&public, &[Val::ONE]).unwrap();
        let mut hints = 0;
        for (r, row) in registered.air.program.rows.iter().enumerate() {
            if let Row::Alu(ops) = row {
                for (lane, op) in ops.iter().enumerate() {
                    if matches!(op, Op::SelectHint { .. }) {
                        hints += 1;
                        let mut trace = clean.clone();
                        trace.values[r * super::super::WIDTH + c_column(lane)] += Val::ONE;
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            prove_batch(
                                &profile::make_config(),
                                &[StarkInstance {
                                    air: &registered.air,
                                    trace: &trace,
                                    public_values: public.to_vec(),
                                }],
                                &registered.data,
                            )
                        }));
                        if let Ok(proof) = result {
                            assert!(registered.verify(&proof, &public).is_err());
                        }
                    }
                }
            }
        }
        assert_eq!(hints, 4);
    }

    #[test]
    fn cubic_and_selection_instructions_are_proved() {
        for bit in [0, 1] {
            let mut b = ProgramBuilder::new(3).unwrap();
            let a = core::array::from_fn(|_| b.input());
            let c = core::array::from_fn(|_| b.input());
            let select = b.input();
            let product = b.ext_mul(a, c);
            let inverse = b.ext_inverse(a);
            let unit = b.ext_mul(a, inverse);
            let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
            b.ext_assert_equal(unit, one);
            let chosen = b.ext_select(select, product, inverse);
            for (i, &w) in chosen.iter().enumerate() {
                let public = b.public(i).unwrap();
                b.assert_equal(w, public);
            }
            let registered =
                RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
            let av = [17, 31, 47].map(Val::from_u64);
            let cv = [59, 71, 97].map(Val::from_u64);
            let a = profile::Challenge::from_basis_coefficients_slice(&av).unwrap();
            let c = profile::Challenge::from_basis_coefficients_slice(&cv).unwrap();
            let result = if bit == 0 { a * c } else { a.inverse() };
            let public = result.as_basis_coefficients_slice();
            let mut witness = av
                .into_iter()
                .chain(cv)
                .chain([Val::from_u64(bit)])
                .collect::<Vec<_>>();
            let proof = registered.prove(public, &witness).unwrap();
            registered.verify(&proof, public).unwrap();
            let mut wrong = public.to_vec();
            wrong[1] += Val::ONE;
            assert!(registered.verify(&proof, &wrong).is_err());
            witness[6] = Val::from_u64(2);
            assert!(registered.prove(public, &witness).is_err());
            witness[6] = Val::ZERO;
            witness[..3].fill(Val::ZERO);
            assert!(registered.prove(public, &witness).is_err());

            // Bypass the interpreter to test the AIR, not just witness generation.
            let witness = av
                .into_iter()
                .chain(cv)
                .chain([Val::from_u64(bit)])
                .collect::<Vec<_>>();
            let clean = registered.air.trace(public, &witness).unwrap();
            for (row, kind) in registered.air.program.rows.iter().enumerate() {
                if let super::super::program::Row::Cubic(_) = kind {
                    let mut trace = clean.clone();
                    trace.values[row * super::super::WIDTH + c_column(0)] += Val::ONE;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        prove_batch(
                            &profile::make_config(),
                            &[StarkInstance {
                                air: &registered.air,
                                trace: &trace,
                                public_values: public.to_vec(),
                            }],
                            &registered.data,
                        )
                    }));
                    if let Ok(proof) = result {
                        assert!(registered.verify(&proof, public).is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn arithmetic_and_hash_execution_proof() {
        let mut b = ProgramBuilder::new(8).unwrap();
        let x = b.input();
        let y = b.input();
        let sum = b.add(x, y);
        let product = b.mul(x, sum);
        let inverse = b.inverse(product);
        let one = b.mul(product, inverse);
        let c1 = b.constant(Val::ONE);
        b.assert_equal(one, c1);
        let zero = b.constant(Val::ZERO);
        b.assert_bool(zero);
        let input = [sum, product, inverse, one, x, y, zero, c1];
        let hash = b.poseidon(input);
        for (i, w) in hash.iter().enumerate() {
            let public = b.public(i).unwrap();
            b.assert_equal(*w, public);
        }
        let program = b.finish(None).unwrap();
        let registered = RegisteredProgram::new(MachineAir::new(program)).unwrap();
        let x = Val::from_u64(19);
        let y = Val::from_u64(23);
        let product = x * (x + y);
        use p3_field::Field;
        let mut public = [
            x + y,
            product,
            product.inverse(),
            Val::ONE,
            x,
            y,
            Val::ZERO,
            Val::ONE,
        ];
        default_goldilocks_poseidon2_8().permute_mut(&mut public);
        let mut proof = registered.prove(&public, &[x, y]).unwrap();
        registered.verify(&proof, &public).unwrap();
        let mut wrong = public;
        wrong[0] += Val::ONE;
        assert!(registered.verify(&proof, &wrong).is_err());
        proof.lookup_terminals[0].as_mut().unwrap().0 += profile::Challenge::ONE;
        assert!(registered.verify(&proof, &public).is_err());
    }

    #[cfg(feature = "block-v2-wide-lanes")]
    #[test]
    fn wide_lane_overlap_and_padding_mutations_are_rejected_by_real_proofs() {
        use super::super::air::d_column;
        use super::super::program::{Op, Row, EXT_LANES, LANES};
        use super::super::WIDTH;
        assert_eq!((LANES, EXT_LANES), (23, 7));
        let mut b = ProgramBuilder::new(8).unwrap();
        let inputs: Vec<_> = (0..LANES * 2).map(|_| b.input()).collect();
        let bit = b.input();
        for i in 0..LANES {
            b.add(inputs[i], inputs[i + 1]);
            b.mul(inputs[i], inputs[i + 1]);
            b.select(bit, inputs[i], inputs[i + 1]);
            b.inverse(inputs[i]);
        }
        for group in 0..EXT_LANES {
            let a = core::array::from_fn(|i| inputs[group * 3 + i]);
            let c = core::array::from_fn(|i| inputs[i]);
            b.cubic_mul(a, c);
            b.cubic_inverse(a);
        }
        let hash = b.poseidon(core::array::from_fn(|i| inputs[i]));
        for (i, value) in hash.into_iter().enumerate() {
            let public = b.public(i).unwrap();
            b.assert_equal(value, public);
        }
        let program = b.finish(Some(32)).unwrap();
        let hash_row = program
            .rows
            .iter()
            .position(|r| matches!(r, Row::Poseidon { .. }))
            .unwrap();
        let cubic_row = program
            .rows
            .iter()
            .position(|r| matches!(r, Row::Cubic(ops) if ops.len() == EXT_LANES))
            .unwrap();
        let alu_row = program.rows.iter().position(|r| matches!(r, Row::Alu(ops)
            if ops.len() == LANES && matches!(ops.last(), Some(Op::Add { .. } | Op::Mul { .. } | Op::Inverse { .. } | Op::Select { .. })))).unwrap();
        let padding_row = program.active_rows();
        assert!(padding_row < program.height());
        let mut witness: Vec<_> = (0..LANES * 2).map(|i| Val::from_usize(i + 2)).collect();
        witness.push(Val::ONE);
        let mut public = core::array::from_fn::<_, 8, _>(|i| Val::from_usize(i + 2));
        default_goldilocks_poseidon2_8().permute_mut(&mut public);
        let registered = RegisteredProgram::new(MachineAir::new(program)).unwrap();
        assert_eq!(registered.analysis().max_constraint_degree, 8);
        let proof = registered.prove(&public, &witness).unwrap();
        registered.verify(&proof, &public).unwrap();
        assert_eq!(proof.lookup_terminals.len(), 1);
        assert_eq!(
            proof.lookup_terminals[0].as_ref().unwrap().0,
            profile::Challenge::ZERO
        );
        let clean = registered.air.trace(&public, &witness).unwrap();
        // Bypass the interpreter: mutate active high lanes, overlapping fixed
        // hash checkpoints, unused arithmetic tail cells, public and padding rows.
        let mutations = [
            (alu_row, c_column(LANES - 1)),
            (alu_row, 4 * LANES),
            (cubic_row, c_column(3 * (EXT_LANES - 1))),
            (cubic_row, d_column(LANES - 1)),
            (hash_row, a_column(0)),
            (hash_row, b_column(0)),
            (hash_row, c_column(0)),
            (hash_row, d_column(0)),
            (hash_row, a_column(LANES - 1)),
            (hash_row, c_column(LANES - 1)),
            (hash_row, WIDTH - 1),
            (0, c_column(LANES - 1)),
            (padding_row, a_column(0)),
            (padding_row, a_column(LANES - 1)),
            (padding_row, b_column(LANES - 1)),
            (padding_row, c_column(LANES - 1)),
            (padding_row, WIDTH - 1),
        ];
        assert_eq!(mutations.len(), 17);
        assert_eq!(
            mutations
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            mutations.len()
        );
        for (row, column) in mutations {
            let mut trace = clean.clone();
            trace.values[row * WIDTH + column] += Val::ONE;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_batch(
                    &profile::make_config(),
                    &[StarkInstance {
                        air: &registered.air,
                        trace: &trace,
                        public_values: public.to_vec(),
                    }],
                    &registered.data,
                )
            }));
            if let Ok(proof) = result {
                assert!(
                    registered.verify(&proof, &public).is_err(),
                    "accepted mutation row={row} column={column}"
                );
            }
        }
    }

    fn copy_program(constant: u64, height: Option<usize>) -> MachineAir {
        let mut b = ProgramBuilder::new(1).unwrap();
        let x = b.input();
        let c = b.constant(Val::from_u64(constant));
        let y = b.add(x, c);
        let public = b.public(0).unwrap();
        b.assert_equal(y, public);
        MachineAir::new(b.finish(height).unwrap())
    }

    #[test]
    fn registration_is_deterministic_and_rejects_key_substitution() {
        let a = RegisteredProgram::new(copy_program(7, None)).unwrap();
        let b = RegisteredProgram::new(copy_program(7, None)).unwrap();
        let c = RegisteredProgram::new(copy_program(8, None)).unwrap();
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), c.id());
        let public = [Val::from_u64(12)];
        let witness = [Val::from_u64(5)];
        let proof = a.prove(&public, &witness).unwrap();
        b.verify(&proof, &public).unwrap();
        assert!(c.verify(&proof, &public).is_err());
        let second = a.prove(&public, &witness).unwrap();
        assert_ne!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&second).unwrap()
        );
        let analysis = a.analysis();
        assert!(analysis.constraints > 100);
        assert!(analysis.permutation_width_base > 0);
        assert!(analysis.max_constraint_degree >= 8);
        assert!(analysis.fri_ali_bits >= 100); // Still NOT total lookup/composition security.
    }

    #[test]
    fn rejects_unconstrained_copy_and_program_tampering() {
        let registered = RegisteredProgram::new(copy_program(7, None)).unwrap();
        let public = vec![Val::from_u64(12)];
        let mut trace = registered.air.trace(&public, &[Val::from_u64(5)]).unwrap();
        // First ALU row lanes: input, constant, add, assert_equal. Change the add's
        // reads and matching local output/assertion so its algebra remains true,
        // but make the read disagree with the wire's unique definition.
        let row = registered
            .air
            .program
            .rows
            .iter()
            .position(|row| matches!(row, super::super::program::Row::Alu(_)))
            .unwrap();
        trace.values[row * super::super::WIDTH + a_column(2)] += Val::ONE; // x becomes x+1
        trace.values[row * super::super::WIDTH + b_column(2)] -= Val::ONE; // 7 becomes 6
                                                                           // Debug prover intentionally panics on a bad lookup witness; release
                                                                           // emits an invalid proof. Both are rejections, never a valid aggregate.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_batch(
                &profile::make_config(),
                &[StarkInstance {
                    air: &registered.air,
                    trace: &trace,
                    public_values: public.clone(),
                }],
                &registered.data,
            )
        }));
        if let Ok(proof) = result {
            assert!(registered.verify(&proof, &public).is_err());
        }

        let mut proof = registered.prove(&public, &[Val::from_u64(5)]).unwrap();
        proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
        assert!(registered.verify(&proof, &public).is_err());
        proof.degree_bits[0] += 1;
        assert!(registered.verify(&proof, &public).is_err());
    }

    #[test]
    fn resource_rejection_precedes_preprocessing_allocation() {
        let air = copy_program(7, Some(1 << 24));
        assert!(matches!(
            RegisteredProgram::new(air),
            Err(super::super::analysis::AdmissionError::RamLowerBound { .. })
        ));
    }
}
