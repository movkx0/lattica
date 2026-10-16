//! Resident commitment adapter for the two pinned upstream PCS fields.
//! One shared CSPRNG stream feeds both this adapter and upstream quotient masks.
//! Cloning an active adapter shares its whole attempt; it never replays RNG state.
//! Fresh entropy still belongs to profile::make_proving_config, not this module.
#[cfg(feature = "stream")]
use super::normalization_workspace::HeapNormalizedDft as Dft;
use super::{
    gpu_hash::FriExtensionMmcs,
    gpu_hash::{CandidateMmcs, LdeInputShape},
    pcs_field::PcsField,
    profile::{self, Challenge},
};
#[cfg(not(feature = "stream"))]
use crate::config::Dft;
use crate::config::Val;
use p3_commit::Mmcs;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::BasedVectorSpace;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
use rand::{Rng, TryRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Mutex, OnceLock};

type Domain = TwoAdicMultiplicativeCoset<Val>;
type Commitment = <CandidateMmcs as Mmcs<Val>>::Commitment;
type ProverData = <CandidateMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
pub(super) type ResidentInner<E = Challenge> =
    HidingFriPcs<Val, Dft, CandidateMmcs, FriExtensionMmcs<E>, SharedProofRng>;
const MAX_MATRICES: usize = 256;
pub(super) const HOST_OUTPUT_BUDGET: usize = 32 << 30;

static RESEARCH_RESIDENT: OnceLock<bool> = OnceLock::new();
static RESEARCH_OPENINGS: OnceLock<bool> = OnceLock::new();
static RESEARCH_INITIALIZE: Mutex<()> = Mutex::new(());

fn parse_research_mode(value: Option<&str>) -> Result<bool, &'static str> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err("LATTICA_V2_GPU_RESIDENT_LDE must be 0 or 1"),
    }
}

fn record_research_mode(mode: &OnceLock<bool>, enabled: bool) -> Result<(), &'static str> {
    if let Some(previous) = mode.get() {
        return if *previous == enabled {
            Ok(())
        } else {
            Err("resident PCS mode cannot change during a research process")
        };
    }
    mode.set(enabled)
        .map_err(|_| "resident PCS mode initialized concurrently")
}

fn research_selection_from_env() -> Result<(bool, bool, bool), String> {
    let value = match std::env::var("LATTICA_V2_GPU_RESIDENT_LDE") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("LATTICA_V2_GPU_RESIDENT_LDE must be ASCII 0 or 1".into());
        }
    };
    let enabled = parse_research_mode(value.as_deref()).map_err(str::to_owned)?;
    let openings = match std::env::var("LATTICA_V2_GPU_OPENINGS") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "0" => false,
        Ok(value) if value == "1" => true,
        _ => return Err("LATTICA_V2_GPU_OPENINGS must be ASCII 0 or 1".into()),
    };
    if openings && !enabled {
        return Err("GPU openings require the explicit resident research backend".into());
    }
    let compact = match std::env::var("LATTICA_V2_GPU_COMPACT_PROVER_DATA").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => return Err("LATTICA_V2_GPU_COMPACT_PROVER_DATA must be 0 or 1".into()),
    };
    if compact
        && (!enabled
            || !openings
            || std::env::var("LATTICA_V2_GPU_OPENING_COMPACT").as_deref() != Ok("1")
            || std::env::var("LATTICA_V2_GPU_QUOTIENT_LDE").as_deref() != Ok("1"))
    {
        return Err(
            "compact prover data requires resident LDE, GPU quotient and compact GPU openings"
                .into(),
        );
    }
    Ok((enabled, openings, compact))
}

fn validate_research_selection(selection: (bool, bool, bool)) -> Result<(), String> {
    for (cell, value) in [
        (&RESEARCH_RESIDENT, selection.0),
        (&RESEARCH_OPENINGS, selection.1),
        (&RESEARCH_COMPACT_DATA, selection.2),
    ] {
        if cell.get().is_some_and(|previous| *previous != value) {
            return Err("resident PCS mode cannot change during a research process".into());
        }
    }
    Ok(())
}

/// Validate native startup without committing a mode or allocating a GPU context.
pub(super) fn preflight_research_from_env() -> Result<(), String> {
    validate_research_selection(research_selection_from_env()?)
}

/// Explicit Rust/native selection after GPU initialization. Merely setting
/// environment variables does not select a library backend.
pub fn initialize_research_from_env() -> Result<bool, String> {
    let _guard = RESEARCH_INITIALIZE
        .lock()
        .map_err(|_| "resident PCS initialization poisoned")?;
    let (enabled, openings, compact) = research_selection_from_env()?;
    validate_research_selection((enabled, openings, compact))?;
    if enabled {
        super::gpu_hash::require_resident_backend()?;
    }
    // Check all immutable settings before recording any of them.
    record_research_mode(&RESEARCH_COMPACT_DATA, compact).map_err(str::to_owned)?;
    record_research_mode(&RESEARCH_OPENINGS, openings).map_err(str::to_owned)?;
    record_research_mode(&RESEARCH_RESIDENT, enabled).map_err(str::to_owned)?;
    Ok(enabled)
}

pub(super) fn research_enabled() -> bool {
    RESEARCH_RESIDENT.get().copied().unwrap_or(false)
}

pub(super) fn research_openings_enabled() -> bool {
    RESEARCH_OPENINGS.get().copied().unwrap_or(false)
}

type SharedProofRng = super::randomness::ProofRng;

pub(super) struct ResidentState<E: PcsField = Challenge> {
    pub(super) device_randomness: Option<super::randomness::Failure>,
    pub(super) preprocessing_salts: Option<Mutex<super::gpu_hash::device::PublicSaltStream>>,
    pub(super) device_session: Option<super::gpu_hash::device::DeviceSession>,
    pub(super) inner: ResidentInner<E>,
    // Only one opening backend may consume FRI randomness. This saved initial
    // stream is used exclusively when GPU openings are selected at construction;
    // active clones share this entire state rather than cloning either stream.
    opening_fri: FriParameters<FriExtensionMmcs<E>>,
    pub(super) gpu_openings: bool,
    opening_mode_locked: std::sync::atomic::AtomicBool,
    pub(super) mmcs: CandidateMmcs,
    pub(super) rng: SharedProofRng,
    random_columns: usize,
    log_blowup: usize,
    pub(super) host_budget: usize,
}

fn collect<T>(values: impl IntoIterator<Item = T>) -> Result<Vec<T>, String> {
    let values: Vec<_> = values.into_iter().take(MAX_MATRICES + 1).collect();
    if values.is_empty() || values.len() > MAX_MATRICES {
        return Err("resident PCS matrix count".into());
    }
    Ok(values)
}

impl<E: PcsField> ResidentState<E> {
    pub(super) fn require_device_proving(&self) -> Result<(), String> {
        if let Some(failure) = &self.device_randomness {
            failure.check()?;
        }
        if self.preprocessing_salts.is_some() {
            return Err(
                "public preprocessing salt configuration cannot prove private statements".into(),
            );
        }
        if self.mmcs.uses_device_storage()
            && (!self.gpu_openings
                || !super::quotient_pcs::gpu_fri_resident_enabled()
                || !super::quotient_pcs::gpu_opening_eval_enabled()
                || !super::quotient_pcs::gpu_lookup_enabled()
                || !super::quotient_pcs::gpu_quotient_resident_enabled())
        {
            return Err(
                "device-only PCS requires owned GPU consumers selected before proof work".into(),
            );
        }
        Ok(())
    }
    pub(super) fn trace_random_words(&self, count: usize) -> Result<Vec<u64>, String> {
        use p3_field::PrimeField64;
        use rand::RngExt;
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(count)
            .map_err(|e| e.to_string())?;
        self.rng
            .with(|rng| samples.extend((0..count).map(|_| rng.random::<Val>().as_canonical_u64())));
        Ok(samples)
    }

    pub(super) fn lock_opening_mode(&self) {
        self.opening_mode_locked
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(super) fn enable_gpu_openings(&mut self) -> Result<(), String> {
        if self
            .opening_mode_locked
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("opening backend cannot change after proof work begins".into());
        }
        self.gpu_openings = true;
        Ok(())
    }
    pub(super) fn enable_gpu_randomness(
        &mut self,
        quotient: &super::randomness::ProofRng,
    ) -> Result<(), String> {
        if self
            .opening_mode_locked
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("GPU randomness must be selected before proof work begins".into());
        }
        if self.device_randomness.is_some() {
            return self.require_device_proving();
        }
        self.require_device_proving()?;
        if !self.mmcs.uses_device_storage() {
            return Err("GPU randomness requires device-only PCS storage".into());
        }
        let session = self
            .device_session
            .as_ref()
            .ok_or("GPU randomness requires a device session")?;
        let failure = super::randomness::Failure::default();
        let activation = failure.begin()?;
        self.mmcs.activate_private_randomness(session, &failure)?;
        self.opening_fri
            .mmcs
            .inner()
            .activate_private_randomness(session, &failure)?;
        self.rng.activate(session, &failure)?;
        quotient.activate(session, &failure)?;
        self.device_randomness = Some(failure);
        activation.complete();
        Ok(())
    }

    pub(super) fn enable_gpu_preprocessing_salts(&mut self) -> Result<(), String> {
        if self
            .opening_mode_locked
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("public salt backend cannot change after preprocessing work begins".into());
        }
        if self.preprocessing_salts.is_some() {
            return Ok(());
        }
        self.require_device_proving()?;
        self.mmcs.require_fresh_public_preprocessing()?;
        let session = self
            .device_session
            .as_ref()
            .ok_or("public salts require a device session")?;
        self.preprocessing_salts = Some(Mutex::new(session.public_preprocessing_salt_stream()?));
        Ok(())
    }

    pub(super) fn new(
        dft: Dft,
        mmcs: CandidateMmcs,
        fri: FriParameters<FriExtensionMmcs<E>>,
        random_columns: usize,
        rng: ChaCha20Rng,
        host_budget: usize,
    ) -> Result<Self, String> {
        if fri.log_blowup != profile::LOG_BLOWUP
            || fri.log_final_poly_len != 0
            || fri.max_log_arity != E::MAX_LOG_ARITY
            || fri.num_queries != E::NUM_QUERIES
            || fri.commit_proof_of_work_bits != 0
            || fri.query_proof_of_work_bits != profile::QUERY_POW_BITS
            || random_columns != profile::NUM_RANDOM_CODEWORDS
            || host_budget == 0
            || host_budget > HOST_OUTPUT_BUDGET
        {
            return Err("resident PCS requires pinned field parameters and host allowance".into());
        }
        let committer = mmcs.share_for_resident()?;
        let log_blowup = fri.log_blowup;
        let rng = SharedProofRng::new(rng);
        let opening_fri = fri.clone();
        let inner = ResidentInner::new(dft, mmcs, fri, random_columns, rng.clone());
        Ok(Self {
            device_randomness: None,
            preprocessing_salts: None,
            device_session: if super::quotient_pcs::gpu_quotient_resident_enabled() {
                Some(super::gpu_hash::device::DeviceSession::new()?)
            } else {
                None
            },
            inner,
            opening_fri,
            gpu_openings: false,
            opening_mode_locked: std::sync::atomic::AtomicBool::new(false),
            mmcs: committer,
            rng,
            random_columns,
            log_blowup,
            host_budget,
        })
    }

    pub(super) fn open(
        &self,
        rounds: Vec<(&ProverData, Vec<Vec<E>>)>,
        challenger: &mut profile::Challenger,
        is_preprocessing: bool,
    ) -> (
        p3_commit::OpenedValues<E>,
        <ResidentInner<E> as p3_commit::Pcs<E, profile::Challenger>>::Proof,
    ) {
        self.lock_opening_mode();
        assert!(self.gpu_openings, "GPU opening backend not selected");
        assert!(
            self.preprocessing_salts.is_none(),
            "public salt setup cannot open a private proof"
        );
        let guard = self
            .device_randomness
            .as_ref()
            .map(|f| f.begin().expect("GPU randomness attempt failed"));
        let result = super::opening_pcs::open_hiding(
            &self.mmcs,
            &self.opening_fri,
            rounds,
            challenger,
            is_preprocessing,
            self.random_columns,
            if super::quotient_pcs::gpu_opening_eval_enabled() {
                Some(self.device_session.as_ref().expect("owned opening session"))
            } else {
                None
            },
            self.host_budget,
        );
        if let Some(guard) = guard {
            guard.complete();
        }
        result
    }

    pub(super) fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<Val>)>,
        preprocessing: bool,
    ) -> Result<(Commitment, ProverData), String> {
        self.lock_opening_mode();
        if self.preprocessing_salts.is_some() || self.device_randomness.is_some() {
            return Err("GPU randomness requires device trace interfaces".into());
        }
        if !preprocessing {
            self.require_device_proving()?;
        }
        let evaluations = collect(evaluations)?;
        let mut shapes = Vec::with_capacity(evaluations.len());
        for (domain, matrix) in &evaluations {
            if matrix.width == 0
                || matrix.values.len() % matrix.width != 0
                || (matrix.values.len() / matrix.width).checked_mul(2) != Some(domain.size())
            {
                return Err("resident hiding input does not match its doubled domain".into());
            }
            let width = matrix
                .width
                .checked_add(if preprocessing {
                    0
                } else {
                    self.random_columns
                })
                .ok_or("resident hiding width overflow")?;
            shapes.push(LdeInputShape {
                height: domain.size(),
                width,
                added_bits: self.log_blowup,
            });
        }
        let _admission = self.mmcs.preflight_retained_owned(
            &shapes,
            self.host_budget,
            usize::from(compact_prover_data()),
            self.device_session.is_some(),
        )?;
        // Same row-major draw order and reshape as p3-fri 0.6.1 HidingFriPcs.
        // This lock is released before entering MMCS or upstream methods.
        let randomized: Vec<_> = if preprocessing {
            evaluations
                .into_iter()
                .map(|(domain, matrix)| {
                    let width = matrix.width;
                    let mut padded = matrix.with_zero_cols(width);
                    padded.width = width;
                    (domain, padded)
                })
                .collect()
        } else {
            self.rng.with(|rng| {
                evaluations
                    .into_iter()
                    .map(|(domain, matrix)| {
                        let width = matrix.width;
                        let mut randomized =
                            matrix.with_random_cols(width + 2 * self.random_columns, &mut *rng);
                        randomized.width = width + self.random_columns;
                        (domain, randomized)
                    })
                    .collect()
            })
        };
        self.mmcs.commit_resident_retained_owned(
            randomized,
            self.log_blowup,
            self.host_budget,
            None,
            usize::from(compact_prover_data()),
            self.device_session.as_ref().map(|s| (s, preprocessing)),
        )
    }

    pub(super) fn randomization_device(
        &self,
        domains: impl IntoIterator<Item = super::gpu_hash::device::DomainSpec>,
    ) -> Result<(Commitment, ProverData), String> {
        self.lock_opening_mode();
        self.require_device_proving()?;
        let domains = collect(domains)?;
        let width = self.random_columns + <E as BasedVectorSpace<Val>>::DIMENSION;
        let shapes: Vec<_> = domains
            .iter()
            .map(|domain| LdeInputShape {
                height: domain.size(),
                width,
                added_bits: self.log_blowup,
            })
            .collect();
        if let Some(failure) = &self.device_randomness {
            use super::gpu_hash::device::{Extension, MatrixSpec, RowOrder};
            use p3_field::PrimeField64;
            let session = self
                .device_session
                .as_ref()
                .ok_or("GPU randomness requires a device session")?;
            let specs: Vec<_> = domains
                .iter()
                .map(|domain| {
                    if !(1..=25).contains(&domain.log_size()) {
                        return Err(
                            "GPU randomization domain exceeds its supported height".to_owned()
                        );
                    }
                    MatrixSpec::new(
                        domain.log_size() as u32,
                        width,
                        Extension::Base,
                        RowOrder::Natural,
                        domain.shift().as_canonical_u64(),
                    )
                })
                .collect::<Result<_, _>>()?;
            let pending: Vec<_> = specs.iter().flat_map(|s| [s.bytes(), 16]).collect();
            let plan = self
                .mmcs
                .preflight_private_salts(&shapes, self.host_budget, 0, &pending)?;
            self.rng.with_device(|rng| {
                rng.preflight_fields(
                    &specs.iter().map(|s| s.words()).collect::<Vec<_>>(),
                    &vec![16; specs.len()],
                )
            })?;
            let guard = failure.begin()?;
            let inputs = self.rng.with_device(|rng| {
                specs
                    .iter()
                    .map(|&spec| {
                        let samples = rng.sample_matrix(spec)?;
                        session.prepare_evaluations(&samples)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            let salts = self
                .mmcs
                .private_device_salts(plan.output_height(), inputs.len())?;
            let result = self.mmcs.commit_evaluations_with_device_salts(
                &inputs,
                self.log_blowup,
                salts,
                session,
                self.host_budget,
            )?;
            guard.complete();
            eprintln!("bounded_gpu_random_stage stage=randomization sample_upload_bytes=0 sample_readback_bytes=0");
            return Ok(result);
        }
        Err("owned randomization requires private GPU randomness".into())
    }

    pub(super) fn randomization(
        &self,
        domains: impl IntoIterator<Item = Domain>,
    ) -> Result<(Commitment, ProverData), String> {
        self.lock_opening_mode();
        self.require_device_proving()?;
        let domains = collect(domains)?;
        if self.device_randomness.is_some() {
            return self.randomization_device(domains.into_iter().map(Into::into));
        }
        let width = self.random_columns + <E as BasedVectorSpace<Val>>::DIMENSION;
        let shapes: Vec<_> = domains
            .iter()
            .map(|domain| LdeInputShape {
                height: domain.size(),
                width,
                added_bits: self.log_blowup,
            })
            .collect();
        let capture = super::quotient_pcs::gpu_opening_eval_enabled()
            .then(|| self.device_session.as_ref().expect("owned opening session"));
        let _admission = self.mmcs.preflight_retained_owned(
            &shapes,
            self.host_budget,
            if compact_prover_data() {
                self.log_blowup
            } else {
                0
            },
            capture.is_some(),
        )?;
        // Already-random evaluations: upstream does NOT interleave another
        // random trace or append additional codewords on this path.
        let randomized = self.rng.with(|rng| {
            domains
                .into_iter()
                .map(|domain| {
                    let matrix = RowMajorMatrix::rand(&mut *rng, domain.size(), width);
                    (domain, matrix)
                })
                .collect()
        });
        self.mmcs.commit_resident_retained_owned(
            randomized,
            self.log_blowup,
            self.host_budget,
            None,
            if compact_prover_data() {
                self.log_blowup
            } else {
                0
            },
            capture.map(|session| (session, false)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn research_selection_is_explicit_strict_and_immutable() {
        assert_eq!(parse_research_mode(None), Ok(false));
        assert_eq!(parse_research_mode(Some("0")), Ok(false));
        assert_eq!(parse_research_mode(Some("1")), Ok(true));
        for invalid in ["", "true", "01", " 1", "1 ", "2", "\u{ff11}"] {
            assert!(parse_research_mode(Some(invalid)).is_err());
        }
        for enabled in [false, true] {
            let mode = OnceLock::new();
            record_research_mode(&mode, enabled).unwrap();
            record_research_mode(&mode, enabled).unwrap();
            assert!(record_research_mode(&mode, !enabled).is_err());
            assert_eq!(mode.get(), Some(&enabled));
        }
    }

    #[test]
    fn shared_rng_preserves_all_draw_methods_without_replaying_a_clone() {
        let mut reference = ChaCha20Rng::from_seed([71; 32]);
        let mut first = SharedProofRng::new(ChaCha20Rng::from_seed([71; 32]));
        let mut second = first.clone();
        for _ in 0..7 {
            assert_eq!(first.next_u32(), reference.next_u32());
            assert_eq!(second.next_u64(), reference.next_u64());
            let mut actual = [0u8; 37];
            let mut expected = [0u8; 37];
            first.fill_bytes(&mut actual);
            reference.fill_bytes(&mut expected);
            assert_eq!(actual, expected);
            second.with(|rng| assert_eq!(rng.next_u64(), reference.next_u64()));
        }
        assert_eq!(format!("{first:?}"), "SharedProofRng(<redacted>)");
    }

    #[test]
    fn input_collection_has_a_hard_bound() {
        assert!(collect(core::iter::empty::<()>()).is_err());
        let mut draws = 0;
        assert!(collect(std::iter::from_fn(|| {
            draws += 1;
            Some(())
        }))
        .is_err());
        assert_eq!(draws, MAX_MATRICES + 1);
    }
}

static RESEARCH_COMPACT_DATA: OnceLock<bool> = OnceLock::new();
pub(super) fn compact_prover_data() -> bool {
    *RESEARCH_COMPACT_DATA.get().unwrap_or(&false)
}

pub(super) fn host_output_budget() -> usize {
    try_host_output_budget().expect("invalid host output byte budget")
}

/// Fallible resource admission before private input decoding/preparation.
pub(super) fn try_host_output_budget() -> Result<usize, String> {
    match std::env::var("LATTICA_V2_HOST_OUTPUT_BYTES") {
        Ok(value) => value.parse().map_err(|_| "invalid host output byte budget".into()),
        Err(std::env::VarError::NotPresent) => Ok(HOST_OUTPUT_BUDGET),
        Err(_) => Err("invalid host output budget environment".into()),
    }
}

#[cfg(test)]
pub(super) fn enable_compact_for_test() {
    RESEARCH_COMPACT_DATA
        .set(true)
        .expect("isolated compact test process");
}
