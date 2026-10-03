//! Candidate-only resident commitment adapter around the pinned upstream PCS.
//! One shared CSPRNG stream feeds both this adapter and upstream quotient masks.
//! Cloning an active adapter shares its whole attempt; it never replays RNG state.
//! Fresh entropy still belongs to profile::make_proving_config, not this module.
#[cfg(feature = "stream")]
use super::normalization_workspace::HeapNormalizedDft as Dft;
use super::{
    gpu_hash::{CandidateMmcs, LdeInputShape},
    profile::{self, Challenge, ChallengeMmcs},
};
#[cfg(not(feature = "stream"))]
use crate::config::Dft;
use crate::config::Val;
use p3_commit::Mmcs;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::BasedVectorSpace;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use rand::{Rng, TryCryptoRng, TryRng};
use rand_chacha::ChaCha20Rng;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex, OnceLock},
};

type Domain = TwoAdicMultiplicativeCoset<Val>;
type Commitment = <CandidateMmcs as Mmcs<Val>>::Commitment;
type ProverData = <CandidateMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
pub(super) type ResidentInner =
    HidingFriPcs<Val, Dft, CandidateMmcs, ChallengeMmcs, SharedProofRng>;
const MAX_MATRICES: usize = 256;
pub(super) const HOST_OUTPUT_BUDGET: usize = 32 << 30;

static RESEARCH_RESIDENT: OnceLock<bool> = OnceLock::new();
static RESEARCH_OPENINGS: OnceLock<bool> = OnceLock::new();

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

/// Explicit research-runner selection only, after GPU initialization. Merely
/// setting this environment variable does not select a library backend.
pub fn initialize_research_from_env() -> Result<bool, String> {
    let value = match std::env::var("LATTICA_V2_GPU_RESIDENT_LDE") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("LATTICA_V2_GPU_RESIDENT_LDE must be ASCII 0 or 1".into())
        }
    };
    let enabled = parse_research_mode(value.as_deref()).map_err(str::to_owned)?;
    if enabled {
        super::gpu_hash::require_resident_backend()?;
    }
    let openings = match std::env::var("LATTICA_V2_GPU_OPENINGS") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "0" => false,
        Ok(value) if value == "1" => true,
        _ => return Err("LATTICA_V2_GPU_OPENINGS must be ASCII 0 or 1".into()),
    };
    if openings && !enabled {
        return Err("GPU openings require the explicit resident research backend".into());
    }
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

/// The RNG itself is moved exactly once; Clone only clones this ownership handle.
#[derive(Clone)]
pub(super) struct SharedProofRng(Arc<Mutex<ChaCha20Rng>>);
impl core::fmt::Debug for SharedProofRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedProofRng(<redacted>)")
    }
}
impl SharedProofRng {
    fn new(rng: ChaCha20Rng) -> Self {
        Self(Arc::new(Mutex::new(rng)))
    }
    fn with<T>(&self, f: impl FnOnce(&mut ChaCha20Rng) -> T) -> T {
        f(&mut self.0.lock().expect("resident hiding stream poisoned"))
    }
}
impl TryRng for SharedProofRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.with(|rng| rng.next_u32()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.with(|rng| rng.next_u64()))
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.with(|rng| rng.fill_bytes(output));
        Ok(())
    }
}
impl TryCryptoRng for SharedProofRng {}

pub(super) struct ResidentState {
    pub(super) inner: ResidentInner,
    // Only one opening backend may consume FRI randomness. This saved initial
    // stream is used exclusively when GPU openings are selected at construction;
    // active clones share this entire state rather than cloning either stream.
    opening_fri: FriParameters<ChallengeMmcs>,
    pub(super) gpu_openings: bool,
    opening_mode_locked: std::sync::atomic::AtomicBool,
    pub(super) mmcs: CandidateMmcs,
    rng: SharedProofRng,
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

impl ResidentState {
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
    pub(super) fn new(
        dft: Dft,
        mmcs: CandidateMmcs,
        fri: FriParameters<ChallengeMmcs>,
        random_columns: usize,
        rng: ChaCha20Rng,
        host_budget: usize,
    ) -> Result<Self, String> {
        if fri.log_blowup != profile::LOG_BLOWUP
            || fri.log_final_poly_len != 0
            || fri.max_log_arity != 1
            || fri.num_queries != profile::NUM_QUERIES
            || fri.commit_proof_of_work_bits != 0
            || fri.query_proof_of_work_bits != profile::QUERY_POW_BITS
            || random_columns != profile::NUM_RANDOM_CODEWORDS
            || host_budget == 0
            || host_budget > HOST_OUTPUT_BUDGET
        {
            return Err(
                "resident PCS requires unchanged candidate parameters and host allowance".into(),
            );
        }
        let committer = mmcs.share_for_resident()?;
        let log_blowup = fri.log_blowup;
        let rng = SharedProofRng::new(rng);
        let opening_fri = fri.clone();
        let inner = ResidentInner::new(dft, mmcs, fri, random_columns, rng.clone());
        Ok(Self {
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
        rounds: Vec<(&ProverData, Vec<Vec<profile::Challenge>>)>,
        challenger: &mut crate::config::Challenger,
        is_preprocessing: bool,
    ) -> (
        p3_commit::OpenedValues<profile::Challenge>,
        <ResidentInner as p3_commit::Pcs<profile::Challenge, crate::config::Challenger>>::Proof,
    ) {
        self.lock_opening_mode();
        assert!(self.gpu_openings, "GPU opening backend not selected");
        super::opening_pcs::open_hiding(
            &self.mmcs,
            &self.opening_fri,
            rounds,
            challenger,
            is_preprocessing,
            self.random_columns,
        )
    }

    pub(super) fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<Val>)>,
        preprocessing: bool,
    ) -> Result<(Commitment, ProverData), String> {
        self.lock_opening_mode();
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
        let _admission = self.mmcs.preflight_resident(&shapes, self.host_budget)?;
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
        self.mmcs
            .commit_resident(randomized, self.log_blowup, self.host_budget)
    }

    pub(super) fn randomization(
        &self,
        domains: impl IntoIterator<Item = Domain>,
    ) -> Result<(Commitment, ProverData), String> {
        self.lock_opening_mode();
        let domains = collect(domains)?;
        let width = self.random_columns + <Challenge as BasedVectorSpace<Val>>::DIMENSION;
        let shapes: Vec<_> = domains
            .iter()
            .map(|domain| LdeInputShape {
                height: domain.size(),
                width,
                added_bits: self.log_blowup,
            })
            .collect();
        let _admission = self.mmcs.preflight_resident(&shapes, self.host_budget)?;
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
        self.mmcs
            .commit_resident(randomized, self.log_blowup, self.host_budget)
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
