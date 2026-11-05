//! Bounded CPU transaction generation. Only public output survives each call.
//! The reference uses process-global scratch, so all calls share NATIVE_LOCK.
use super::{sizes, FixtureAmounts, NativeError, NATIVE_LOCK, RING_PAIRS, VALUE_LIMIT};
use serde::Serialize;
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, rc::Rc, time::Instant};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_attempts: u64,
    pub random_call_limit: u64,
    pub proposal_limit: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_attempts: 1024,
            random_call_limit: 1 << 24,
            proposal_limit: 1 << 28,
        }
    }
}
impl Limits {
    fn valid(self) -> bool {
        (1..=1024).contains(&self.max_attempts)
            && (1..=1 << 24).contains(&self.random_call_limit)
            && (1..=1 << 28).contains(&self.proposal_limit)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct Statistics {
    pub parameters_ns: u64,
    pub inputs_ns: u64,
    pub spend_ns: u64,
    pub encoding_ns: u64,
    pub cleanup_ns: u64,
    pub attempts: u64,
    pub random_calls: u64,
    pub random_blocks: u64,
    pub proposals: u64,
    pub parameter_cache_hits: u64,
    /// 0 success; 1 native failure; 2 attempts; 3 RNG; 4 proposals; 5 entropy.
    pub status: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    pub cache_public_parameters: bool,
    /// AES blocks interleaved per group. Supports 1, 4 and 8 only.
    pub aes_lanes: u32,
    pub limits: Limits,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            cache_public_parameters: false,
            aes_lanes: 1,
            limits: Limits::default(),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Native(NativeError),
    InvalidConfiguration,
    Refused(Statistics),
}
impl From<NativeError> for Error {
    fn from(error: NativeError) -> Self {
        Self::Native(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(error) => error.fmt(f),
            Self::InvalidConfiguration => f.write_str("invalid CPU generation configuration"),
            Self::Refused(stats) => write!(f, "CPU generation refused (status {})", stats.status),
        }
    }
}
impl std::error::Error for Error {}

/// Unverified public output. The consumer must independently verify it.
#[derive(Debug)]
pub struct Output {
    pub statement: Vec<u8>,
    pub proof: Vec<u8>,
    pub statistics: Statistics,
    /// Includes allocation, native setup/keygen/mint/spend/encoding and cleanup.
    /// The caller measures owner construction, verification and retirement too.
    pub generation_ns: u64,
}

extern "C" {
    fn lattica_cpu_generation_bytes() -> usize;
    fn lattica_cpu_generation_new(
        seed: *const u8,
        context: *const u8,
        cache: u32,
        lanes: u32,
    ) -> *mut c_void;
    fn lattica_cpu_generation_free(owner: *mut c_void);
    fn lattica_cpu_generation_spend(
        owner: *mut c_void,
        index: u64,
        in0: u64,
        in1: u64,
        out0: u64,
        out1: u64,
        limits: Limits,
        statement: *mut u8,
        statement_len: usize,
        proof: *mut u8,
        proof_len: usize,
        statistics: *mut Statistics,
    ) -> i32;
}

/// One bounded workspace and at most one public setup cache entry. Private
/// state is erased after every call, including refusals. No GPU is initialized.
pub struct Generator {
    owner: NonNull<c_void>,
    config: Configuration,
    // Never move a reference generator between workers. C still takes the
    // process lock so separate owners cannot race the shared native scratch.
    _not_send_sync: PhantomData<Rc<()>>,
}
impl Generator {
    pub fn allocation_bytes() -> Result<usize, Error> {
        sizes()?;
        // Constant sizeof; does not touch native state.
        Ok(unsafe { lattica_cpu_generation_bytes() })
    }
    pub fn new(seed: [u8; 32], context: [u8; 32], config: Configuration) -> Result<Self, Error> {
        sizes()?;
        if !matches!(config.aes_lanes, 1 | 4 | 8) || !config.limits.valid() {
            return Err(Error::InvalidConfiguration);
        }
        let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
        let owner = NonNull::new(unsafe {
            lattica_cpu_generation_new(
                seed.as_ptr(),
                context.as_ptr(),
                config.cache_public_parameters.into(),
                config.aes_lanes,
            )
        })
        .ok_or(NativeError::NativeFailure)?;
        Ok(Self {
            owner,
            config,
            _not_send_sync: PhantomData,
        })
    }
    pub fn generate(&mut self, index: u64, amounts: FixtureAmounts) -> Result<Output, Error> {
        let start = Instant::now();
        if index >= RING_PAIRS
            || amounts
                .input
                .iter()
                .chain(&amounts.output)
                .any(|&x| x >= VALUE_LIMIT)
            || amounts.input.iter().sum::<u64>() != amounts.output.iter().sum::<u64>()
        {
            return Err(NativeError::InvalidWitness.into());
        }
        let (statement_len, proof_len) = sizes()?;
        let mut statement = vec![0; statement_len];
        let mut proof = vec![0; proof_len];
        let mut statistics = Statistics::default();
        let _guard = NATIVE_LOCK.lock().map_err(|_| NativeError::Poisoned)?;
        let result = unsafe {
            lattica_cpu_generation_spend(
                self.owner.as_ptr(),
                index,
                amounts.input[0],
                amounts.input[1],
                amounts.output[0],
                amounts.output[1],
                self.config.limits,
                statement.as_mut_ptr(),
                statement.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut statistics,
            )
        };
        if result != 1 {
            return Err(Error::Refused(statistics));
        }
        Ok(Output {
            statement,
            proof,
            statistics,
            generation_ns: nanos(start),
        })
    }
}
impl Drop for Generator {
    fn drop(&mut self) {
        // A poisoned Rust lock must not prevent erasure of owned secrets.
        let _guard = NATIVE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            lattica_cpu_generation_free(self.owner.as_ptr());
        }
    }
}
fn nanos(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

#[cfg(all(test, feature = "native-generation-oracle"))]
mod tests;
