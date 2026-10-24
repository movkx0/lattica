//! Evidence and cost gates for experiments; this module proves no cryptographic claim.
//!
//! A native verifier benchmark cannot establish recursive-verifier cost. Likewise,
//! reducing active rows does not establish a smaller padded proving domain. Keep
//! those distinctions in measurement records before comparing elapsed times.

use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::{fmt, fs, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CostError(pub String);

impl fmt::Display for CostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CostError {}

fn require(condition: bool, message: &str) -> Result<(), CostError> {
    if condition {
        Ok(())
    } else {
        Err(CostError(message.into()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasurementKind {
    NativeProve,
    NativeVerify,
    FirstRecursiveWrapper,
    FullBlockAggregation,
}

impl MeasurementKind {
    fn is_recursive(self) -> bool {
        matches!(
            self,
            Self::FirstRecursiveWrapper | Self::FullBlockAggregation
        )
    }
}

/// A statement about data supplied to the measured operation, not a ZK proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessAccess {
    PublicArtifactsOnly,
    WalletSecrets,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheState {
    Cold,
    Warm,
    ExistingUncontrolled,
}

/// Individual clocks cannot be compared when any included phase differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingBoundary {
    pub includes_wallet_generation: bool,
    pub includes_program_compilation: bool,
    pub includes_preprocessing: bool,
    pub includes_serialization: bool,
    pub includes_independent_verification: bool,
    pub includes_host_application: bool,
    pub cache_state: CacheState,
}

/// These are matched requirements, not a certificate that either scheme meets them.
/// `review_reference` must identify the supporting argument separately per scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityRequirements {
    pub target_bits: u16,
    pub adversary_model: String,
    pub assurance_level: String,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    pub capacity: u32,
    pub entries: u32,
    pub user_entries: u32,
    pub issuance_entries: u32,
    /// Binds input/output counts, anonymity requirement and supported statements.
    pub statement_contract: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionEnvironment {
    /// Stable hardware identity; a marketing GPU name alone is insufficient.
    pub hardware_id: String,
    pub backend: String,
    pub cpu_threads: u32,
    pub concurrent_workers: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub active_rows: u64,
    pub padded_rows: u64,
}

impl Geometry {
    pub fn validate(self) -> Result<(), CostError> {
        require(self.active_rows > 0, "active rows must be positive")?;
        require(
            self.padded_rows.is_power_of_two(),
            "padded rows must be a power of two",
        )?;
        require(
            self.active_rows <= self.padded_rows,
            "active rows exceed padded domain",
        )
    }
}

/// Bytes actually published in the chosen wire format. All fields are separate
/// so a proof allowance cannot accidentally be presented as a full-block limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayloadBytes {
    pub proof: u64,
    pub public_body: u64,
    pub encrypted_outputs: u64,
    pub framing: u64,
}

impl PayloadBytes {
    pub fn total(self) -> Result<u64, CostError> {
        [
            self.proof,
            self.public_body,
            self.encrypted_outputs,
            self.framing,
        ]
        .into_iter()
        .try_fold(0u64, |sum, n| sum.checked_add(n))
        .ok_or_else(|| CostError("payload byte count overflow".into()))
    }

    /// Repeat *unaggregated* transaction payloads. This does not model compression.
    pub fn repeat(self, entries: u32) -> Result<Self, CostError> {
        require(entries > 0, "entry count must be positive")?;
        let multiply = |n: u64| {
            n.checked_mul(u64::from(entries))
                .ok_or_else(|| CostError("payload byte count overflow".into()))
        };
        let result = Self {
            proof: multiply(self.proof)?,
            public_body: multiply(self.public_body)?,
            encrypted_outputs: multiply(self.encrypted_outputs)?,
            framing: multiply(self.framing)?,
        };
        result.total()?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockBudget {
    pub proof_limit: u64,
    /// None means no full-block limit has been supplied; it does not mean zero.
    pub total_limit: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetDecision {
    pub total_bytes: u64,
    pub proof_fits: bool,
    pub total_fits: Option<bool>,
}

impl BlockBudget {
    pub fn evaluate(self, bytes: PayloadBytes) -> Result<BudgetDecision, CostError> {
        require(self.proof_limit > 0, "proof allowance must be positive")?;
        if let Some(total) = self.total_limit {
            require(total > 0, "total allowance must be positive")?;
        }
        let total_bytes = bytes.total()?;
        Ok(BudgetDecision {
            total_bytes,
            proof_fits: bytes.proof <= self.proof_limit,
            total_fits: self.total_limit.map(|limit| total_bytes <= limit),
        })
    }

    pub fn per_transaction_proof_allowance(self, entries: u32) -> Result<u64, CostError> {
        require(entries > 0, "entry count must be positive")?;
        require(self.proof_limit > 0, "proof allowance must be positive")?;
        Ok(self.proof_limit / u64::from(entries))
    }
}

#[derive(Clone, Debug)]
pub struct Measurement {
    pub kind: MeasurementKind,
    /// Identifies the actual inner construction, parameters and source revision.
    pub scheme_profile: String,
    /// Pinned outer proof-system parameters, required for recursive measurements.
    /// This is not the leaf registry/key identity: that changes with the program
    /// and belongs in `scheme_profile` and `verification_reference` instead.
    pub outer_profile: Option<String>,
    pub security: SecurityRequirements,
    pub workload: Workload,
    pub environment: ExecutionEnvironment,
    pub timing: TimingBoundary,
    pub witness_access: WitnessAccess,
    pub geometry: Option<Geometry>,
    pub payload: PayloadBytes,
    pub median_seconds: f64,
    pub measured_samples: u32,
    pub peak_host_bytes: u64,
    pub peak_device_bytes: u64,
    /// Artifact reference for independently replayable correctness evidence.
    pub verification_reference: String,
}

impl Measurement {
    pub fn validate(&self) -> Result<(), CostError> {
        require(
            !self.scheme_profile.trim().is_empty(),
            "missing scheme profile",
        )?;
        require(self.security.target_bits > 0, "missing security target")?;
        for value in [
            &self.security.adversary_model,
            &self.security.assurance_level,
            &self.security.review_reference,
            &self.workload.statement_contract,
            &self.environment.hardware_id,
            &self.environment.backend,
            &self.verification_reference,
        ] {
            require(
                !value.trim().is_empty(),
                "missing measurement identity or evidence",
            )?;
        }
        require(
            self.workload.entries > 0 && self.workload.entries <= self.workload.capacity,
            "entries must be positive and fit capacity",
        )?;
        let classified = self
            .workload
            .user_entries
            .checked_add(self.workload.issuance_entries)
            .ok_or_else(|| CostError("workload count overflow".into()))?;
        require(
            classified == self.workload.entries,
            "workload entry classes do not sum to entries",
        )?;
        require(
            self.environment.cpu_threads > 0 && self.environment.concurrent_workers > 0,
            "execution resources must be positive",
        )?;
        require(
            self.median_seconds.is_finite() && self.median_seconds > 0.0,
            "measurement duration must be finite and positive",
        )?;
        require(self.measured_samples > 0, "measurement has no samples")?;
        self.payload.total()?;
        if let Some(geometry) = self.geometry {
            geometry.validate()?;
        }
        if self.kind.is_recursive() {
            require(
                self.witness_access == WitnessAccess::PublicArtifactsOnly,
                "aggregation must consume public artifacts, never wallet secrets",
            )?;
            require(
                self.geometry.is_some(),
                "recursive measurement lacks circuit geometry",
            )?;
            require(
                self.outer_profile
                    .as_ref()
                    .is_some_and(|p| !p.trim().is_empty()),
                "recursive measurement lacks pinned outer profile",
            )?;
            require(
                !self.timing.includes_wallet_generation,
                "aggregation timing cannot include private wallet witness generation",
            )?;
            require(
                self.payload.proof > 0,
                "recursive measurement lacks output proof bytes",
            )?;
        }
        if self.kind == MeasurementKind::NativeVerify {
            require(
                self.witness_access == WitnessAccess::PublicArtifactsOnly,
                "native verification must use public artifacts",
            )?;
            require(
                !self.timing.includes_wallet_generation,
                "native verification timing cannot include wallet generation",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Comparison {
    /// Baseline duration / candidate duration for this exact matched scope only.
    pub observed_time_ratio: f64,
    pub proof_bytes_reduced: bool,
    pub total_bytes_reduced: bool,
    pub active_rows_reduced: Option<bool>,
    pub padded_domain_reduced: Option<bool>,
}

/// This returns an observed ratio, never a production readiness or security verdict.
/// Different schemes may have different security arguments but must claim the same
/// target/model/assurance, and recursive experiments must pin the same outer profile.
pub fn compare(baseline: &Measurement, candidate: &Measurement) -> Result<Comparison, CostError> {
    baseline.validate()?;
    candidate.validate()?;
    require(
        baseline.kind == candidate.kind,
        "measurement scope mismatch",
    )?;
    require(
        baseline.security.target_bits == candidate.security.target_bits
            && baseline.security.adversary_model == candidate.security.adversary_model
            && baseline.security.assurance_level == candidate.security.assurance_level,
        "security requirements mismatch",
    )?;
    require(
        baseline.workload == candidate.workload,
        "capacity or workload mismatch",
    )?;
    require(
        baseline.environment == candidate.environment,
        "execution environment mismatch",
    )?;
    require(
        baseline.timing == candidate.timing,
        "timing boundary mismatch",
    )?;
    require(
        baseline.witness_access == candidate.witness_access,
        "witness access mismatch",
    )?;
    require(
        baseline.outer_profile == candidate.outer_profile,
        "outer verifier profile mismatch",
    )?;
    let geometry = baseline.geometry.zip(candidate.geometry);
    require(
        baseline.geometry.is_some() == candidate.geometry.is_some(),
        "geometry scope mismatch",
    )?;
    let ratio = baseline.median_seconds / candidate.median_seconds;
    require(
        ratio.is_finite() && ratio > 0.0,
        "time ratio is not representable",
    )?;
    Ok(Comparison {
        observed_time_ratio: ratio,
        proof_bytes_reduced: candidate.payload.proof < baseline.payload.proof,
        total_bytes_reduced: candidate.payload.total()? < baseline.payload.total()?,
        active_rows_reduced: geometry.map(|(a, b)| b.active_rows < a.active_rows),
        padded_domain_reduced: geometry.map(|(a, b)| b.padded_rows < a.padded_rows),
    })
}

/// Conditional work model only. `wrapper_share` must be the measured fraction of
/// total work in wrappers, not their fraction of proof jobs. This does not predict
/// wall-clock latency, shared-domain resizing or a new aggregation architecture.
pub fn conditional_aggregation_speedup(
    wrapper_share: f64,
    wrapper_speedup: f64,
) -> Result<f64, CostError> {
    require(
        wrapper_share.is_finite() && (0.0..=1.0).contains(&wrapper_share),
        "wrapper work share must lie between zero and one",
    )?;
    require(
        wrapper_speedup.is_finite() && wrapper_speedup > 0.0,
        "wrapper speedup must be finite and positive",
    )?;
    let result = 1.0 / ((1.0 - wrapper_share) + wrapper_share / wrapper_speedup);
    require(
        result.is_finite() && result > 0.0,
        "conditional speedup is not representable",
    )?;
    Ok(result)
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedFact {
    pub label: String,
    pub pointer: String,
    pub value: Value,
}

/// Historical observations stay separate from fully matched `Measurement`s.
/// A catalog item cannot establish a speedup by itself.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedBaseline {
    pub id: String,
    pub profile: String,
    pub scope: String,
    pub source_path: String,
    pub source_sha3_256: String,
    pub exclusions: Vec<String>,
    pub facts: Vec<VerifiedFact>,
}

pub const BASELINE_MANIFEST: &str = include_str!("../data/baselines.json");

fn string_field(value: &Value, key: &str) -> Result<String, CostError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CostError(format!("missing string field {key}")))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, CostError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| CostError(format!("missing array field {key}")))
}

/// Read pinned historical sources and check both their complete content digest
/// and each recorded JSON-pointer value. Never re-label these records as a matched
/// candidate benchmark. `repo_root` should be the isolated research worktree.
pub fn read_baselines(
    repo_root: &Path,
    manifest: &str,
) -> Result<Vec<VerifiedBaseline>, CostError> {
    let manifest: Value = serde_json::from_str(manifest)
        .map_err(|e| CostError(format!("baseline manifest JSON: {e}")))?;
    require(
        string_field(&manifest, "schema")? == "lattica-pq-ringct-cost-baselines-v1",
        "unknown baseline schema",
    )?;
    require(
        string_field(&manifest, "hash_algorithm")? == "sha3-256",
        "unknown provenance hash",
    )?;
    let records = array_field(&manifest, "records")?;
    require(!records.is_empty(), "empty baseline manifest")?;
    let mut result = Vec::new();
    for record in records {
        let source_path = string_field(record, "source_path")?;
        let path = Path::new(&source_path);
        require(
            path.components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
            "baseline source path must be relative without traversal",
        )?;
        let bytes = fs::read(repo_root.join(path))
            .map_err(|e| CostError(format!("read {source_path}: {e}")))?;
        let expected_hash = string_field(record, "source_sha3_256")?;
        let actual_hash = format!("{:x}", Sha3_256::digest(&bytes));
        require(
            expected_hash == actual_hash,
            "baseline source provenance hash mismatch",
        )?;
        let source: Value = serde_json::from_slice(&bytes)
            .map_err(|e| CostError(format!("source {source_path} JSON: {e}")))?;
        let mut facts = Vec::new();
        for fact in array_field(record, "facts")? {
            let pointer = string_field(fact, "pointer")?;
            let value = source
                .pointer(&pointer)
                .ok_or_else(|| CostError(format!("missing source pointer {pointer}")))?;
            let expected = fact
                .get("value")
                .ok_or_else(|| CostError(format!("missing expected value at {pointer}")))?;
            require(value == expected, "baseline fact does not match source")?;
            facts.push(VerifiedFact {
                label: string_field(fact, "label")?,
                pointer,
                value: value.clone(),
            });
        }
        require(!facts.is_empty(), "baseline has no facts")?;
        let exclusions = array_field(record, "exclusions")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| CostError("invalid baseline exclusion".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        require(!exclusions.is_empty(), "baseline lacks scope exclusions")?;
        let id = string_field(record, "id")?;
        require(
            !result.iter().any(|r: &VerifiedBaseline| r.id == id),
            "duplicate baseline id",
        )?;
        result.push(VerifiedBaseline {
            id,
            profile: string_field(record, "profile")?,
            scope: string_field(record, "scope")?,
            source_path,
            source_sha3_256: expected_hash,
            exclusions,
            facts,
        });
    }
    Ok(result)
}
