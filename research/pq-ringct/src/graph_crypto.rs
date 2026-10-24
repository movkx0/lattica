//! Bounded provisioning of the seven full MatRiCT AES/SHAKE requests.
//!
//! Native inputs are witness hints, never validity receipts. Every produced or
//! cached segment is a real STARK for its exact registered descriptor/phase.
//! Graph leaves must still verify the complete component tree and all producer
//! joins. Planning, resource estimates and native cache checks do not discharge
//! any SourceBinding obligation.
use crate::{
    aes_lane_air::{
        self,
        join::{AesLanePartition, AesLaneSegmentProof},
    },
    graph_tree,
    rust_verify::committed_backend::{Operation, UnprovedRelationGraph},
    shake_air::{
        self,
        lane::{batch::ShakeBatchPartition, LaneShakeProof},
    },
};
use lattica_prover_p3::block_v2::{machine::program::Val, profile};
use p3_air::BaseAir;
use sha3::{Digest, Sha3_256};

mod cache;
mod factory;
mod layout;
mod preparation;
mod prover;
mod retention;
mod shake_wrappers;
mod wide;
mod wide_aes;
pub use crate::component_tree::WideAesProof;
pub use crate::outer_cache::ProofCache as OuterProofCache;
pub use cache::{
    CacheOutcome, ProofCache, SerialArchiveImport, WideAesArchiveImport, WideAesCacheOutcome,
    WideArchiveImport, WideCacheOutcome,
};
pub use layout::{LayoutComparison, LayoutGeometry, WideShakePartitionEstimate};
pub use prover::{CompleteRequestProof, NodeProvingReport, RequestProver, RequestProvingReport};
pub use retention::{NativeRetentionShape, RetainedNativeChild};
pub use shake_wrappers::{
    ShakeWrapperCounts, ShakeWrapperLayout, ShakeWrapperSchedule, ShakeWrapperSpan,
};
pub use wide::WideShakeFactory;
pub use wide_aes::WideAesFactory;
#[cfg(all(test, feature = "native-trace-audit"))]
mod gpu_tests;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn err(e: impl std::fmt::Debug) -> Error {
    Error(format!("{e:?}"))
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}

/// Performance admission only: neither mode changes the cryptographic profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Existing local evidence covers native batches through eight units.
    ValidatedLocal,
    /// Larger batches are estimates for explicitly guarded experiments or
    /// production workers. They are not claims of measured peak memory.
    Estimated,
}
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub maximum_aes_blocks: usize,
    pub maximum_shake_permutations: usize,
    pub child_memory_budget_bytes: u64,
    pub admission: Admission,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            maximum_aes_blocks: 8,
            maximum_shake_permutations: 8,
            child_memory_budget_bytes: 8 << 30,
            admission: Admission::ValidatedLocal,
        }
    }
}
impl Policy {
    fn validate(self) -> Result<Self> {
        require(
            [self.maximum_aes_blocks, self.maximum_shake_permutations]
                .into_iter()
                .all(|n| n.is_power_of_two() && n <= 64),
            "crypto candidate batch sizes must be powers of two in1..=64",
        )?;
        require(
            self.child_memory_budget_bytes != 0,
            "zero crypto child memory budget",
        )?;
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDescriptor {
    Aes(aes_lane_air::Descriptor),
    Shake(shake_air::Descriptor),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentInfo {
    pub first_unit: usize,
    pub units: usize,
    pub width: usize,
    pub height: usize,
    pub raw_trace_bytes: u64,
    pub estimated_peak_bytes: u64,
    pub within_previously_measured_batch_size: bool,
}
/// Conservative planning heuristic, not a bound or measured peak. It exceeds
/// the retained eight-unit AES/SHAKE test peaks. Outer wrapper and parent STARK
/// memory must be planned separately. Runtime processes still need OS guards.
fn estimate(first_unit: usize, units: usize, width: usize, height: usize) -> Result<SegmentInfo> {
    let raw = (width as u64)
        .checked_mul(height as u64)
        .and_then(|n| n.checked_mul(8))
        .ok_or_else(|| Error("crypto trace size overflow".into()))?;
    let peak = raw
        .checked_mul(48)
        .and_then(|n| n.checked_add(512 << 20))
        .ok_or_else(|| Error("crypto memory estimate overflow".into()))?;
    Ok(SegmentInfo {
        first_unit,
        units,
        width,
        height,
        raw_trace_bytes: raw,
        estimated_peak_bytes: peak,
        within_previously_measured_batch_size: units <= 8,
    })
}
enum Payload {
    Aes([u8; 32]),
    Shake(Vec<u8>),
}
enum Partition {
    Aes(AesLanePartition),
    Shake(ShakeBatchPartition),
}
pub struct Request {
    operation: usize,
    subrequest: u32,
    index: u32,
    profile: [u8; 32],
    descriptor: RequestDescriptor,
    payload: Payload,
    partition: Partition,
    segments: Vec<SegmentInfo>,
    memory_budget: u64,
}
pub enum SegmentArtifact {
    Aes(AesLaneSegmentProof),
    Shake(LaneShakeProof),
}
impl SegmentArtifact {
    pub fn public_values(&self) -> &[Val] {
        match self {
            Self::Aes(a) => &a.public_values,
            Self::Shake(a) => &a.public_values,
        }
    }
    fn proof(&self) -> &p3_uni_stark::Proof<profile::Config> {
        match self {
            Self::Aes(a) => &a.proof,
            Self::Shake(a) => &a.proof,
        }
    }
}
impl Request {
    pub fn operation_index(&self) -> usize {
        self.operation
    }
    pub fn subrequest(&self) -> u32 {
        self.subrequest
    }
    pub fn request_index(&self) -> u32 {
        self.index
    }
    pub fn descriptor(&self) -> RequestDescriptor {
        self.descriptor
    }
    pub fn segments(&self) -> &[SegmentInfo] {
        &self.segments
    }
    pub fn units(&self) -> usize {
        self.segments.iter().map(|s| s.units).sum()
    }
    pub fn maximum_segment_units(&self) -> usize {
        self.segments.iter().map(|s| s.units).max().unwrap_or(0)
    }
    pub fn contract(&self) -> Result<crate::component_tree::Contract> {
        match self.descriptor {
            RequestDescriptor::Aes(d) => {
                crate::component_tree::Contract::aes(self.profile, self.index, d)
            }
            RequestDescriptor::Shake(d) => {
                crate::component_tree::Contract::shake(self.profile, self.index, d)
            }
        }
        .map_err(err)
    }
    pub fn aes_partition(&self) -> Option<&AesLanePartition> {
        match &self.partition {
            Partition::Aes(a) => Some(a),
            _ => None,
        }
    }
    pub fn shake_partition(&self) -> Option<&ShakeBatchPartition> {
        match &self.partition {
            Partition::Shake(a) => Some(a),
            _ => None,
        }
    }
    fn new(
        profile: [u8; 32],
        operation: usize,
        subrequest: u32,
        descriptor: RequestDescriptor,
        payload: Payload,
        policy: Policy,
    ) -> Result<Self> {
        require(subrequest <= 1, "crypto subrequest index")?;
        let index = u32::try_from(operation)
            .map_err(err)?
            .checked_mul(2)
            .and_then(|n| n.checked_add(subrequest))
            .ok_or_else(|| Error("crypto request index overflow".into()))?;
        let requested = match descriptor {
            RequestDescriptor::Aes(_) => policy.maximum_aes_blocks,
            RequestDescriptor::Shake(_) => policy.maximum_shake_permutations,
        };
        let mut maximum = if policy.admission == Admission::ValidatedLocal {
            requested.min(8)
        } else {
            requested
        };
        loop {
            let (partition, segments) = match descriptor {
                RequestDescriptor::Aes(d) => {
                    let partition = AesLanePartition::new(d, maximum).map_err(err)?;
                    let segments = partition
                        .segments()
                        .iter()
                        .map(|a| estimate(a.first_block, a.blocks, aes_lane_air::WIDTH, a.height))
                        .collect::<Result<Vec<_>>>()?;
                    (Partition::Aes(partition), segments)
                }
                RequestDescriptor::Shake(d) => {
                    let partition = ShakeBatchPartition::new(d, maximum).map_err(err)?;
                    let segments = partition
                        .segments()
                        .iter()
                        .map(|a| {
                            estimate(
                                a.first_permutation(),
                                a.permutations(),
                                a.width(),
                                a.height(),
                            )
                        })
                        .collect::<Result<Vec<_>>>()?;
                    (Partition::Shake(partition), segments)
                }
            };
            if segments
                .iter()
                .all(|s| s.estimated_peak_bytes <= policy.child_memory_budget_bytes)
            {
                return Ok(Self {
                    operation,
                    subrequest,
                    index,
                    profile,
                    descriptor,
                    payload,
                    partition,
                    segments,
                    memory_budget: policy.child_memory_budget_bytes,
                });
            }
            require(
                maximum > 1,
                "smallest crypto segment exceeds estimated child memory budget",
            )?;
            maximum /= 2;
        }
    }
    /// Cache lookup identity only. Loading must still verify the actual proof,
    /// exact height and public endpoint values for this registered request.
    pub fn cache_key(&self, segment: usize) -> Result<[u8; 32]> {
        let info = self
            .segments
            .get(segment)
            .ok_or_else(|| Error("crypto segment index".into()))?;
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/crypto-child-cache/v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update(self.profile);
        hash.update(self.index.to_le_bytes());
        let descriptor = match self.descriptor {
            RequestDescriptor::Aes(d) => {
                vec![1, d.domain, u64::from(d.start_counter), d.output_len as u64]
            }
            RequestDescriptor::Shake(d) => vec![2, d.input_len as u64, d.output_len as u64],
        };
        hash.update((descriptor.len() as u64).to_le_bytes());
        for field in descriptor {
            hash.update(field.to_le_bytes());
        }
        for field in [
            segment,
            info.first_unit,
            info.units,
            info.width,
            info.height,
        ] {
            hash.update((field as u64).to_le_bytes());
        }
        let payload: &[u8] = match &self.payload {
            Payload::Aes(key) => key,
            Payload::Shake(input) => input,
        };
        hash.update((payload.len() as u64).to_le_bytes());
        hash.update(payload);
        Ok(hash.finalize().into())
    }
}

pub struct Plan {
    requests: Vec<Request>,
    policy: Policy,
}
impl Plan {
    pub fn new(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        policy: Policy,
    ) -> Result<Self> {
        let _ = tree.node_manifest_hint(graph).map_err(err)?;
        Self::from_trusted_metadata(tree, graph, policy, |seed, context| {
            Ok(crate::transcript_bridge::pp_input_bytes(seed, context))
        })
    }
    fn from_trusted_metadata(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        policy: Policy,
        pp_input: impl Fn(&[u8; 32], &[u8; 32]) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let policy = policy.validate()?;
        let profile = tree.label();
        let mut requests = Vec::new();
        for (index, operation) in graph.operations().iter().enumerate() {
            match operation {
                Operation::ParametersPp {
                    setup_seed,
                    context,
                    ..
                } => {
                    require(
                        *setup_seed == graph.setup_seed(),
                        "parameter setup differs from registered graph",
                    )?;
                    let input = pp_input(setup_seed, &graph.byte_string(*context).values)?;
                    requests.push(Request::new(
                        profile,
                        index,
                        0,
                        RequestDescriptor::Shake(shake_air::Descriptor {
                            input_len: input.len(),
                            output_len: 32,
                        }),
                        Payload::Shake(input),
                        policy,
                    )?);
                }
                Operation::SampleG { seed, .. } => requests.push(Request::new(
                    profile,
                    index,
                    0,
                    RequestDescriptor::Aes(aes_lane_air::Descriptor {
                        domain: 0,
                        start_counter: 0,
                        output_len: crate::uniform_air::Kind::SampleG4.draws() * 4,
                    }),
                    Payload::Aes(graph.byte_string(*seed).values),
                    policy,
                )?),
                Operation::ExpandAlpha { seed, .. } => {
                    let key = graph.byte_string(*seed).values;
                    for (subrequest, start_counter, output_len) in [
                        (0, 0, crate::uniform_air::Kind::ExpandAlpha2.draws() * 4),
                        (1, 161, 127),
                    ] {
                        requests.push(Request::new(
                            profile,
                            index,
                            subrequest,
                            RequestDescriptor::Aes(aes_lane_air::Descriptor {
                                domain: 0x4368,
                                start_counter,
                                output_len,
                            }),
                            Payload::Aes(key),
                            policy,
                        )?);
                    }
                }
                Operation::HashAlpha { .. } | Operation::HashX { .. } => {
                    let (air, values, _) =
                        crate::transcript_air::TranscriptAir::from_graph_operation(
                            graph, operation,
                        )
                        .map_err(err)?;
                    let input = air.serialize(&values).map_err(err)?;
                    let output_len = if matches!(operation, Operation::HashAlpha { .. }) {
                        32
                    } else {
                        137
                    };
                    requests.push(Request::new(
                        profile,
                        index,
                        0,
                        RequestDescriptor::Shake(shake_air::Descriptor {
                            input_len: input.len(),
                            output_len,
                        }),
                        Payload::Shake(input),
                        policy,
                    )?);
                }
                _ => {}
            }
        }
        require(
            requests.len() == 7,
            "full MatRiCT graph must have seven AES/SHAKE requests",
        )?;
        Ok(Self { requests, policy })
    }
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }
    pub fn policy(&self) -> Policy {
        self.policy
    }
    pub fn native_child_count(&self) -> usize {
        self.requests.iter().map(|r| r.segments.len()).sum()
    }
}

#[cfg(all(test, feature = "opencl"))]
mod raw_gpu_tests;
