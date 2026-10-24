//! Typed recursive endpoint trees for AES/SHAKE component proofs.
//!
//! This is not a MatRiCT acceptance predicate. A transaction coordinator must
//! authenticate every request against the arithmetic obligation manifest and
//! canonical statement. Constructors here pin the actual component AIR and
//! recursively check every child proof and every endpoint equality.
use crate::{aes_lane_air, shake_air};
use lattica_prover_p3::block_v2::{
    commitment,
    machine::{
        analysis,
        backend::{RegisteredProgram, RegisteredVerifier},
        program::{ConstructionCounters, ConstructionLimits, ExecutionError, Val, Wire},
        verifier::{self, ProofInputs},
        MachineAir, Program, ProgramBuilder,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof;
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::sync::Arc;

mod cache;
pub use crate::outer_cache::ProofCache as OuterProofCache;
pub use cache::CacheOutcome;

mod retention;
mod shake_compile_memory;
pub use shake_compile_memory::{ShakeGroupCompileFootprint, ShakeGroupFootprintError};
mod preparation;
use preparation::with_endpoint_preparation;
mod wide;
pub use wide::{compile_wide_shake, compile_wide_shake_with_context};
mod wide_aes;
pub use wide_aes::{compile_wide_aes, compile_wide_aes_with_context, WideAesProof};

pub const CONTEXT: usize = 8;
pub const STATEMENT: usize = 16;
pub const EXPECTED_INPUT: usize = 20;
pub const EXPECTED_OUTPUT: usize = 24;
const KIND: usize = 28;
const REQUEST: usize = 29;
const FIRST: usize = 30;
const COUNT: usize = 31;
const TOTAL: usize = 32;
const LEVEL: usize = 33;
const DESCRIPTOR: usize = 34;
pub const HEADER: usize = 38;
const CONTRACT_DOMAIN: u64 = 0x43545245455f5631;
const ENDPOINT_DOMAIN: u64 = 0x43545245455f4531;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
type Result<T> = std::result::Result<T, Error>;
fn err(value: impl std::fmt::Debug) -> Error {
    Error(format!("{value:?}"))
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Shake(shake_air::Descriptor),
    Aes(aes_lane_air::Descriptor),
}

/// Fixed registration data, never chosen by an unauthenticated proof header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    profile: [u8; 32],
    request: u32,
    kind: Kind,
    total: u32,
}
impl Contract {
    pub fn shake(
        profile: [u8; 32],
        request: u32,
        descriptor: shake_air::Descriptor,
    ) -> Result<Self> {
        let total = u32::try_from(descriptor.permutations().map_err(err)?).map_err(err)?;
        require(total != 0, "empty SHAKE contract")?;
        shake_air::lane::LaneShakeAir::new(descriptor, 0).map_err(err)?;
        Ok(Self {
            profile,
            request,
            kind: Kind::Shake(descriptor),
            total,
        })
    }
    pub fn aes(
        profile: [u8; 32],
        request: u32,
        descriptor: aes_lane_air::Descriptor,
    ) -> Result<Self> {
        aes_lane_air::AesLaneAir::new(descriptor).map_err(err)?;
        Ok(Self {
            profile,
            request,
            kind: Kind::Aes(descriptor),
            total: u32::try_from(descriptor.blocks()).map_err(err)?,
        })
    }
    fn boundary_width(&self) -> usize {
        match self.kind {
            Kind::Shake(_) => 108,
            Kind::Aes(_) => 4,
        }
    }
    fn tag(&self) -> u64 {
        match self.kind {
            Kind::Shake(_) => 1,
            Kind::Aes(_) => 2,
        }
    }
    fn descriptor_root(&self) -> Result<[Val; 4]> {
        let mut fields = vec![self.tag(), u64::from(self.total)];
        match self.kind {
            Kind::Shake(d) => fields.extend([d.input_len as u64, d.output_len as u64]),
            Kind::Aes(d) => fields.extend([
                d.domain & 0xffff_ffff,
                d.domain >> 32,
                u64::from(d.start_counter),
                d.output_len as u64,
            ]),
        }
        Ok(commitment::hash_fields(CONTRACT_DOMAIN, &fields)
            .map_err(err)?
            .map(Val::from_u64))
    }
    fn span(&self, first: u32, count: u32) -> Result<Spec> {
        let end = first
            .checked_add(count)
            .ok_or_else(|| Error("component interval overflow".into()))?;
        require(
            count > 0 && end <= self.total,
            "component interval outside request",
        )?;
        Ok(Spec {
            contract: self.clone(),
            first,
            count,
            level: 0,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Spec {
    contract: Contract,
    first: u32,
    count: u32,
    level: u32,
}
impl Spec {
    fn width(&self) -> usize {
        HEADER + 8
    }
    fn end(&self) -> u32 {
        self.first + self.count
    }
    fn merge(left: &Self, right: &Self) -> Result<Self> {
        require(
            left.contract == right.contract,
            "different component contract",
        )?;
        require(
            left.end() == right.first,
            "missing, duplicated, overlapping or reordered interval",
        )?;
        let mut result = left.contract.span(
            left.first,
            left.count
                .checked_add(right.count)
                .ok_or_else(|| Error("component count overflow".into()))?,
        )?;
        result.level = left
            .level
            .max(right.level)
            .checked_add(1)
            .ok_or_else(|| Error("component level overflow".into()))?;
        Ok(result)
    }
}

/// These roots must ultimately come from the constrained transaction/obligation
/// manifest. Supplying arbitrary context here does not prove that transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointContext {
    pub context: [u8; 32],
    pub statement: [Val; 4],
    pub input: [Val; 4],
    pub output: [Val; 4],
}
fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}
fn header(spec: &Spec, context: &EndpointContext) -> Result<Vec<Val>> {
    let mut result = vec![Val::ZERO; spec.width()];
    result[..8].copy_from_slice(&words(&spec.contract.profile));
    result[CONTEXT..CONTEXT + 8].copy_from_slice(&words(&context.context));
    for (offset, values) in [
        (STATEMENT, context.statement),
        (EXPECTED_INPUT, context.input),
        (EXPECTED_OUTPUT, context.output),
    ] {
        result[offset..offset + 4].copy_from_slice(&values);
    }
    for (offset, value) in [
        (KIND, spec.contract.tag()),
        (REQUEST, u64::from(spec.contract.request)),
        (FIRST, u64::from(spec.first)),
        (COUNT, u64::from(spec.count)),
        (TOTAL, u64::from(spec.contract.total)),
        (LEVEL, u64::from(spec.level)),
    ] {
        result[offset] = Val::from_u64(value);
    }
    result[DESCRIPTOR..DESCRIPTOR + 4].copy_from_slice(&spec.contract.descriptor_root()?);
    Ok(result)
}
fn constant(b: &mut ProgramBuilder, wire: Wire, value: Val) {
    let expected = b.constant(value);
    b.assert_equal(wire, expected);
}
fn public_wires(b: &mut ProgramBuilder, spec: &Spec) -> Result<Vec<Wire>> {
    let public = (0..spec.width())
        .map(|i| b.public(i).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    for (wire, value) in public[..8].iter().zip(words(&spec.contract.profile)) {
        constant(b, *wire, value);
    }
    for &wire in &public[CONTEXT..CONTEXT + 8] {
        lattica_prover_p3::block_v2::machine::pq_modular::bounded_bits(b, wire, 32).map_err(err)?;
    }
    for (offset, value) in [
        (KIND, spec.contract.tag()),
        (REQUEST, u64::from(spec.contract.request)),
        (FIRST, u64::from(spec.first)),
        (COUNT, u64::from(spec.count)),
        (TOTAL, u64::from(spec.contract.total)),
        (LEVEL, u64::from(spec.level)),
    ] {
        constant(b, public[offset], Val::from_u64(value));
    }
    for (i, value) in spec.contract.descriptor_root()?.into_iter().enumerate() {
        constant(b, public[DESCRIPTOR + i], value);
    }
    Ok(public)
}
fn bind_request_ends(
    b: &mut ProgramBuilder,
    spec: &Spec,
    public: &[Wire],
    start: &[Wire],
    end: &[Wire],
) {
    if spec.first == 0 {
        match spec.contract.kind {
            Kind::Shake(d) => {
                for &wire in &start[..100] {
                    constant(b, wire, Val::ZERO);
                }
                for (offset, domain, length) in [
                    (100, shake_air::SHAKE_INPUT_DOMAIN, d.input_len),
                    (104, shake_air::SHAKE_OUTPUT_DOMAIN, d.output_len),
                ] {
                    for (i, value) in [
                        Val::from_u64(domain),
                        Val::from_usize(length),
                        Val::ZERO,
                        Val::ZERO,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        constant(b, start[offset + i], value);
                    }
                }
            }
            Kind::Aes(d) => {
                for (wire, value) in start.iter().zip([
                    Val::from_u64(aes_lane_air::AES_OUTPUT_DOMAIN),
                    Val::from_usize(d.output_len),
                    Val::ZERO,
                    Val::ZERO,
                ]) {
                    constant(b, *wire, value);
                }
            }
        }
    }
    if spec.end() == spec.contract.total {
        match spec.contract.kind {
            Kind::Shake(_) => {
                for i in 0..4 {
                    b.assert_equal(end[100 + i], public[EXPECTED_INPUT + i]);
                    b.assert_equal(end[104 + i], public[EXPECTED_OUTPUT + i]);
                }
            }
            Kind::Aes(_) => {
                for i in 0..4 {
                    b.assert_equal(end[i], public[EXPECTED_OUTPUT + i]);
                }
            }
        }
    }
}

/// A compiled constrained predicate, not an acceptance receipt.
pub struct CompiledNode {
    spec: Spec,
    program: Arc<Program>,
    public: Vec<Val>,
    witness: Vec<Val>,
}
#[derive(Clone, Debug)]
pub struct Geometry {
    pub active_rows: usize,
    pub padded_rows: usize,
    pub wires: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub permutation_width_base: usize,
    pub quotient_chunks: usize,
    pub constraints: usize,
    pub max_constraint_degree: usize,
    pub fri_ali_bits: usize,
    pub retained_lde_bytes: u64,
}
impl CompiledNode {
    pub fn program(&self) -> &Program {
        &self.program
    }
    pub fn public_values(&self) -> &[Val] {
        &self.public
    }
    pub fn geometry(&self) -> Result<Geometry> {
        let report = analysis::analyze(&MachineAir::from_shared_program(Arc::clone(&self.program))).map_err(err)?;
        Ok(Geometry {
            active_rows: self.program.active_rows(),
            padded_rows: self.program.height(),
            wires: self.program.wire_count(),
            main_width: report.main_width,
            preprocessed_width: report.preprocessed_width,
            permutation_width_base: report.permutation_width_base,
            quotient_chunks: report.quotient_chunks,
            constraints: report.constraints,
            max_constraint_degree: report.max_constraint_degree,
            fri_ali_bits: report.fri_ali_bits,
            retained_lde_bytes: report.retained_lde_bytes,
        })
    }
    pub fn evaluate(&self) -> Result<()> {
        MachineAir::from_shared_program(Arc::clone(&self.program))
            .trace(&self.public, &self.witness)
            .map_err(err)?;
        Ok(())
    }
    pub fn prepare(self, memory_budget: u64) -> Result<PreparedNode> {
        require(
            self.geometry()?.retained_lde_bytes <= memory_budget,
            "endpoint node exceeds retained-LDE budget before registration",
        )?;
        let registered =
            RegisteredProgram::new_with_memory_budget(MachineAir::from_shared_program(self.program), memory_budget)
                .map_err(err)?;
        Ok(PreparedNode {
            registered,
            spec: self.spec,
            public: self.public,
            witness: self.witness,
        })
    }
}
pub struct PreparedNode {
    registered: RegisteredProgram,
    spec: Spec,
    public: Vec<Val>,
    witness: Vec<Val>,
}
impl PreparedNode {
    pub fn key(&self) -> NodeKey {
        NodeKey {
            spec: self.spec.clone(),
            height: self.registered.air().program().height(),
            cap: self.registered.preprocessing_cap().roots().to_vec(),
            verifier: Arc::new(self.registered.verifier()),
        }
    }
    pub fn prove(&self) -> Result<NodeProof> {
        let proof = self
            .registered
            .prove(&self.public, &self.witness)
            .map_err(err)?;
        self.registered.verify(&proof, &self.public).map_err(err)?;
        Ok(NodeProof {
            public: self.public.clone(),
            proof,
        })
    }
}
pub struct NodeProof {
    pub public: Vec<Val>,
    pub proof: BatchProof<Config>,
}
/// Retains an authenticated source cap and compact verifier metadata only.
/// Child proving state and its preprocessing LDE may be dropped before merging.
#[derive(Clone)]
pub struct NodeKey {
    spec: Spec,
    height: usize,
    cap: Vec<[Val; 4]>,
    verifier: Arc<RegisteredVerifier>,
}
impl NodeKey {
    pub(crate) fn manifest_shape(&self) -> Result<crate::obligation_manifest::CryptoShape> {
        use crate::obligation_manifest::CryptoShape;
        require(
            self.spec.first == 0 && self.spec.count == self.spec.contract.total,
            "incomplete request manifest record",
        )?;
        let index = self.spec.contract.request;
        Ok(match self.spec.contract.kind {
            Kind::Shake(d) => CryptoShape::Shake {
                index,
                input_len: d.input_len,
                output_len: d.output_len,
            },
            Kind::Aes(d) => CryptoShape::Aes {
                index,
                domain: d.domain,
                start_counter: d.start_counter,
                output_len: d.output_len,
            },
        })
    }
    /// Complete registered child verification, then expose only authenticated
    /// request roots in the caller's current constrained program.
    pub(crate) fn compile_manifest_record(
        &self,
        b: &mut lattica_prover_p3::block_v2::machine::program::ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        proof: &NodeProof,
        context: &crate::obligation_manifest::ContextWires,
    ) -> Result<[[Wire; 4]; 2]> {
        self.manifest_shape()?;
        require(
            proof.public.len() == self.spec.width(),
            "request node public width",
        )?;
        let public = inputs.bases(b, &proof.public).map_err(err)?;
        let cap: Vec<_> = self
            .cap
            .iter()
            .map(|root| root.map(|value| b.constant(value)))
            .collect();
        verifier::batch::verify(b, inputs, &self.air()?, &public, &cap, &proof.proof)
            .map_err(err)?;
        for (i, expected) in context
            .profile
            .iter()
            .chain(&context.context)
            .chain(&context.statement)
            .enumerate()
        {
            b.assert_equal(public[i], *expected);
        }
        Ok([
            public[EXPECTED_INPUT..EXPECTED_INPUT + 4]
                .try_into()
                .map_err(err)?,
            public[EXPECTED_OUTPUT..EXPECTED_OUTPUT + 4]
                .try_into()
                .map_err(err)?,
        ])
    }
    fn air(&self) -> Result<MachineAir> {
        Ok(MachineAir::new(
            ProgramBuilder::new(self.spec.width())
                .map_err(err)?
                .finish(Some(self.height))
                .map_err(err)?,
        ))
    }
    pub fn verify(&self, proof: &NodeProof) -> Result<()> {
        self.verifier
            .verify(&proof.proof, &proof.public)
            .map_err(err)
    }
    pub fn verify_request(&self, proof: &NodeProof, context: &EndpointContext) -> Result<()> {
        require(
            self.spec.first == 0 && self.spec.count == self.spec.contract.total,
            "incomplete request node",
        )?;
        let expected = header(&self.spec, context)?;
        require(
            proof.public.len() == expected.len() && proof.public[..HEADER] == expected[..HEADER],
            "unexpected context, statement or request roots",
        )?;
        self.verify(proof)
    }
}

fn endpoint_root(contract: &Contract, values: &[Val]) -> Result<[Val; 4]> {
    require(
        values.len() == contract.boundary_width(),
        "endpoint field width",
    )?;
    let mut fields = vec![contract.tag(), values.len() as u64];
    fields.extend(values.iter().map(|v| v.as_canonical_u64()));
    Ok(commitment::hash_fields(ENDPOINT_DOMAIN, &fields)
        .map_err(err)?
        .map(Val::from_u64))
}
fn bind_endpoints(
    b: &mut ProgramBuilder,
    spec: &Spec,
    outer: &[Wire],
    start: &[Wire],
    end: &[Wire],
) {
    bind_request_ends(b, spec, outer, start, end);
    for (offset, endpoint) in [(HEADER, start), (HEADER + 4, end)] {
        let mut fields = vec![
            b.constant(Val::from_u64(spec.contract.tag())),
            b.constant(Val::from_usize(endpoint.len())),
        ];
        fields.extend_from_slice(endpoint);
        let digest = b.hash_fields(ENDPOINT_DOMAIN, &fields);
        for i in 0..4 {
            b.assert_equal(digest[i], outer[offset + i]);
        }
    }
}
pub fn compile_aes(
    contract: &Contract,
    first: u32,
    blocks: u32,
    context: &EndpointContext,
    proof: &aes_lane_air::join::AesLaneSegmentProof,
) -> Result<CompiledNode> {
    compile_aes_with_context(contract, first, blocks, context, proof, None)
}
pub fn compile_aes_with_context(
    contract: &Contract,
    first: u32,
    blocks: u32,
    context: &EndpointContext,
    proof: &aes_lane_air::join::AesLaneSegmentProof,

    execution: Option<&crate::execution::ProvingContext>,
) -> Result<CompiledNode> {
    with_endpoint_preparation(execution, |endpoint_root| {
        let Kind::Aes(descriptor) = contract.kind else {
            return Err(Error("AES proof used for non-AES contract".into()));
        };
        let spec = contract.span(first, blocks)?;
        let air = aes_lane_air::AesLaneAir::segment(descriptor, first as usize, blocks as usize)
            .map_err(err)?;
        let mut public = header(&spec, context)?;
        public[HEADER..HEADER + 4].copy_from_slice(&endpoint_root(
            contract,
            &proof.public_values[aes_lane_air::OUTPUT_START..aes_lane_air::OUTPUT_START + 4],
        )?);
        public[HEADER + 4..].copy_from_slice(&endpoint_root(
            contract,
            &proof.public_values[aes_lane_air::OUTPUT_END..aes_lane_air::OUTPUT_END + 4],
        )?);
        let mut b = ProgramBuilder::new(spec.width()).map_err(err)?;
        let outer = public_wires(&mut b, &spec)?;
        let mut inputs = ProofInputs::default();
        let child = inputs.bases(&mut b, &proof.public_values).map_err(err)?;
        verifier::uni::verify(&mut b, &mut inputs, &air, air.height, &child, &proof.proof)
            .map_err(err)?;
        for i in 0..4 {
            b.assert_equal(
                child[aes_lane_air::INPUT_COMMITMENT + i],
                outer[EXPECTED_INPUT + i],
            );
        }
        bind_endpoints(
            &mut b,
            &spec,
            &outer,
            &child[aes_lane_air::OUTPUT_START..aes_lane_air::OUTPUT_START + 4],
            &child[aes_lane_air::OUTPUT_END..aes_lane_air::OUTPUT_END + 4],
        );
        Ok(CompiledNode {
            spec,
            program: Arc::new(b.finish(None).map_err(err)?),
            public,
            witness: inputs.values,
        })
    })
}
fn shake_indices() -> [Vec<usize>; 2] {
    [
        (
            shake_air::START_STATE,
            shake_air::INPUT_START,
            shake_air::OUTPUT_START,
        ),
        (
            shake_air::END_STATE,
            shake_air::INPUT_END,
            shake_air::OUTPUT_END,
        ),
    ]
    .map(|(state, input, output)| {
        (state..state + 100)
            .chain(input..input + 4)
            .chain(output..output + 4)
            .collect()
    })
}
pub fn compile_shake(
    contract: &Contract,
    permutation: u32,
    context: &EndpointContext,
    proof: &shake_air::lane::LaneShakeProof,
) -> Result<CompiledNode> {
    compile_shake_batch(contract, permutation, 1, context, proof)
}

/// Canonical single or homogeneous batched SHAKE leaf. The source constructors
/// reject a batch spanning absorption/padding/squeezing phase boundaries.
pub fn compile_shake_batch(
    contract: &Contract,
    first: u32,
    count: u32,
    context: &EndpointContext,
    proof: &shake_air::lane::LaneShakeProof,
) -> Result<CompiledNode> {
    compile_shake_group(
        contract,
        &[ShakeGroupMember {
            first,
            count,
            proof,
        }],
        context,
    )
}

pub fn compile_shake_batch_with_context(
    contract: &Contract,
    first: u32,
    count: u32,
    context: &EndpointContext,
    proof: &shake_air::lane::LaneShakeProof,
    execution: Option<&crate::execution::ProvingContext>,
) -> Result<CompiledNode> {
    compile_shake_group_with_context(
        contract,
        &[ShakeGroupMember {
            first,
            count,
            proof,
        }],
        context,
        execution,
    )
}
/// One unchanged native child proof within a grouped recursive wrapper.
pub struct ShakeGroupMember<'a> {
    pub first: u32,
    pub count: u32,
    pub proof: &'a shake_air::lane::LaneShakeProof,
}

/// An early, allocation-free rejection check. The recursive verifier below
/// still emits all 108 equalities; host equality is never proof acceptance.
fn check_shake_boundary(
    left: &[Val; shake_air::PUBLIC_VALUES],
    right: &[Val; shake_air::PUBLIC_VALUES],
) -> Result<()> {
    for (left_start, right_start, width) in [
        (shake_air::END_STATE, shake_air::START_STATE, 100),
        (shake_air::INPUT_END, shake_air::INPUT_START, 4),
        (shake_air::OUTPUT_END, shake_air::OUTPUT_START, 4),
    ] {
        require(
            left[left_start..left_start + width] == right[right_start..right_start + width],
            "SHAKE wrapper interior state/input/output boundary mismatch",
        )?;
    }
    Ok(())
}

fn check_shake_group_members(contract: &Contract, members: &[ShakeGroupMember<'_>]) -> Result<()> {
    require(
        matches!(contract.kind, Kind::Shake(_)),
        "SHAKE proof used for non-SHAKE contract",
    )?;
    require(!members.is_empty(), "empty SHAKE wrapper group")?;
    let mut end = members[0].first;
    for member in members {
        require(
            member.first == end,
            "missing, duplicate, overlapping or reordered SHAKE group segment",
        )?;
        end = contract.span(member.first, member.count)?.end();
    }
    for adjacent in members.windows(2) {
        check_shake_boundary(
            &adjacent[0].proof.public_values,
            &adjacent[1].proof.public_values,
        )?;
    }
    Ok(())
}

/// Verify a contiguous set of native SHAKE segments in one recursive program.
/// Every native AIR retains its exact phase/count registration, and all 108
/// state/input/output boundary fields are equated between consecutive children.
pub fn compile_shake_group(
    contract: &Contract,
    members: &[ShakeGroupMember<'_>],
    context: &EndpointContext,
) -> Result<CompiledNode> {
    compile_shake_group_with_context(contract, members, context, None)
}
pub fn compile_shake_group_with_context(
    contract: &Contract,
    members: &[ShakeGroupMember<'_>],
    context: &EndpointContext,

    execution: Option<&crate::execution::ProvingContext>,
) -> Result<CompiledNode> {
    with_endpoint_preparation(execution, |endpoint_root| {
        use shake_air::lane::batch::{BatchShakeAir, ShakeSegmentAir};
        let Kind::Shake(descriptor) = contract.kind else {
            return Err(Error("SHAKE proof used for non-SHAKE contract".into()));
        };
        require(!members.is_empty(), "empty SHAKE wrapper group")?;
        let first = members[0].first;
        let mut end = first;
        let mut airs = Vec::with_capacity(members.len());
        for member in members {
            require(
                member.first == end,
                "missing, duplicate, overlapping or reordered SHAKE group segment",
            )?;
            let span = contract.span(member.first, member.count)?;
            end = span.end();
            airs.push(if member.count == 1 {
                ShakeSegmentAir::Single(
                    shake_air::lane::LaneShakeAir::new(descriptor, member.first as usize)
                        .map_err(err)?,
                )
            } else {
                let batch = BatchShakeAir::full_absorb(
                    descriptor,
                    member.first as usize,
                    member.count as usize,
                )
                .or_else(|_| {
                    BatchShakeAir::full_squeeze(
                        descriptor,
                        member.first as usize,
                        member.count as usize,
                    )
                })
                .map_err(err)?;
                ShakeSegmentAir::Batch(batch)
            });
        }
        let spec = contract.span(first, end - first)?;
        let indices = shake_indices();
        let mut public = header(&spec, context)?;
        for (offset, index, proof) in [
            (HEADER, &indices[0], members[0].proof),
            (HEADER + 4, &indices[1], members.last().unwrap().proof),
        ] {
            public[offset..offset + 4].copy_from_slice(&endpoint_root(
                contract,
                &index
                    .iter()
                    .map(|&i| proof.public_values[i])
                    .collect::<Vec<_>>(),
            )?);
        }
        let mut b = ProgramBuilder::new(spec.width()).map_err(err)?;
        let outer = public_wires(&mut b, &spec)?;
        let mut inputs = ProofInputs::default();
        let mut initial = None;
        let mut previous: Option<Vec<Wire>> = None;
        for (member, air) in members.iter().zip(&airs) {
            let child = inputs
                .bases(&mut b, &member.proof.public_values)
                .map_err(err)?;
            verifier::uni::verify(
                &mut b,
                &mut inputs,
                air,
                air.height(),
                &child,
                &member.proof.proof,
            )
            .map_err(err)?;
            let endpoints = indices
                .each_ref()
                .map(|index| index.iter().map(|&i| child[i]).collect::<Vec<_>>());
            if let Some(prior) = previous.take() {
                for (&left, &right) in prior.iter().zip(&endpoints[0]) {
                    b.assert_equal(left, right);
                }
            } else {
                initial = Some(endpoints[0].clone());
            }
            previous = Some(endpoints[1].clone());
        }
        bind_endpoints(&mut b, &spec, &outer, &initial.unwrap(), &previous.unwrap());
        Ok(CompiledNode {
            spec,
            program: Arc::new(b.finish(None).map_err(err)?),
            public,
            witness: inputs.values,
        })
    })
}

/// Construction stages only. No stage registers or proves a wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShakeGroupCompilePhase {
    AuxiliaryAdmission,
    Initialize,
    Inputs { member: usize },
    NativeVerifier { member: usize },
    Finish,
}

/// Public admission metadata only; no proof/witness/partial program is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShakeGroupResourceRefusal {
    pub phase: ShakeGroupCompilePhase,
    pub limits: ConstructionLimits,
    /// None if initialization refused. At Finish this is a pre-finish snapshot,
    /// excluding any later packing/compaction requests; not a process RSS peak.
    pub counters: Option<ConstructionCounters>,
    pub reason: &'static str,
}

pub enum ShakeGroupCompileOutcome {
    Compiled(CompiledNode),
    ResourceRefused(ShakeGroupResourceRefusal),
}

fn shake_group_refused(
    limits: ConstructionLimits,
    phase: ShakeGroupCompilePhase,
    counters: Option<ConstructionCounters>,
    reason: &'static str,
) -> ShakeGroupCompileOutcome {
    ShakeGroupCompileOutcome::ResourceRefused(ShakeGroupResourceRefusal {
        phase, limits, counters, reason,
    })
}

fn shake_group_compile_error(
    error: verifier::CompileError,
    limits: ConstructionLimits,
    phase: ShakeGroupCompilePhase,
    counters: ConstructionCounters,
) -> Result<ShakeGroupCompileOutcome> {
    match error {
        // A typed original admission source AND its sticky builder state are
        // required. A Shape/Unsupported/Backend error never permits fallback,
        // even if a resource bit was also set earlier in that compilation.
        verifier::CompileError::ResourceAdmission(reason) if counters.resource_failed => {
            Ok(shake_group_refused(limits, phase, Some(counters), reason))
        }
        error => Err(err(error)),
    }
}

/// Compile the unchanged grouped native-verifier relation with explicit builder
/// program-byte, wire and total ProofInputs-value limits installed before the
/// first operation. Every native verifier and all 108 boundary equalities remain.
///
/// This is a prerequisite only: it never enables grouping, performs fallback,
/// registers a program or dispatches a native/outer proof. A resource refusal
/// drops compiler-owned program/input storage before returning metadata;
/// all Err values must propagate. No resource refusal authorizes a caller to
/// retry after proof dispatch. Endpoint preparation uses the same execution
/// context as the existing API, after auxiliary admission succeeds.
///
/// ConstructionLimits is not an overall host cap. Callers must separately admit
/// retained native proofs and allocator overhead. The auxiliary allowance covers
/// old/new ProofInputs buffers, returned wires, AIR/symbolic/periodic scratch,
/// and endpoint helpers. It must be reserved alongside the builder allowance.
/// Exact row/retained-LDE/device admission is still required on a Compiled node
/// before any proof registration/dispatch. There is no unbounded retry here.
pub fn compile_shake_group_bounded_with_context(
    contract: &Contract,
    members: &[ShakeGroupMember<'_>],
    context: &EndpointContext,

    execution: Option<&crate::execution::ProvingContext>,
    limits: ConstructionLimits,
    auxiliary_host_allowance: usize,
) -> Result<ShakeGroupCompileOutcome> {
    // Reject malformed intervals and interior endpoints before acquiring an
    // endpoint preparation session or allocating compiler/AIR storage.
    check_shake_group_members(contract, members)?;
    // Validate each native geometry on the stack before classifying a resource
    // refusal; malformed phase/count shapes never become retryable admission.
    for member in members { shake_compile_memory::air(contract, member)?; }
    let footprint = ShakeGroupCompileFootprint::for_group(members.len(), limits).map_err(err)?;
    if footprint.auxiliary_peak_bytes > auxiliary_host_allowance {
        return Ok(shake_group_refused(limits, ShakeGroupCompilePhase::AuxiliaryAdmission,
            None, "SHAKE compiler auxiliary host allowance"));
    }
    with_endpoint_preparation(execution, |endpoint_root| {
        use shake_air::lane::batch::{BatchShakeAir, ShakeSegmentAir};
        let Kind::Shake(descriptor) = contract.kind else {
            return Err(Error("SHAKE proof used for non-SHAKE contract".into()));
        };
        require(!members.is_empty(), "empty SHAKE wrapper group")?;
        let first = members[0].first;
        let mut end = first;
        let mut airs = Vec::with_capacity(members.len());
        for member in members {
            require(
                member.first == end,
                "missing, duplicate, overlapping or reordered SHAKE group segment",
            )?;
            let span = contract.span(member.first, member.count)?;
            end = span.end();
            airs.push(if member.count == 1 {
                ShakeSegmentAir::Single(
                    shake_air::lane::LaneShakeAir::new(descriptor, member.first as usize)
                        .map_err(err)?,
                )
            } else {
                let batch = BatchShakeAir::full_absorb(
                    descriptor,
                    member.first as usize,
                    member.count as usize,
                )
                .or_else(|_| {
                    BatchShakeAir::full_squeeze(
                        descriptor,
                        member.first as usize,
                        member.count as usize,
                    )
                })
                .map_err(err)?;
                ShakeSegmentAir::Batch(batch)
            });
        }
        let spec = contract.span(first, end - first)?;
        let indices = shake_indices();
        let mut public = header(&spec, context)?;
        for (offset, index, proof) in [
            (HEADER, &indices[0], members[0].proof),
            (HEADER + 4, &indices[1], members.last().unwrap().proof),
        ] {
            public[offset..offset + 4].copy_from_slice(&endpoint_root(
                contract,
                &index
                    .iter()
                    .map(|&i| proof.public_values[i])
                    .collect::<Vec<_>>(),
            )?);
        }
        let mut b = match ProgramBuilder::new_with_construction_limits(spec.width(), limits) {
            Ok(builder) => builder,
            Err(ExecutionError::TooLarge) => return Ok(shake_group_refused(
                limits, ShakeGroupCompilePhase::Initialize, None, "program construction initialization",
            )),
            Err(error) => return Err(err(error)),
        };
        let outer = public_wires(&mut b, &spec)?;
        let mut inputs = ProofInputs::default();
        let mut initial = None;
        let mut previous: Option<Vec<Wire>> = None;
        for (member_index, (member, air)) in members.iter().zip(&airs).enumerate() {
            let child = match inputs.bases(&mut b, &member.proof.public_values) {
                Ok(child) => child,
                Err(error) => return shake_group_compile_error(
                    error, limits, ShakeGroupCompilePhase::Inputs { member: member_index },
                    b.construction_counters(),
                ),
            };
            // The pinned fixed table was admitted before endpoint preparation;
            // never ask the generic verifier to allocate an unknown AIR table.
            let columns = air.periodic_columns();
            require(columns.len() == shake_air::lane::PERIODIC_COLUMNS
                && columns.iter().all(|c| c.len() == shake_air::lane::SCHEDULE_PERIOD),
                "SHAKE compiler periodic geometry")?;
            if let Err(error) = verifier::uni::verify_bounded(
                &mut b,
                &mut inputs,
                air,
                air.height(),
                &child,
                &member.proof.proof,
                &columns,
                footprint.symbolic,
            ) {
                return shake_group_compile_error(
                    error, limits, ShakeGroupCompilePhase::NativeVerifier { member: member_index },
                    b.construction_counters(),
                );
            }
            let endpoints = indices
                .each_ref()
                .map(|index| index.iter().map(|&i| child[i]).collect::<Vec<_>>());
            if let Some(prior) = previous.take() {
                for (&left, &right) in prior.iter().zip(&endpoints[0]) {
                    b.assert_equal(left, right);
                }
            } else {
                initial = Some(endpoints[0].clone());
            }
            previous = Some(endpoints[1].clone());
        }
        bind_endpoints(&mut b, &spec, &outer, &initial.unwrap(), &previous.unwrap());
        // This is the snapshot BEFORE finish: final compaction/packing may
        // refuse later, so counters must not be advertised as a final peak.
        let counters = b.construction_counters();
        let program = match b.finish(None) {
            Ok(program) => program,
            Err(ExecutionError::TooLarge) => return Ok(shake_group_refused(
                limits, ShakeGroupCompilePhase::Finish, Some(counters), "program finishing",
            )),
            Err(error) => return Err(err(error)),
        };
        Ok(ShakeGroupCompileOutcome::Compiled(CompiledNode {
            spec, program: Arc::new(program), public, witness: inputs.values,
        }))
    })
}


fn bind_merge(b: &mut ProgramBuilder, _spec: &Spec, outer: &[Wire], left: &[Wire], right: &[Wire]) {
    for i in 0..HEADER {
        if ![FIRST, COUNT, LEVEL].contains(&i) {
            b.assert_equal(left[i], outer[i]);
            b.assert_equal(right[i], outer[i]);
        }
    }
    b.assert_equal(left[FIRST], outer[FIRST]);
    let adjacent = b.add(left[FIRST], left[COUNT]);
    b.assert_equal(adjacent, right[FIRST]);
    let count = b.add(left[COUNT], right[COUNT]);
    b.assert_equal(count, outer[COUNT]);
    let width = 4;
    for i in 0..width {
        b.assert_equal(left[HEADER + width + i], right[HEADER + i]);
        b.assert_equal(left[HEADER + i], outer[HEADER + i]);
        b.assert_equal(right[HEADER + width + i], outer[HEADER + width + i]);
    }
}
fn merge_impl(left: &NodeKey, right: &NodeKey, children: [&NodeProof; 2]) -> Result<CompiledNode> {
    let spec = Spec::merge(&left.spec, &right.spec)?;
    require(
        children.iter().all(|p| p.public.len() == spec.width()),
        "component child public width",
    )?;
    let mut public = children[0].public.clone();
    public[FIRST] = Val::from_u32(spec.first);
    public[COUNT] = Val::from_u32(spec.count);
    public[LEVEL] = Val::from_u32(spec.level);
    let width = 4;
    public[HEADER + width..].copy_from_slice(&children[1].public[HEADER + width..]);
    let mut b = ProgramBuilder::new(spec.width()).map_err(err)?;
    let outer = public_wires(&mut b, &spec)?;
    let mut inputs = ProofInputs::default();
    let mut wires = Vec::new();
    for (key, proof) in [left, right].into_iter().zip(children) {
        let child = inputs.bases(&mut b, &proof.public).map_err(err)?;
        let cap: Vec<_> = key
            .cap
            .iter()
            .map(|root| root.map(|value| b.constant(value)))
            .collect();
        verifier::batch::verify(&mut b, &mut inputs, &key.air()?, &child, &cap, &proof.proof)
            .map_err(err)?;
        wires.push(child);
    }
    bind_merge(&mut b, &spec, &outer, &wires[0], &wires[1]);
    Ok(CompiledNode {
        spec,
        program: Arc::new(b.finish(None).map_err(err)?),
        public,
        witness: inputs.values,
    })
}
/// Full child verification remains in the emitted circuit. Native verification
/// below is only early error reporting, never the predicate being proved.
pub fn compile_merge(
    left: &NodeKey,
    right: &NodeKey,
    children: [&NodeProof; 2],
) -> Result<CompiledNode> {
    Spec::merge(&left.spec, &right.spec)?;
    left.verify(children[0])?;
    right.verify(children[1])?;
    merge_impl(left, right, children)
}
/// Compile with invalid zero templates only to measure shape. This function
/// never returns a proof/receipt or a predicate whose template was accepted.
pub fn merge_geometry(left: &NodeKey, right: &NodeKey) -> Result<Geometry> {
    Spec::merge(&left.spec, &right.spec)?;
    let dummy = |key: &NodeKey| -> Result<NodeProof> {
        Ok(NodeProof {
            public: vec![Val::ZERO; key.spec.width()],
            proof: verifier::template::batch(&key.air()?).map_err(err)?,
        })
    };
    let a = dummy(left)?;
    let b = dummy(right)?;
    merge_impl(left, right, [&a, &b])?.geometry()
}

#[cfg(test)]
pub(crate) mod shape_diagnostic;
#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod crypto_segment_proof_tests;
#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod crypto_segment_shape_tests;

#[cfg(all(test, feature = "recursive-wide"))]
mod parent_proof_tests;

#[cfg(test)]
mod bounded_shake_tests;
