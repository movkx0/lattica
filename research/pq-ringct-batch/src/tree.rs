#[cfg(feature = "opencl")]
use crate::contract::leaf_fields;
use crate::{
    contract::{leaf_root, node_metadata, node_root, Spec},
    err, require, Error, Geometry, Plan, Result, CONTEXT, COUNT, FIRST, LEAF_DOMAIN, MODE,
    NODE_DOMAIN, PUBLIC_VALUES, ROOT, TOTAL,
};
use lattica_pq_ringct_research::{
    graph_tree::{ContextWires, GraphContext, NodeKey as GraphKey, NodeProof as GraphProof},
    recursive_aggregation::LeafStatement,
};
use lattica_prover_p3::block_v2::{
    machine::{
        analysis,
        backend::{RegisteredProgram, RegisteredVerifier},
        program::{Val, Wire},
        verifier::{self, ProofInputs},
        ExecutionError, MachineAir, Program, ProgramBuilder, WIDTH,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof as RawProof;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use sha3::{Digest, Sha3_256};
use std::{sync::Arc, time::Instant};

/// Borrowed complete graph proof at one checked original-statement position.
/// Its constructor always native-verifies the complete graph; merge compilation
/// additionally emits the full graph verifier into the parent.
pub struct GraphChild<'a> {
    spec: Spec,
    key: &'a GraphKey,
    proof: &'a GraphProof,
    context: &'a GraphContext,
}
/// Aggregate children own only their compact trusted key and actual proof.
pub enum Child<'a> {
    Graph(GraphChild<'a>),
    Batch(BatchNode),
}
impl<'a> From<GraphChild<'a>> for Child<'a> {
    fn from(child: GraphChild<'a>) -> Self {
        Self::Graph(child)
    }
}
impl<'a> From<BatchNode> for Child<'a> {
    fn from(node: BatchNode) -> Self {
        Self::Batch(node)
    }
}
impl Plan {
    pub fn graph_child<'a>(
        &self,
        index: u32,
        key: &'a GraphKey,
        proof: &'a GraphProof,
        context: &'a GraphContext,
    ) -> Result<GraphChild<'a>> {
        let child = GraphChild {
            spec: Spec::new(self, index, 1)?,
            key,
            proof,
            context,
        };
        child.verify()?;
        Ok(child)
    }
    /// Verify exact complete ordered coverage against the original public
    /// statements. For N=1 this verifies the complete graph directly.
    pub fn verify_expected(&self, root: &Child<'_>, statements: &[LeafStatement]) -> Result<()> {
        require(
            self.same_scope(&root.spec().plan),
            "different expected batch scope",
        )?;
        require(
            root.spec().complete(),
            "incomplete ordered transaction coverage",
        )?;
        let expected = self.expected_root(statements)?;
        root.verify()?;
        require(
            root.root()? == expected,
            "unexpected ordered original statements",
        )?;
        if let Child::Graph(_) = root {
            require(
                self.total() == 1,
                "a single graph cannot cover a multi-entry batch",
            )?;
        }
        Ok(())
    }
}
impl GraphChild<'_> {
    fn verify(&self) -> Result<()> {
        require(
            self.key.profile_label() == self.spec.plan.graph_profile(),
            "graph key profile mismatch",
        )?;
        require(
            self.context.context == self.spec.plan.context(),
            "graph context mismatch",
        )?;
        self.key
            .verify_complete(self.proof, self.context)
            .map_err(err)
    }
}
impl Child<'_> {
    pub(crate) fn matches_scope(&self, plan: &Plan) -> bool {
        self.spec().plan.same_scope(plan)
    }
    fn spec(&self) -> &Spec {
        match self {
            Self::Graph(c) => &c.spec,
            Self::Batch(n) => &n.key.spec,
        }
    }
    fn verify(&self) -> Result<()> {
        match self {
            Self::Graph(c) => c.verify(),
            Self::Batch(n) => n.key.verify(&n.proof),
        }
    }
    fn root(&self) -> Result<[u64; 4]> {
        match self {
            Self::Graph(c) => leaf_root(&c.spec, c.context.statement.map(|v| v.as_canonical_u64())),
            Self::Batch(n) => Ok(core::array::from_fn(|i| {
                n.proof.public[ROOT + i].as_canonical_u64()
            })),
        }
    }
    pub fn span(&self) -> (u32, u32) {
        (self.spec().first, self.spec().count)
    }
    pub fn level(&self) -> u32 {
        self.spec().level()
    }
}

pub struct CompiledNode {
    spec: Spec,
    program: Arc<Program>,
    public: [Val; PUBLIC_VALUES],
    witness: Vec<Val>,
    recursive_witness_targets: Vec<RecursiveWitnessTarget>,
}

/// Acceptance diagnostics for an aggregate child's embedded verifier. These
/// checks execute the compiled program; they do not generate a negative proof.
#[derive(Clone, Debug)]
pub struct RecursiveWitnessCheck {
    pub child_index: usize,
    pub child_first: u32,
    pub child_count: u32,
    /// Principal temporary evaluation buffers only. The resident program and
    /// witness, allocator overhead, and whole-process limits remain separate.
    pub principal_buffer_bound_bytes: u64,
    pub evaluation_seconds: f64,
}

struct RecursiveWitnessTarget {
    child_index: usize,
    child_first: u32,
    child_count: u32,
    witness_index: usize,
    original: Val,
}

fn recursive_witness_target(
    child_index: usize,
    child: &BatchNode,
    proof_start: usize,
    inputs: &ProofInputs,
) -> Result<RecursiveWitnessTarget> {
    let proof = &child.proof.proof;
    let random = proof
        .commitments
        .random
        .as_ref()
        .ok_or_else(|| Error("missing aggregate child random cap".into()))?;
    let permutation = proof
        .commitments
        .permutation
        .as_ref()
        .ok_or_else(|| Error("missing aggregate child permutation cap".into()))?;
    let terminal = proof
        .lookup_terminals
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| Error("missing aggregate child lookup terminal".into()))?;
    let opening = proof
        .opened_values
        .instances
        .first()
        .and_then(|instance| instance.base_opened_values.trace_local.first())
        .ok_or_else(|| Error("missing aggregate child trace opening".into()))?;
    let terminal_values: &[Val] = terminal.0.as_basis_coefficients_slice();
    let opening_values: &[Val] = opening.as_basis_coefficients_slice();
    require(
        terminal_values.len() == 3 && opening_values.len() == 3,
        "aggregate child extension width differs from frozen cubic profile",
    )?;

    // Frozen machine/verifier/batch.rs emits these four caps, the terminal,
    // then trace_local. Match the complete prefix against the actual emitted
    // inputs rather than trusting a numeric offset. The child's public/header
    // fields precede proof_start and are never diagnostic mutation targets.
    let mut prefix = Vec::new();
    for cap in [
        &proof.commitments.main,
        &proof.commitments.quotient_chunks,
        random,
        permutation,
    ] {
        prefix.extend(cap.roots().iter().flatten().copied());
    }
    prefix.extend_from_slice(terminal_values);
    let witness_index = proof_start
        .checked_add(prefix.len())
        .ok_or_else(|| Error("aggregate child opening offset overflow".into()))?;
    prefix.extend_from_slice(opening_values);
    let prefix_end = proof_start
        .checked_add(prefix.len())
        .ok_or_else(|| Error("aggregate child proof prefix overflow".into()))?;
    require(
        inputs.values.get(proof_start..prefix_end) == Some(prefix.as_slice()),
        "aggregate child proof input prefix differs from frozen verifier layout",
    )?;
    Ok(RecursiveWitnessTarget {
        child_index,
        child_first: child.key.spec.first,
        child_count: child.key.spec.count,
        witness_index,
        original: opening_values[0],
    })
}
fn assert_constant(b: &mut ProgramBuilder, wire: Wire, value: Val) {
    let constant = b.constant(value);
    b.assert_equal(wire, constant);
}
fn public_header(b: &mut ProgramBuilder, spec: &Spec) -> Result<[Wire; PUBLIC_VALUES]> {
    let fields: [Wire; PUBLIC_VALUES] = (0..PUBLIC_VALUES)
        .map(|i| b.public(i).map_err(err))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(err)?;
    let fixed = spec.public([0; 4])?;
    // All metadata is pinned to this checked registered spec, including context
    // and u32 indices/counts. There are no unbounded metadata witness aliases.
    for i in 0..ROOT {
        assert_constant(b, fields[i], fixed[i]);
    }
    constrain_interval(b, fields[FIRST], fields[COUNT], fields[TOTAL], spec)?;
    Ok(fields)
}
fn constrain_interval(
    b: &mut ProgramBuilder,
    first: Wire,
    count: Wire,
    total: Wire,
    spec: &Spec,
) -> Result<()> {
    // The nonnegative residual is a checked u32 constant. All three metadata
    // inputs are checked-spec constants, so this sum is ordinary bounded integer
    // equality, not a field-wrap interpretation of first+count<=total.
    let remaining = b.constant(Val::from_u32(spec.remaining()?));
    let end = b.add(first, count);
    let full = b.add(end, remaining);
    b.assert_equal(full, total);
    Ok(())
}
struct EmittedChild {
    first: Wire,
    count: Wire,
    total: Wire,
    root: [Wire; 4],
    recursive_witness_target: Option<RecursiveWitnessTarget>,
}
fn emit_child(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    outer: &[Wire; PUBLIC_VALUES],
    child_index: usize,
    child: &Child<'_>,
) -> Result<EmittedChild> {
    match child {
        Child::Graph(c) => {
            let digest: [Wire; 4] = inputs
                .bases(b, &c.context.statement)
                .map_err(err)?
                .try_into()
                .map_err(err)?;
            let manifest = inputs
                .bases(b, &c.context.node_manifest)
                .map_err(err)?
                .try_into()
                .map_err(err)?;
            let expected = ContextWires {
                context: outer[CONTEXT..CONTEXT + 8].try_into().unwrap(),
                statement: digest,
                node_manifest: manifest,
            };
            // GraphKey's private trusted construction pins its graph profile;
            // graph_child and compile_merge checked that profile against Plan.
            c.key
                .compile_complete(b, inputs, c.proof, &expected)
                .map_err(err)?;
            let first = b.constant(Val::from_u32(c.spec.first));
            let count = b.constant(Val::ONE);
            let total = b.constant(Val::from_u32(c.spec.plan.total()));
            b.assert_equal(total, outer[TOTAL]);
            let mut fields = vec![first, total];
            fields.extend(digest);
            let root = b.hash_fields(LEAF_DOMAIN, &fields);
            constrain_interval(b, first, count, total, &c.spec)?;
            Ok(EmittedChild {
                first,
                count,
                total,
                root,
                recursive_witness_target: None,
            })
        }
        Child::Batch(n) => {
            let fields = inputs.bases(b, &n.proof.public).map_err(err)?;
            let proof_start = inputs.values.len();
            let cap: Vec<_> = n
                .key
                .cap
                .iter()
                .map(|root| root.map(|v| b.constant(v)))
                .collect();
            verifier::batch::verify(b, inputs, &n.key.air()?, &fields, &cap, &n.proof.proof)
                .map_err(err)?;
            let recursive_witness_target =
                recursive_witness_target(child_index, n, proof_start, inputs)?;
            for i in 0..16 {
                b.assert_equal(fields[i], outer[i]);
            }
            let fixed = n.key.spec.public([0; 4])?;
            for i in MODE..=TOTAL {
                assert_constant(b, fields[i], fixed[i]);
            }
            b.assert_equal(fields[TOTAL], outer[TOTAL]);
            constrain_interval(b, fields[FIRST], fields[COUNT], fields[TOTAL], &n.key.spec)?;
            Ok(EmittedChild {
                first: fields[FIRST],
                count: fields[COUNT],
                total: fields[TOTAL],
                root: fields[ROOT..ROOT + 4].try_into().unwrap(),
                recursive_witness_target: Some(recursive_witness_target),
            })
        }
    }
}
/// Both actual child proofs are checked natively, then both full verifiers and
/// the canonical ordered coverage/root constraints are emitted into one program.
/// Owned aggregate children are dropped before this function returns its witness.
pub fn compile_merge(children: [Child<'_>; 2]) -> Result<CompiledNode> {
    compile_merge_impl(children, None)
}

#[cfg(feature = "opencl")]
pub(crate) fn compile_merge_with_context(
    children: [Child<'_>; 2],
    execution: &lattica_pq_ringct_research::execution::ProvingContext,
) -> Result<CompiledNode> {
    if execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
        execution
            .with_witness_preparation(execution.host_bytes() as usize, |operations| {
                let root = gpu_merge_root(&children, operations).map_err(|e| e.to_string())?;
                compile_merge_impl(children, Some(root)).map_err(|e| e.to_string())
            })
            .map(|(compiled, _)| compiled)
            .map_err(Error)
    } else {
        compile_merge(children)
    }
}

#[cfg(feature = "opencl")]
pub(crate) fn compile_merge_on_gpu(
    children: [Child<'_>; 2],
    host_bytes: usize,
) -> Result<CompiledNode> {
    lattica_prover_p3::block_v2::native_gpu::with_operations(
        host_bytes,
        lattica_pq_ringct_research::opencl::strict_request(),
        |operations| {
            let root = gpu_merge_root(&children, operations).map_err(|e| e.to_string())?;
            compile_merge_impl(children, Some(root)).map_err(|e| e.to_string())
        },
    )
    .map(|(compiled, _)| compiled)
    .map_err(Error)
}

#[cfg(feature = "opencl")]
fn gpu_merge_root(
    children: &[Child<'_>; 2],
    operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
) -> Result<[u64; 4]> {
    let spec = Spec::merge(children[0].spec(), children[1].spec())?;
    let counts = [children[0].spec().count, children[1].spec().count];
    let mut roots = [[0; 4]; 2];
    for (child, root) in children.iter().zip(&mut roots) {
        *root = match child {
            Child::Graph(c) => {
                let fields =
                    leaf_fields(&c.spec, c.context.statement.map(|v| v.as_canonical_u64()))?;
                operations
                    .commit_field_chunks([LEAF_DOMAIN, fields.len() as u64, 0, 0], &fields)
                    .map_err(Error)?
            }
            Child::Batch(_) => child.root()?,
        };
    }
    let mut fields = node_metadata(&spec, counts[0], counts[1])?.to_vec();
    fields.extend(roots[0]);
    fields.extend(roots[1]);
    operations
        .commit_field_chunks([NODE_DOMAIN, fields.len() as u64, 0, 0], &fields)
        .map_err(Error)
}

fn compile_merge_impl(
    children: [Child<'_>; 2],
    prepared_root: Option<[u64; 4]>,
) -> Result<CompiledNode> {
    let spec = Spec::merge(children[0].spec(), children[1].spec())?;
    for child in &children {
        child.verify()?;
    }
    let counts = [children[0].spec().count, children[1].spec().count];
    let root = match prepared_root {
        Some(root) => root,
        None => node_root(
            &spec,
            counts[0],
            counts[1],
            [children[0].root()?, children[1].root()?],
        )?,
    };
    let public = spec.public(root)?;
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).map_err(err)?;
    let outer = public_header(&mut b, &spec)?;
    let mut inputs = ProofInputs::default();
    let left = emit_child(&mut b, &mut inputs, &outer, 0, &children[0])?;
    let right = emit_child(&mut b, &mut inputs, &outer, 1, &children[1])?;
    let recursive_witness_targets = [
        left.recursive_witness_target,
        right.recursive_witness_target,
    ]
    .into_iter()
    .flatten()
    .collect();
    b.assert_equal(left.first, outer[FIRST]);
    let adjacent = b.add(left.first, left.count);
    b.assert_equal(adjacent, right.first);
    let count = b.add(left.count, right.count);
    b.assert_equal(count, outer[COUNT]);
    b.assert_equal(left.total, outer[TOTAL]);
    b.assert_equal(right.total, outer[TOTAL]);
    let mut fields: Vec<_> = node_metadata(&spec, counts[0], counts[1])?
        .into_iter()
        .map(|v| b.constant(Val::from_u64(v)))
        .collect();
    fields.extend(left.root);
    fields.extend(right.root);
    let root = b.hash_fields(NODE_DOMAIN, &fields);
    for i in 0..4 {
        b.assert_equal(root[i], outer[ROOT + i]);
    }
    let program = Arc::new(b.finish(None).map_err(err)?);
    drop(children);
    Ok(CompiledNode {
        spec,
        program,
        public,
        witness: inputs.values,
        recursive_witness_targets,
    })
}
impl CompiledNode {
    pub fn public_values(&self) -> &[Val; PUBLIC_VALUES] {
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
            memory_budget != 0 && self.geometry()?.retained_lde_bytes <= memory_budget,
            "batch node exceeds retained-LDE memory admission",
        )?;
        let registered =
            RegisteredProgram::new_with_memory_budget(MachineAir::from_shared_program(self.program), memory_budget)
                .map_err(err)?;
        Ok(PreparedNode {
            spec: self.spec,
            registered,
            public: self.public,
            witness: self.witness,
        })
    }

    /// Register the unchanged recursive relation through an initialized,
    /// bounded OpenCL session. An explicit GPU request prevents CPU fallback.
    #[cfg(feature = "opencl")]
    pub fn prepare_opencl(
        self,
        session: &lattica_pq_ringct_research::opencl::Session,
    ) -> Result<PreparedNode> {
        let limits = session.limits();
        session.check_rows(self.program.height()).map_err(Error)?;
        require(
            self.geometry()?.retained_lde_bytes <= limits.host_bytes,
            "batch node exceeds retained-LDE host admission",
        )?;
        let registered = RegisteredProgram::new_with_request(
            MachineAir::from_shared_program(self.program),
            limits.host_bytes,
            lattica_pq_ringct_research::opencl::strict_request(),
        )
        .map_err(err)?;
        Ok(PreparedNode {
            spec: self.spec,
            registered,
            public: self.public,
            witness: self.witness,
        })
    }

    /// Explicit acceptance diagnostics for real aggregate children, before
    /// proving-state registration. Each temporary mutation changes only the
    /// first base coefficient of that child's first trace opening. Public
    /// values and the already compiled program remain unchanged.
    ///
    /// The returned checks require the ordinary valid merge proof as their
    /// positive control. No extra positive trace or proof is generated here.
    /// evaluation_budget bounds principal temporary buffers, including the
    /// full trace if a mutation unexpectedly succeeds; it is not a process RSS
    /// bound and does not replace the caller's process/resource guards.
    pub fn prepare_with_recursive_witness_checks(
        mut self,
        memory_budget: u64,
        evaluation_budget: u64,
    ) -> Result<(PreparedNode, Vec<RecursiveWitnessCheck>)> {
        require(
            memory_budget != 0 && self.geometry()?.retained_lde_bytes <= memory_budget,
            "batch node exceeds retained-LDE memory admission",
        )?;
        let checks = self.evaluate_recursive_witness_checks(evaluation_budget)?;
        Ok((self.prepare(memory_budget)?, checks))
    }

    /// Evaluate aggregate-child opening mutations against the actual compiled
    /// verifier without registration or proof generation. All original witness
    /// values are restored before returning, including on an evaluation error.
    pub fn evaluate_recursive_witness_checks(
        &mut self,
        evaluation_budget: u64,
    ) -> Result<Vec<RecursiveWitnessCheck>> {
        require(
            !self.recursive_witness_targets.is_empty(),
            "recursive witness checks require an aggregate child",
        )?;
        let principal_buffer_bound_bytes = self
            .program
            .height()
            .checked_mul(WIDTH)
            .and_then(|fields| fields.checked_add(self.program.wire_count()))
            .and_then(|fields| fields.checked_mul(core::mem::size_of::<Val>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| Error("recursive witness evaluation buffer bound overflow".into()))?;
        require(
            evaluation_budget != 0 && principal_buffer_bound_bytes <= evaluation_budget,
            "recursive witness evaluation exceeds principal-buffer admission",
        )?;
        let air = MachineAir::from_shared_program(Arc::clone(&self.program));
        let mut checks = Vec::with_capacity(self.recursive_witness_targets.len());
        for target in &self.recursive_witness_targets {
            let original = *self
                .witness
                .get(target.witness_index)
                .ok_or_else(|| Error("aggregate child opening target is outside witness".into()))?;
            require(
                original == target.original,
                "aggregate child opening target differs from compiled proof input",
            )?;
            self.witness[target.witness_index] = original + Val::ONE;
            let started = Instant::now();
            let evaluated = air.trace(&self.public, &self.witness);
            let evaluation_seconds = started.elapsed().as_secs_f64();
            // Restore before matching every normal return, including unexpected
            // errors and a successful full trace. No mutated witness is registered.
            self.witness[target.witness_index] = original;
            match evaluated {
                Err(ExecutionError::Unsatisfied) => {}
                Err(error) => {
                    return Err(Error(format!(
                        "aggregate child opening mutation returned unexpected error: {error:?}"
                    )));
                }
                Ok(trace) => {
                    drop(trace);
                    return Err(Error(
                        "aggregate child opening mutation satisfied compiled verifier".into(),
                    ));
                }
            }
            checks.push(RecursiveWitnessCheck {
                child_index: target.child_index,
                child_first: target.child_first,
                child_count: target.child_count,
                principal_buffer_bound_bytes,
                evaluation_seconds,
            });
        }
        Ok(checks)
    }

    /// Prove the current checked node using the context's explicit backend and
    /// registered-program registry. Public values, witnesses and node metadata
    /// always come from this invocation, even when registration is reused.
    pub fn prove_with_context(
        self,
        execution: &lattica_pq_ringct_research::execution::ProvingContext,
    ) -> Result<BatchNode> {
        self.spec.validate_public(&self.public)?;
        require(
            self.geometry()?.retained_lde_bytes <= execution.host_bytes(),
            "batch node exceeds retained-LDE memory admission; this is not a peak-memory bound",
        )?;
        let Self {
            spec,
            program,
            public,
            witness,
            ..
        } = self;
        let scope = format!(
            "batch span=[{},{}] level={}",
            spec.first,
            spec.count,
            spec.level()
        );
        execution.with_registered_shared(program, |registered| {
            let key = BatchKey {
                spec: spec.clone(),
                height: registered.air().program().height(),
                cap: registered.preprocessing_cap().roots().to_vec(),
                verifier: registered.verifier(),
            };
            let detail = format!(
                "{scope} program={:02x?} registered_id={:?} cap_sha3={:02x?} cache_policy=fresh_only",
                registered.program_identity(), registered.id(),
                lattica_pq_ringct_research::proof_cache_policy::cap_identity(&key.cap),
            );
            let work = || -> std::result::Result<BatchNode, String> {
                let proof = registered.prove(&public, &witness)?;
                registered.verify(&proof, &public)?;
                Ok(BatchNode { key, proof: BatchProof { public, proof } })
            };
            work().map_err(|error| format!("{detail}: {error}"))
        }).map_err(|error| Error(format!("{scope}: {error}")))
    }
}

/// Serializable fields alone confer no authority; a locally registered BatchKey
/// and verify_expected against the original statements are required.
pub struct BatchProof {
    pub public: [Val; PUBLIC_VALUES],
    pub proof: RawProof<Config>,
}
#[derive(Clone)]
pub struct BatchKey {
    spec: Spec,
    height: usize,
    cap: Vec<[Val; 4]>,
    verifier: Arc<RegisteredVerifier>,
}
impl BatchKey {
    fn air(&self) -> Result<MachineAir> {
        // The universal machine verifier needs public width/height and its
        // registration-derived cap; retaining the prepared LDE is unnecessary.
        Ok(MachineAir::new(
            ProgramBuilder::new(PUBLIC_VALUES)
                .map_err(err)?
                .finish(Some(self.height))
                .map_err(err)?,
        ))
    }
    pub fn span(&self) -> (u32, u32) {
        (self.spec.first, self.spec.count)
    }
    pub fn level(&self) -> u32 {
        self.spec.level()
    }
    pub fn total(&self) -> u32 {
        self.spec.plan.total()
    }
    pub fn batch_profile(&self) -> [u8; 32] {
        self.spec.plan.batch_profile()
    }
    /// Verify this exact registered interval; this is not complete-batch acceptance.
    pub fn verify(&self, proof: &BatchProof) -> Result<()> {
        self.spec.validate_public(&proof.public)?;
        self.verifier
            .verify(&proof.proof, &proof.public)
            .map_err(err)
    }
    pub fn verify_expected(&self, proof: &BatchProof, statements: &[LeafStatement]) -> Result<()> {
        require(
            self.spec.complete(),
            "incomplete ordered transaction coverage",
        )?;
        let expected = self.spec.plan.expected_public(statements)?;
        require(
            proof.public == expected,
            "unexpected ordered original statements",
        )?;
        self.verify(proof)
    }
}
pub struct BatchNode {
    key: BatchKey,
    proof: BatchProof,
}
impl BatchNode {
    pub fn key(&self) -> &BatchKey {
        &self.key
    }
    pub fn proof(&self) -> &BatchProof {
        &self.proof
    }
    pub fn into_parts(self) -> (BatchKey, BatchProof) {
        (self.key, self.proof)
    }
}
pub struct PreparedNode {
    spec: Spec,
    registered: RegisteredProgram,
    public: [Val; PUBLIC_VALUES],
    witness: Vec<Val>,
}
impl PreparedNode {
    pub fn key(&self) -> BatchKey {
        BatchKey {
            spec: self.spec.clone(),
            height: self.registered.air().program().height(),
            cap: self.registered.preprocessing_cap().roots().to_vec(),
            verifier: Arc::new(self.registered.verifier()),
        }
    }
    pub fn public_values(&self) -> &[Val; PUBLIC_VALUES] {
        &self.public
    }
    /// Cache domain is deliberately distinct from the frozen graph/outer caches.
    /// The caller's batch build/source identity must describe this external crate.
    /// A cache hit must still pass accept_cached under fresh trusted registration.
    pub fn cache_identity(&self, source_identity: [u8; 32]) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/ordered-batch/registered-node-cache/v1");
        hash.update(source_identity);
        hash.update((self.registered.air().program().height() as u64).to_le_bytes());
        let cap = self.registered.preprocessing_cap().roots();
        hash.update((cap.len() as u64).to_le_bytes());
        for value in cap.iter().flatten().chain(self.public.iter()) {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        hash.finalize().into()
    }
    /// Consumes and drops prepared proving state before returning the compact node.
    pub fn prove(self) -> Result<BatchNode> {
        let proof = self
            .registered
            .prove(&self.public, &self.witness)
            .map_err(err)?;
        let public = self.public;
        self.accept_cached(BatchProof { public, proof })
    }

    /// Require observed GPU stages for the actual parent proof. Registered
    /// preprocessing is re-admitted by the backend; CPU-prepared state cannot
    /// be relabeled as strict GPU work. Consumes all prepared proving state.
    #[cfg(feature = "opencl")]
    pub fn prove_opencl(
        self,
        session: &lattica_pq_ringct_research::opencl::Session,
    ) -> Result<BatchNode> {
        session
            .check_rows(self.registered.air().program().height())
            .map_err(Error)?;
        let proof = self
            .registered
            .prove_with_request(
                &self.public,
                &self.witness,
                lattica_pq_ringct_research::opencl::strict_request(),
            )
            .map_err(err)?;
        let public = self.public;
        self.accept_cached(BatchProof { public, proof })
    }
    /// Attach public cached bytes only after exact-public and actual cryptographic
    /// verification. No key, cap or acceptance receipt is loaded from the cache.
    pub fn accept_cached(self, proof: BatchProof) -> Result<BatchNode> {
        require(
            proof.public == self.public,
            "cached batch public statement mismatch",
        )?;
        self.registered
            .verify(&proof.proof, &proof.public)
            .map_err(err)?;
        let key = self.key();
        drop(self);
        Ok(BatchNode { key, proof })
    }
}
