//! Bounded compilation from genuine source-authenticated child owners.
//! The legacy leaf entry remains restricted; the closed child entry covers
//! all four original parent edges, including parent/parent and parent/leaf.
use super::super::super::super::Node as SourceNode;
use super::*;
use crate::component_tree::{
    CompiledNode, MachineAir, Program, ProgramBuilder, COUNT, FIRST, LEVEL,
};
use lattica_prover_p3::block_v2::machine::{
    program::{ExecutionError, ProofInputs, Wire},
    verifier::{batch, CompileError},
};
use std::sync::Arc;

mod bank;
mod children;
pub(in crate::component_tree::owned_shake) use children::{
    AcceptedChild, AcceptedParent, CapturedParentAcceptance, ParentAcceptanceReport,
    PreissuedParentAcceptance,
};

type Source<'source, 'request> = ParentSourceBound<'source, 'request>;
const PUBLICS: usize = HEADER + 8;

#[derive(Clone, Copy, Debug)]
struct Storage {
    core: super::super::super::PlanningStorage,
    complete: Requirements,
}

/// This owner must be issued before native capacity is assigned. It accepts
/// only the exact child edges of the immutable original request tree.
pub(in crate::component_tree::owned_shake) struct PreissuedLeafParentCompiler<
    'bound,
    'source,
    'request,
> {
    source: &'bound Source<'source, 'request>,
    ordinal: usize,
    children: [SourceNode; 2],
    specs: [Spec; 3],
    storage: Storage,
    original: Reservation,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::component_tree::owned_shake) struct LeafParentCompilationReport {
    pub(in crate::component_tree::owned_shake) ordinal: usize,
    pub(in crate::component_tree::owned_shake) first: u32,
    pub(in crate::component_tree::owned_shake) count: u32,
    pub(in crate::component_tree::owned_shake) level: u32,
    pub(in crate::component_tree::owned_shake) active_rows: usize,
    pub(in crate::component_tree::owned_shake) padded_rows: usize,
    pub(in crate::component_tree::owned_shake) wires: usize,
    pub(in crate::component_tree::owned_shake) witness_values: usize,
    pub(in crate::component_tree::owned_shake) retained_program_bytes: usize,
    pub(in crate::component_tree::owned_shake) compiler_elapsed_ns: u128,
    pub(in crate::component_tree::owned_shake) independently_authenticated_children: usize,
    pub(in crate::component_tree::owned_shake) parent_proof_generated: bool,
    pub(in crate::component_tree::owned_shake) workflow_admitted: bool,
}

struct Payload(CompiledNode);
impl Drop for Payload {
    fn drop(&mut self) {
        for value in &mut self.0.witness {
            // SAFETY: the original witness buffer is exclusively owned here.
            unsafe { core::ptr::write_volatile(value, Val::ZERO) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Retains the whole original compiler claim until the compiled payload dies.
/// No raw program, witness, key, proof or reservation can escape this owner.
pub(in crate::component_tree::owned_shake) struct CompiledLeafParent<'bound, 'source, 'request> {
    payload: Payload,
    source: &'bound Source<'source, 'request>,
    report: LeafParentCompilationReport,
    original: Reservation,
}

/// A temporary borrow created only inside the admitted fixed compiler. The
/// output module can emit the exact original child through it, but cannot
/// construct it, extract its compiler, select another child, or retain it.
pub(in crate::component_tree::owned_shake) struct ParentChildEmission<
    'phase,
    'child,
    'bound,
    'source,
    'request,
> {
    builder: &'phase mut ProgramBuilder,
    inputs: &'phase mut ProofInputs,
    child: &'child AcceptedChild<'bound, 'source, 'request>,
    spec: &'child Spec,
    ledger: &'child Ledger,
}

pub(in crate::component_tree::owned_shake) struct EmittedParentChild {
    wires: [Wire; PUBLICS],
    public: [Val; PUBLICS],
}

fn frames<T>(count: usize) -> Result<usize> {
    super::super::super::times(count, size_of::<T>())
}

fn caller_bytes() -> Result<usize> {
    let parts = [
        frames::<PreissuedLeafParentCompiler<'static, 'static, 'static>>(8)?,
        frames::<Result<PreissuedLeafParentCompiler<'static, 'static, 'static>>>(8)?,
        frames::<CompiledLeafParent<'static, 'static, 'static>>(8)?,
        frames::<Result<CompiledLeafParent<'static, 'static, 'static>>>(8)?,
        frames::<AcceptedLeaf<'static, 'static, 'static>>(16)?,
        frames::<AcceptedChild<'static, 'static, 'static>>(16)?,
        children::additional_host_bytes()?,
        frames::<ParentChildEmission<'static, 'static, 'static, 'static, 'static>>(8)?,
        frames::<EmittedParentChild>(8)?,
        frames::<Result<EmittedParentChild>>(8)?,
        frames::<ProgramBuilder>(8)?,
        frames::<core::result::Result<ProgramBuilder, ExecutionError>>(8)?,
        frames::<Program>(8)?,
        frames::<core::result::Result<Program, ExecutionError>>(8)?,
        frames::<MachineAir>(8)?,
        frames::<ProofInputs>(8)?,
        frames::<CompiledNode>(8)?,
        frames::<Payload>(8)?,
        frames::<Result<Payload>>(8)?,
        frames::<LeafParentCompilationReport>(8)?,
        frames::<Storage>(8)?,
        frames::<Result<Storage>>(8)?,
        frames::<Spec>(24)?,
        frames::<Result<Spec>>(8)?,
        frames::<[Spec; 3]>(8)?,
        frames::<Result<([SourceNode; 2], [Spec; 3])>>(8)?,
        frames::<SourceNode>(32)?,
        frames::<[SourceNode; 2]>(8)?,
        frames::<[[Wire; 4]; ROOTS]>(8)?,
        frames::<[Wire; PUBLICS]>(24)?,
        frames::<[Val; PUBLICS]>(24)?,
        frames::<Vec<Wire>>(16)?,
        frames::<core::result::Result<[Wire; PUBLICS], Vec<Wire>>>(8)?,
        frames::<core::result::Result<[Val; PUBLICS], core::array::TryFromSliceError>>(8)?,
        frames::<core::result::Result<Vec<Wire>, CompileError>>(8)?,
        frames::<core::result::Result<Wire, ExecutionError>>(8)?,
        frames::<core::result::Result<(), CompileError>>(8)?,
        frames::<Result<()>>(16)?,
        frames::<Requirements>(16)?,
        frames::<Reservation>(8)?,
        frames::<super::super::super::PlanningStorage>(8)?,
        frames::<[batch::shape::RegisteredChildShape; 2]>(8)?,
        frames::<std::time::Instant>(8)?,
        frames::<[usize; 2]>(8)?,
        frames::<usize>(16)?,
        // Original fixed core helpers are charged by PlanningStorage below.
        // This adds complete iterator/error/header/Arc/return framing, plus
        // bounded diagnostics, without inlining or move-elision credit.
        64 << 10,
    ];
    let helper = super::super::super::times(8, size_of_val(&parts))?;
    parts.into_iter().try_fold(helper, super::super::super::add)
}

impl Storage {
    fn source() -> Result<Self> {
        let shape = super::super::super::shape(crate::component_tree::owned_shake::MAX_ROWS)?;
        let core = super::super::super::PlanningStorage::for_children(
            PUBLICS,
            &[shape, shape],
            super::super::super::construction(),
        )
        .map_err(|_| Error::Source)?;
        if core.auxiliary_peak_bytes > crate::component_tree::owned_shake::AUXILIARY_BYTES {
            return Err(Error::Capacity);
        }
        let mut complete = super::super::super::requirement(
            Category::SymbolicCompiler,
            crate::component_tree::owned_shake::PROGRAM_BYTES,
        )?;
        for (category, bytes) in [
            (
                Category::CompilerInputs,
                super::super::super::add(core.input_backing_bytes, frames::<Val>(2 * PUBLICS)?)?,
            ),
            (
                Category::PhaseScratch,
                core.auxiliary_peak_bytes
                    .checked_sub(core.input_backing_bytes)
                    .ok_or(Error::Overflow)?,
            ),
            (Category::RegisteredMetadata, caller_bytes()?),
        ] {
            complete
                .add(
                    category,
                    Bytes {
                        host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
                        device: 0,
                    },
                )
                .map_err(|_| Error::Overflow)?;
        }
        Ok(Self { core, complete })
    }
}

fn node_spec(source: &Source<'_, '_>, node: SourceNode, before: usize) -> Result<Spec> {
    let contract = source
        .request
        .owner
        .request()
        .contract()
        .map_err(|_| Error::Source)?;
    match node {
        SourceNode::Leaf(index) => {
            let span = source.request.tree.leaves.get(index).ok_or(Error::Source)?;
            if span.level != 0 {
                return Err(Error::Source);
            }
            contract
                .span(span.first, span.count)
                .map_err(|_| Error::Source)
        }
        SourceNode::Parent(index) if index < before => {
            let (_, specs) = specs(source, index)?;
            Ok(specs[2].clone())
        }
        SourceNode::Parent(_) => Err(Error::Source),
    }
}

fn specs(source: &Source<'_, '_>, ordinal: usize) -> Result<([SourceNode; 2], [Spec; 3])> {
    let parent = source
        .request
        .tree
        .parents
        .get(ordinal)
        .and_then(|entry| *entry)
        .ok_or(Error::Source)?;
    let left_spec = node_spec(source, parent.left, ordinal)?;
    let right_spec = node_spec(source, parent.right, ordinal)?;
    let merged = Spec::merge(&left_spec, &right_spec).map_err(|_| Error::Source)?;
    if (merged.first, merged.count, merged.level)
        != (
            parent.interval.first,
            parent.interval.count,
            parent.interval.level,
        )
    {
        return Err(Error::Source);
    }
    Ok(([parent.left, parent.right], [left_spec, right_spec, merged]))
}

impl<'source, 'request> ParentSourceBound<'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn preissue_leaf_parent_compiler<'bound>(
        &'bound self,
        ordinal: usize,
        ledger: &Ledger,
    ) -> Result<PreissuedLeafParentCompiler<'bound, 'source, 'request>> {
        let (children, _) = specs(self, ordinal)?;
        if !matches!(children, [SourceNode::Leaf(_), SourceNode::Leaf(_)]) {
            return Err(Error::Source);
        }
        self.preissue_parent_compiler(ordinal, ledger)
    }

    pub(in crate::component_tree::owned_shake) fn preissue_parent_compiler<'bound>(
        &'bound self,
        ordinal: usize,
        ledger: &Ledger,
    ) -> Result<PreissuedLeafParentCompiler<'bound, 'source, 'request>> {
        if !self.is_for(self.request, ledger) {
            return Err(Error::Authority);
        }
        let (children, specs) = specs(self, ordinal)?;
        let storage = Storage::source()?;
        let original = ledger
            .admit_phase(storage.complete)
            .map_err(|_| Error::Capacity)?;
        Ok(PreissuedLeafParentCompiler {
            source: self,
            ordinal,
            children,
            specs,
            storage,
            original,
        })
    }
}

fn original_leaf(
    child: &AcceptedLeaf<'_, '_, '_>,
    source: &Source<'_, '_>,
    index: usize,
    ledger: &Ledger,
) -> Result<()> {
    if !core::ptr::eq(child.source, source)
        || child.index != index
        || !child.original.belongs_to(ledger)
        || child.original.requirements() != super::metadata_requirement()?
        || !child.cap_original.belongs_to(ledger)
        || child.cap_original.requirements() != super::super::requirements()?
        || !child.output.belongs_to(ledger)
        || !child.report.source_key_authenticated
        || child.report.leaf != index
        || child.report.height != child.height
        || child.report.workflow_admitted
    {
        return Err(Error::Authority);
    }
    super::super::super::shape(child.height)?;
    Ok(())
}

impl ParentChildEmission<'_, '_, '_, '_, '_> {
    /// Called only by the output's private action; it returns fixed framing
    /// wires/public values, never a key, proof, verifier, or ownership token.
    pub(in crate::component_tree::owned_shake) fn emit_original(
        &mut self,
        owner: &RetainedNodeOutput<'_>,
        key: &NodeKey,
        proof: &NodeProof,
        request: &crate::graph_crypto::ReservedShakeRequest,
    ) -> Result<EmittedParentChild> {
        if !core::ptr::eq(owner, self.child.output())
            || !core::ptr::eq(request, self.child.source().request.owner)
            || !owner.belongs_to(self.ledger)
            || key.spec != *self.spec
            || key.height != self.child.height()
            || key.cap.as_slice() != &self.child.cap()[..]
            || key.cap.capacity() != ROOTS
            || proof.public.len() != PUBLICS
        {
            return Err(Error::Source);
        }
        let public: [Val; PUBLICS] = proof
            .public
            .as_slice()
            .try_into()
            .map_err(|_| Error::Source)?;
        let wires: [Wire; PUBLICS] = self
            .inputs
            .bases(self.builder, &public)
            .map_err(|_| Error::Capacity)?
            .try_into()
            .map_err(|_| Error::Source)?;
        let placeholder = self.builder.public(0).map_err(|_| Error::Capacity)?;
        let mut cap = [[placeholder; 4]; ROOTS];
        for (out, digest) in cap.iter_mut().zip(self.child.cap()) {
            *out = digest.map(|value| self.builder.constant(value));
        }
        self.builder.public(0).map_err(|_| Error::Capacity)?;
        // Same fixed empty-AIR geometry helper as the original core source
        // census. It allocates no height-sized trace. The actual captured cap
        // binds the child's full registered program, not this empty geometry.
        let program = ProgramBuilder::new(PUBLICS)
            .and_then(|builder| builder.finish(Some(self.child.height())))
            .map_err(|_| Error::Capacity)?;
        let air = MachineAir::new(program);
        batch::verify_with_bounded_cpu_symbolic(
            self.builder,
            self.inputs,
            &air,
            &wires,
            &cap,
            &proof.proof,
        )
        .map_err(|_| Error::Planner)?;
        Ok(EmittedParentChild { wires, public })
    }
}

impl<'bound, 'source, 'request> PreissuedLeafParentCompiler<'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn compile(
        self,
        left: AcceptedLeaf<'bound, 'source, 'request>,
        right: AcceptedLeaf<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> Result<CompiledLeafParent<'bound, 'source, 'request>> {
        self.compile_children(
            AcceptedChild::Leaf(left),
            AcceptedChild::Leaf(right),
            ledger,
        )
    }

    pub(in crate::component_tree::owned_shake) fn compile_children(
        self,
        left: AcceptedChild<'bound, 'source, 'request>,
        right: AcceptedChild<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> Result<CompiledLeafParent<'bound, 'source, 'request>> {
        if !self.source.is_for(self.source.request, ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != self.storage.complete
            || self.storage.complete != Storage::source()?.complete
        {
            return Err(Error::Authority);
        }
        let (expected_children, expected_specs) = specs(self.source, self.ordinal)?;
        if self.children != expected_children || self.specs != expected_specs {
            return Err(Error::Source);
        }
        left.check_original(self.source, self.children[0], ledger)?;
        right.check_original(self.source, self.children[1], ledger)?;
        let started = std::time::Instant::now();
        let mut builder = ProgramBuilder::new_with_construction_limits(
            PUBLICS,
            super::super::super::construction(),
        )
        .map_err(|_| Error::Capacity)?;
        let outer: [Wire; PUBLICS] =
            crate::component_tree::public_wires(&mut builder, &self.specs[2])
                .map_err(|_| Error::Capacity)?
                .try_into()
                .map_err(|_| Error::Source)?;
        let mut inputs = ProofInputs::default();
        let left_emitted = left.output().emit_parent_child(&mut ParentChildEmission {
            builder: &mut builder,
            inputs: &mut inputs,
            child: &left,
            spec: &self.specs[0],
            ledger,
        })?;
        let right_emitted = right.output().emit_parent_child(&mut ParentChildEmission {
            builder: &mut builder,
            inputs: &mut inputs,
            child: &right,
            spec: &self.specs[1],
            ledger,
        })?;
        super::super::super::framing::emit(
            &mut builder,
            &self.specs[2],
            &outer,
            &left_emitted.wires,
            &right_emitted.wires,
        )?;
        let mut public = left_emitted.public;
        public[FIRST] = Val::from_u32(self.specs[2].first);
        public[COUNT] = Val::from_u32(self.specs[2].count);
        public[LEVEL] = Val::from_u32(self.specs[2].level);
        public[HEADER + 4..].copy_from_slice(&right_emitted.public[HEADER + 4..]);
        let program = builder.finish(None).map_err(|_| Error::Capacity)?;
        let counts = batch::shape::OperationCounts::from_program(&program);
        let bound = self.source.geometry;
        let retained_program_bytes = program.retained_host_bytes().map_err(|_| Error::Capacity)?;
        let retained_input_bytes = inputs
            .values
            .capacity()
            .checked_mul(size_of::<Val>())
            .ok_or(Error::Overflow)?;
        if counts.scalar > bound.operations.scalar
            || counts.cubic > bound.operations.cubic
            || counts.poseidon > bound.operations.poseidon
            || program.public_values() != PUBLICS
            || program.active_rows() > bound.active_rows_upper_bound
            || program.height() > bound.padded_rows_upper_bound
            || program.wire_count() > bound.wires_upper_bound
            || program.witness_values() > bound.input_values_upper_bound
            || program.witness_values() != inputs.values.len()
            || inputs.values.capacity() > crate::component_tree::owned_shake::INPUT_VALUES
            || retained_program_bytes > crate::component_tree::owned_shake::PROGRAM_BYTES
            || retained_input_bytes > self.storage.core.input_backing_bytes
        {
            return Err(Error::Capacity);
        }
        let report = LeafParentCompilationReport {
            ordinal: self.ordinal,
            first: self.specs[2].first,
            count: self.specs[2].count,
            level: self.specs[2].level,
            active_rows: program.active_rows(),
            padded_rows: program.height(),
            wires: program.wire_count(),
            witness_values: program.witness_values(),
            retained_program_bytes,
            compiler_elapsed_ns: started.elapsed().as_nanos(),
            independently_authenticated_children: 2,
            parent_proof_generated: false,
            workflow_admitted: false,
        };
        let public = public.to_vec();
        if public.capacity() > 2 * PUBLICS {
            return Err(Error::Capacity);
        }
        let payload = Payload(CompiledNode {
            spec: self.specs[2].clone(),
            program: Arc::new(program),
            public,
            witness: inputs.values,
        });
        // Every proof/public value has moved into the admitted input owner.
        // The two original retained proofs/caps may die only after emission.
        drop(left);
        drop(right);
        Ok(CompiledLeafParent {
            payload,
            source: self.source,
            report,
            original: self.original,
        })
    }
}

impl CompiledLeafParent<'_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn report(&self) -> LeafParentCompilationReport {
        self.report
    }
}

#[cfg(test)]
mod tests;

impl ParentSourceBound<'_, '_> {
    pub(in crate::component_tree::owned_shake) fn parent_outer_shape(
        &self,
        ordinal: usize,
        ledger: &Ledger,
    ) -> Result<lattica_prover_p3::block_v2::machine::OuterSourceShape> {
        if !self.is_for(self.request, ledger) {
            return Err(Error::Authority);
        }
        specs(self, ordinal)?;
        let geometry = self.geometry;
        lattica_prover_p3::block_v2::machine::OuterSourceShape::registered_parent_bounds(
            geometry.operations,
            geometry.wires_upper_bound,
            geometry.input_values_upper_bound,
            geometry.selection_hint_words_upper_bound,
        )
        .map_err(|_| Error::Source)
    }
}
impl ParentSourceBound<'_, '_> {
    pub(in crate::component_tree::owned_shake) fn check_original_request(
        &self,
        request: &crate::graph_crypto::ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<()> {
        if !core::ptr::eq(self.request.owner, request) || !self.is_for(self.request, ledger) {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

// Private primitive: only the future same-subtree combined bank/sequence can
// reach parent production; no raw compiler or continuation entry is exported.
mod production;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use production::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};
