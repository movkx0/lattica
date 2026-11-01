//! Source-derived compiler facts for arbitrary unchanged SHAKE partitions.
//!
//! These values carry no execution authority. The workflow planner reserves
//! their construction before calling `inspect`; runtime operations additionally
//! require the original whole-workflow phase and retained input owners.

use super::{PairedFailure, Result};
use crate::{
    component_tree::{
        native_shape::{self, framing, NativeDescriptor, NativePlanningStorage},
        CompiledNode, ShakeGroupCompileFootprint, HEADER,
    },
    execution::retained_resources::{Bytes, Category, Requirements},
    graph_crypto::{Request, RequestDescriptor, ShakeWrapperSpan},
};
mod aes;
pub(crate) use aes::AesBlueprint;

use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, MAX_WIRES},
    verifier::{
        batch::shape::{self, OperationCounts, PlanningStorage, RegisteredChildShape},
        uni::shape::NativeCoreMetadata as NativeCoreCounts,
    },
    OuterSourceShape,
};

pub(crate) const MAX_ROWS: usize = 1 << 20;
pub(crate) const PROGRAM_BYTES: usize = 2 << 30;
pub(crate) const INPUT_VALUES: usize = 1 << 20;
pub(crate) const AUXILIARY_BYTES: usize = 512 << 20;
pub(crate) const PUBLICS: usize = HEADER + 8;

pub(crate) fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(PairedFailure::Overflow)
}
pub(crate) fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).filter(|n| *n <= isize::MAX as usize)
        .ok_or(PairedFailure::Overflow)
}
pub(crate) fn bytes<T>(count: usize) -> Result<usize> {
    mul(size_of::<T>(), count)
}
/// Pure public boundary framing census; private Contract methods and Spec
/// never cross the component-tree ownership boundary.
pub(crate) fn boundary_preparation_words(request: &Request) -> Result<usize> {
    let contract = request.contract().map_err(|_| PairedFailure::Source)?;
    add(contract.boundary_width(), 2)
}
pub(crate) fn requirement(category: Category, host: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(host).map_err(|_| PairedFailure::Overflow)?, device: 0,
    }))
}
pub(crate) fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut total = Requirements::default();
    for part in parts {
        for category in Category::ALL {
            total.add(category, part.get(category)).map_err(|_| PairedFailure::Overflow)?;
        }
    }
    Ok(total)
}
pub(crate) fn maxima(a: Requirements, b: Requirements) -> Requirements {
    let mut result = Requirements::default();
    for category in Category::ALL {
        let a = a.get(category);
        let b = b.get(category);
        // A single category maximum cannot overflow a zero accumulator.
        result.add(category, Bytes { host: a.host.max(b.host), device: a.device.max(b.device) })
            .expect("one category maximum");
    }
    result
}
pub(crate) fn construction() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: PROGRAM_BYTES,
        max_wires: MAX_WIRES,
        max_input_values: INPUT_VALUES,
    }
}

/// Public source facts, never copied proof headers or observed actual rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ComponentSourceFacts {
    pub(crate) public_values: usize,
    pub(crate) operations: OperationCounts,
    pub(crate) maximum_active_rows: usize,
    pub(crate) maximum_padded_rows: usize,
    pub(crate) maximum_wires: usize,
    pub(crate) maximum_input_values: usize,
    pub(crate) maximum_hint_words: usize,
    pub(crate) input_values_are_exact: bool,
}

impl ComponentSourceFacts {
    /// Source-derived packed storage, checked against actual capacities while
    /// the complete construction allowance is still live. Compiler tables and
    /// packing overlap belong to the single active compile phase, not each
    /// retained sibling. The existing 2 GiB compiler ceiling remains unchanged.
    pub(crate) fn retained_program_host_bytes(self) -> Result<usize> {
        self.operations.retained_program_host_ceiling(self.public_values,
            self.maximum_wires, self.maximum_hint_words)
            .map(|bytes| bytes.min(PROGRAM_BYTES)).map_err(|_| PairedFailure::Overflow)
    }
    fn new(operations: OperationCounts, wires: usize, inputs: usize, hints: usize,
           input_values_are_exact: bool) -> Result<Self> {
        let active = operations.active_rows(PUBLICS).map_err(|_| PairedFailure::Overflow)?;
        let padded = operations.padded_rows(PUBLICS).map_err(|_| PairedFailure::Overflow)?;
        if PUBLICS != 46 || padded > MAX_ROWS || wires > MAX_WIRES || inputs > INPUT_VALUES {
            return Err(PairedFailure::Rows);
        }
        Ok(Self { public_values: PUBLICS, operations, maximum_active_rows: active,
            maximum_padded_rows: padded, maximum_wires: wires,
            maximum_input_values: inputs, maximum_hint_words: hints, input_values_are_exact })
    }

    pub(crate) fn outer_shape(self) -> Result<OuterSourceShape> {
        if self.input_values_are_exact {
            OuterSourceShape::owned_shake(self.operations, self.maximum_wires,
                self.maximum_input_values, self.maximum_hint_words)
        } else {
            OuterSourceShape::registered_parent_bounds(self.operations, self.maximum_wires,
                self.maximum_input_values, self.maximum_hint_words)
        }.map_err(|_| PairedFailure::Source)
    }

    pub(crate) fn check_compiled(self, node: &CompiledNode) -> Result<()> {
        let program = &node.program;
        let actual = OperationCounts::from_program(program);
        if program.public_values() != self.public_values || node.public.len() != self.public_values
            || program.active_rows() > self.maximum_active_rows
            || program.height() > self.maximum_padded_rows
            || program.wire_count() > self.maximum_wires
            || program.witness_values() > self.maximum_input_values
            || (self.input_values_are_exact && program.witness_values() != self.maximum_input_values)
            || node.witness.len() != program.witness_values()
            || program.retained_host_bytes().map_err(|_| PairedFailure::Capacity)?
                > self.retained_program_host_bytes()?
            || shape::selection_hint_words(program).map_err(|_| PairedFailure::Overflow)?
                > self.maximum_hint_words
            || actual.scalar > self.operations.scalar || actual.cubic > self.operations.cubic
            || actual.poseidon > self.operations.poseidon {
            return Err(PairedFailure::SourceDrift);
        }
        Ok(())
    }

    /// Backing is derived from the existing source-output declaration across
    /// every possible actual height. Keep its complete verifier lifecycle
    /// separately, without subtracting its already-owned proof allowance.
    pub(crate) fn output_requirements(self) -> Result<(Requirements, Requirements)> {
        let footprint = self.outer_shape()?.output_footprint().map_err(|_| PairedFailure::Source)?;
        let public = bytes::<crate::component_tree::Val>(2 * PUBLICS)?;
        let inline = bytes::<super::PairedNode<'static>>(8)?;
        let proof = footprint.proof_backing_ceiling_host_bytes
            .checked_add(public as u64).and_then(|v| v.checked_add(inline as u64))
            .ok_or(PairedFailure::Overflow)?;
        let key = footprint.verifier_metadata_retained_host_bytes
            .checked_add(footprint.copied_key_cap_host_bytes)
            .and_then(|v| v.checked_add(bytes::<super::PairedNode<'static>>(8).ok()? as u64))
            .ok_or(PairedFailure::Overflow)?;
        let mut output = Requirements::single(Category::RecursiveProof, Bytes { host: proof, device: 0 });
        output.add(Category::RegisteredMetadata, Bytes { host: key, device: 0 })
            .map_err(|_| PairedFailure::Overflow)?;
        let verifier = Requirements::single(Category::IndependentVerifier, Bytes {
            host: footprint.verifier_lifecycle_peak_host_bytes,
            device: 0,
        });
        Ok((output, verifier))
    }
}

/// Allocation-free blueprint of one exact singleton or pair. All native phase
/// geometries are validated before any symbolic planner is invoked.
pub(crate) struct GroupBlueprint {
    descriptors: [Option<NativeDescriptor<'static>>; 2],
    storage: [Option<NativePlanningStorage>; 2],
    members: usize,
    planning: Requirements,
}

impl GroupBlueprint {
    pub(crate) fn new(request: &Request, span: ShakeWrapperSpan) -> Result<Self> {
        let RequestDescriptor::Shake(descriptor) = request.descriptor() else {
            return Err(PairedFailure::Source);
        };
        if !(1..=2).contains(&span.segment_count) { return Err(PairedFailure::Coverage); }
        let mut descriptors = [None, None];
        let mut storage = [None, None];
        let mut peak = 0;
        let mut next = span.first_unit;
        for offset in 0..span.segment_count {
            let segment = request.segments().get(add(span.first_segment, offset)?)
                .ok_or(PairedFailure::Coverage)?;
            if segment.first_unit != next { return Err(PairedFailure::Coverage); }
            next = add(next, segment.units)?;
            let source = NativeDescriptor::Shake {
                descriptor, first: segment.first_unit, count: segment.units,
            };
            let geometry = source.geometry().map_err(|_| PairedFailure::Source)?;
            if geometry.width != segment.width || geometry.height != segment.height {
                return Err(PairedFailure::SourceDrift);
            }
            let bound = NativePlanningStorage::for_descriptor(source, construction())
                .map_err(|_| PairedFailure::Source)?;
            if bound.auxiliary_peak_bytes > AUXILIARY_BYTES { return Err(PairedFailure::Capacity); }
            peak = peak.max(bound.total_requested_bytes);
            descriptors[offset] = Some(source);
            storage[offset] = Some(bound);
        }
        if next != add(span.first_unit, span.units)? { return Err(PairedFailure::Coverage); }
        Ok(Self { descriptors, storage, members: span.segment_count,
            planning: requirement(Category::PhaseScratch, peak)? })
    }

    pub(crate) fn planning_requirements(&self) -> Requirements { self.planning }

    /// Caller retains the exact preflight original for the complete call.
    pub(crate) fn inspect(&self) -> Result<ComponentSourceFacts> {
        use crate::component_tree::native_shape::cohort;
        let first = self.descriptors[0].ok_or(PairedFailure::Source)?;
        let descriptors = [cohort::Descriptor::Native(first),
            cohort::Descriptor::Native(self.descriptors[1].unwrap_or(first))];
        let auxiliary = self.storage.iter().flatten().map(|s| s.auxiliary_peak_bytes).max().ok_or(PairedFailure::Source)?;
        let bounds = cohort::bounds(&descriptors[..self.members], construction(), auxiliary).map_err(|_| PairedFailure::Source)?;
        let mut cores: [Option<NativeCoreCounts>; 2] = [None, None];
        for i in 0..self.members {
            let result = bounds[i].ok_or(PairedFailure::Source)?;
            if result.storage != self.storage[i].ok_or(PairedFailure::Source)? { return Err(PairedFailure::SourceDrift); }
            cores[i] = Some(result.counts);
        }
        let framing = framing::shake_wrapper(self.members).map_err(|_| PairedFailure::Source)?;
        if framing.cubic != 0 { return Err(PairedFailure::SourceDrift); }
        let mut operations = framing;
        let mut wires = add(PUBLICS, add(framing.scalar, mul(8, framing.poseidon)?)?)?;
        let mut inputs = 0;
        let mut hints = 0;
        for core in cores.iter().flatten() {
            operations = operations.with_overhead(core.operations).map_err(|_| PairedFailure::Overflow)?;
            wires = add(wires, core.wires)?;
            inputs = add(inputs, core.input_values)?;
            hints = add(hints, core.selection_hint_words)?;
        }
        ComponentSourceFacts::new(operations, wires, inputs, hints, true)
    }
}

pub(crate) fn registered_shape(height: usize) -> Result<RegisteredChildShape> {
    if !(8..=MAX_ROWS).contains(&height) || !height.is_power_of_two() {
        return Err(PairedFailure::Rows);
    }
    use lattica_prover_p3::block_v2::profile;
    Ok(RegisteredChildShape { public_values: PUBLICS, height,
        preprocessing_cap_roots: 1 << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP)
            .min(profile::CAP_HEIGHT) })
}

pub(crate) fn parent_planning_requirements() -> Result<Requirements> {
    let storage = PlanningStorage::for_children(0, &[registered_shape(MAX_ROWS)?], construction())
        .map_err(|_| PairedFailure::Source)?;
    if storage.auxiliary_peak_bytes > AUXILIARY_BYTES { return Err(PairedFailure::Capacity); }
    requirement(Category::PhaseScratch, add(PROGRAM_BYTES, storage.auxiliary_peak_bytes)?)
}

pub(crate) fn parent_source() -> Result<ComponentSourceFacts> {
    let envelope = shape::verifier_height_envelope(PUBLICS, MAX_ROWS, construction(), AUXILIARY_BYTES)
        .map_err(|_| PairedFailure::Source)?;
    if envelope.heights_enumerated != 18 { return Err(PairedFailure::SourceDrift); }
    // Exactly the maintained component public_wires + bind_merge framing.
    let framing = OperationCounts {
        scalar: 8 * 162 + (8 + 6 + 4) * 2 + 2 * (HEADER - 3) + 5 + 3 * 4,
        cubic: 0, poseidon: 0,
    };
    let operations = envelope.operations.with_overhead(envelope.operations)
        .and_then(|n| n.with_overhead(framing)).map_err(|_| PairedFailure::Overflow)?;
    ComponentSourceFacts::new(operations,
        add(PUBLICS, add(mul(2, envelope.wire_upper_bound)?, framing.scalar)?)?,
        mul(2, envelope.input_values_upper_bound)?,
        mul(2, envelope.selection_hint_words_upper_bound)?, false)
}

/// The compiled owner keeps Program and ProofInputs charged while the outer
/// backend borrows them. Scratch is returned only after the compiler finishes.
pub(crate) fn compiler_requirements(source: ComponentSourceFacts, members: Option<usize>) -> Result<(Requirements, Requirements)> {
    let (input, auxiliary) = if let Some(members) = members {
        let source = ShakeGroupCompileFootprint::for_group(members, construction())
            .map_err(|_| PairedFailure::Source)?;
        (source.input_backing_bytes, source.auxiliary_peak_bytes)
    } else {
        let source = PlanningStorage::for_children(PUBLICS,
            &[registered_shape(MAX_ROWS)?, registered_shape(MAX_ROWS)?], construction())
            .map_err(|_| PairedFailure::Source)?;
        (source.input_backing_bytes, source.auxiliary_peak_bytes)
    };
    if auxiliary > AUXILIARY_BYTES { return Err(PairedFailure::Capacity); }
    let owners = bytes::<super::PairedCompiled<'static>>(8)?;
    let retained = source.retained_program_host_bytes()?;
    let construction_extra = PROGRAM_BYTES.checked_sub(retained).ok_or(PairedFailure::Capacity)?;
    let output = combine(&[
        requirement(Category::SymbolicCompiler, add(retained, owners)?)?,
        requirement(Category::CompilerInputs, add(input, bytes::<crate::component_tree::Val>(2 * PUBLICS)?)?)?,
    ])?;
    // The output plus this temporary still covers the full 2 GiB construction
    // ceiling. It retires only after check_compiled accepted immutable backing.
    // Keep auxiliary storage additive to input storage as before.
    let scratch = requirement(Category::PhaseScratch,
        add(construction_extra, add(auxiliary, super::caller_bytes()?)?)?)?;
    Ok((output, scratch))
}

#[cfg(all(test, not(debug_assertions)))]
mod retained_tests {
    use super::*;

    #[test]
    fn packed_retention_keeps_full_compiler_allowance_until_completion() {
        let facts = ComponentSourceFacts::new(
            OperationCounts { scalar: 100, cubic: 5, poseidon: 2 }, 256, 10, 16, true).unwrap();
        let retained = facts.retained_program_host_bytes().unwrap();
        assert!(retained < PROGRAM_BYTES);
        let auxiliary = ShakeGroupCompileFootprint::for_group(1, construction()).unwrap().auxiliary_peak_bytes;
        let (output, scratch) = compiler_requirements(facts, Some(1)).unwrap();
        let owners = bytes::<super::super::PairedCompiled<'static>>(8).unwrap();
        assert_eq!(output.get(Category::SymbolicCompiler).host, (retained + owners) as u64);
        assert_eq!(output.get(Category::SymbolicCompiler).host + scratch.get(Category::PhaseScratch).host,
            (PROGRAM_BYTES + owners + auxiliary + super::super::caller_bytes().unwrap()) as u64);
    }
}
