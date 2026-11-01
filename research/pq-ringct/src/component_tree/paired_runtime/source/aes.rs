//! Exact unchanged AES leaf source. One native segment stays one wrapper.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AesBlueprint {
    descriptor: NativeDescriptor<'static>,
    storage: NativePlanningStorage,
}

impl AesBlueprint {
    pub(crate) fn new(request: &Request, index: usize) -> Result<Self> {
        let RequestDescriptor::Aes(descriptor) = request.descriptor() else {
            return Err(PairedFailure::Source);
        };
        let segment = request.segments().get(index).ok_or(PairedFailure::Coverage)?;
        let native = NativeDescriptor::Aes { descriptor,
            first: segment.first_unit, count: segment.units };
        let storage = NativePlanningStorage::for_descriptor(native, construction())
            .map_err(|_| PairedFailure::Source)?;
        if storage.geometry.width != segment.width || storage.geometry.height != segment.height
            || storage.geometry.public_values != crate::aes_lane_air::PUBLIC_VALUES
            || storage.geometry.periodic_columns != 31 || storage.geometry.maximum_period != 64 {
            return Err(PairedFailure::SourceDrift);
        }
        if storage.auxiliary_peak_bytes > AUXILIARY_BYTES { return Err(PairedFailure::Capacity); }
        Ok(Self { descriptor: native, storage })
    }

    pub(crate) fn planning_requirements(&self) -> Result<Requirements> {
        requirement(Category::PhaseScratch, self.storage.total_requested_bytes)
    }

    pub(crate) fn metadata_request(&self) -> native_shape::cohort::Request<'static> {
        native_shape::cohort::Request { descriptor:native_shape::cohort::Descriptor::Native(self.descriptor),
            auxiliary:self.storage.auxiliary_peak_bytes }
    }

    /// The same bounded native recorder used by the concrete compiler below,
    /// plus the unchanged component header and both endpoint conditions.
    pub(crate) fn inspect(&self) -> Result<ComponentSourceFacts> {
        let core = native_shape::native_core_bound(self.descriptor, construction(),
            self.storage.auxiliary_peak_bytes).map_err(|_| PairedFailure::Source)?;
        self.inspect_bound(core)
    }

    pub(crate) fn inspect_bound(&self, core: native_shape::NativeCoreBound) -> Result<ComponentSourceFacts> {
        if core.storage != self.storage { return Err(PairedFailure::SourceDrift); }
        let framing = framing::AES_WRAPPER;
        if framing.cubic != 0 { return Err(PairedFailure::SourceDrift); }
        let operations = core.counts.operations.with_overhead(framing)
            .map_err(|_| PairedFailure::Overflow)?;
        let wires = add(core.counts.wires,
            add(PUBLICS, add(framing.scalar, mul(8, framing.poseidon)?)?)?)?;
        ComponentSourceFacts::new(operations, wires, core.counts.input_values,
            core.counts.selection_hint_words, true)
    }

    pub(crate) fn compiler_requirements(&self) -> Result<(Requirements, Requirements)> {
        // NativePlanningStorage already includes the exact AES AIR, public
        // periodic table, bounded symbolic recorder/graph, verifier helpers,
        // ProofInputs growth and returned native wire vectors. Wrapper fields
        // and fixed endpoint hash marshaling are additive, outside that census.
        let wrapper = [
            bytes::<Self>(8)?, bytes::<crate::component_tree::Spec>(8)?,
            bytes::<crate::component_tree::Val>(4 * PUBLICS)?,
            bytes::<crate::component_tree::Wire>(4 * PUBLICS)?,
            bytes::<u64>(4 * 6)?, bytes::<Vec<u64>>(8)?,
            bytes::<Vec<crate::component_tree::Wire>>(8)?,
            bytes::<Vec<crate::component_tree::Val>>(8)?,
            super::super::caller_bytes()?, 64 << 10,
        ].into_iter().try_fold(0, add)?;
        let output = combine(&[
            requirement(Category::SymbolicCompiler,
                add(PROGRAM_BYTES, bytes::<super::super::PairedCompiled<'static>>(8)?)?)?,
            requirement(Category::CompilerInputs,
                add(self.storage.input_backing_bytes, bytes::<crate::component_tree::Val>(2 * PUBLICS)?)?)?,
        ])?;
        let scratch = requirement(Category::PhaseScratch,
            add(self.storage.auxiliary_peak_bytes, wrapper)?)?;
        Ok((output, scratch))
    }
}
