use super::*;
use crate::graph_crypto::{OwnedAesRequestPlan, OwnedAesRequestReport, OwnedAesExecuteError, OwnedAesStepKind};

/// Each field borrows one concrete original table. Plan and output data
/// lifetimes remain explicit; no invariant CaseOwnerTable is shortened.
pub(crate) struct AesRuntime<'tables, 'case, 'plans, 'request> {
    pub(crate) plans: &'plans AesPlanTable<'case, 'request>,
    pub(crate) endpoints: &'tables AesEndpointOutputs<'case, 'request>,
    pub(crate) native: &'tables AesNativeOutputs<'case, 'request>,
    pub(crate) compiled: &'tables AesCompiledOutputs<'case, 'request>,
    pub(crate) outer: &'tables AesOuterOutputs<'case, 'request>,
    pub(crate) native_packets: &'tables AesNativePreissues<'case, 'plans, 'request>,
    pub(crate) outer_packets: &'tables AesOuterPreissues<'case, 'plans, 'request>,
    pub(crate) requests: &'tables AesRequestOutputs<'case, 'request>,
    pub(crate) reports: &'tables AesReportTable<'case>,
}

impl<'tables, 'case, 'plans, 'request> AesRuntime<'tables, 'case, 'plans, 'request> {
    fn plan(&self, request: usize) -> Result<&'plans OwnedAesRequestPlan<'request>> {
        value(slot(self.plans, request)?)?.as_ref().map_err(|_| WorkflowError::Source)
    }

    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let counts = metadata.counts();
        let requests = counts.family(ProducerFamily::Aes);
        original_table(self.plans, case, requests)?;
        for ordinal in 0..requests { self.plan(ordinal)?; }
        uninitialized_table(self.endpoints, case, requests)?;
        uninitialized_table(self.native, case, counts.aes_native())?;
        uninitialized_table(self.compiled, case, counts.aes_recursive())?;
        uninitialized_table(self.outer, case, counts.aes_recursive())?;
        uninitialized_table(self.native_packets, case, counts.aes_native())?;
        uninitialized_table(self.outer_packets, case, counts.aes_recursive())?;
        uninitialized_table(self.requests, case, requests)?;
        uninitialized_table(self.reports, case, requests)?;
        // No target changes before the complete table/case/occupancy preflight.
        initialize_table(self.endpoints)?;
        initialize_table(self.native)?;
        initialize_table(self.compiled)?;
        initialize_table(self.outer)?;
        initialize_table(self.native_packets)?;
        initialize_table(self.outer_packets)?;
        initialize_table(self.requests)?;
        for slot in self.reports.slots() {
            slot.install(RefCell::new(OwnedAesRequestReport::default())).map_err(|_| WorkflowError::Sequence)?;
        }
        guard.planning.validate_metadata_driver(metadata, case)?;
        guard.completed = true;
        Ok(())
    }

    /// Full route coverage is checked once before preissue. Current-step
    /// input edges are checked separately before each consuming extraction.
    fn validate_routes(&self, inventory: &ValidatedCompleteInventory<'_, '_>) -> Result<()> {
        let closed = inventory.closed_plan();
        let mut counts = [0usize; 4];
        for (closed_ordinal, (dispatch, scheduled)) in closed.dispatch().iter().zip(closed.steps()).enumerate() {
            if !matches!(dispatch.producer(), ProducerRoute::Crypto { family: CryptoFamily::Aes, .. }) { continue; }
            let (request, ordinal, output) = route(dispatch, CryptoFamily::Aes)?;
            let plan = self.plan(request)?;
            same_binding(PhaseBinding::for_aes(plan, ordinal)?, scheduled.binding)?;
            for input_index in 0..dispatch.inputs().len() {
                super::super::runtime_inputs::input_edge(inventory, closed_ordinal, input_index)?;
            }
            let (counter, index) = match output {
                CryptoOutput::Endpoint(index) => (0, index),
                CryptoOutput::Native(index) => (1, index),
                CryptoOutput::Compiled(index) => (2, index),
                CryptoOutput::Outer(index) => (3, index),
            };
            if index != counts[counter] { return Err(WorkflowError::Sequence); }
            plus(&mut counts[counter], 1)?;
        }
        let source = inventory.producer_counts();
        let expected = [source.family(ProducerFamily::Aes), source.aes_native(),
            source.aes_recursive(), source.aes_recursive()];
        if counts != expected { return Err(WorkflowError::Sequence); }
        Ok(())
    }

    /// A prior preflight of another descriptor grants this value no authority.
    /// Counts come directly from the exact immutable metadata behind the seal.
    fn validate_tables(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState, require_empty: bool) -> Result<()>
    {
        let source = inventory.producer_counts();
        let counts = [source.family(ProducerFamily::Aes), source.aes_native(),
            source.aes_recursive(), source.aes_recursive()];
        original_table(self.plans, case, counts[0])?;
        if require_empty { empty_table(self.endpoints, case, counts[0])?; }
        else { original_table(self.endpoints, case, counts[0])?; }
        if require_empty { empty_table(self.native, case, counts[1])?; }
        else { original_table(self.native, case, counts[1])?; }
        if require_empty { empty_table(self.compiled, case, counts[2])?; }
        else { original_table(self.compiled, case, counts[2])?; }
        if require_empty { empty_table(self.outer, case, counts[3])?; }
        else { original_table(self.outer, case, counts[3])?; }
        if require_empty { empty_table(self.native_packets, case, counts[1])?; }
        else { original_table(self.native_packets, case, counts[1])?; }
        if require_empty { empty_table(self.outer_packets, case, counts[3])?; }
        else { original_table(self.outer_packets, case, counts[3])?; }
        if require_empty { empty_table(self.requests, case, counts[0])?; }
        else { original_table(self.requests, case, counts[0])?; }
        original_table(self.reports, case, counts[0])?;
        Ok(())
    }

    /// The initial check additionally requires all runtime/preissue cells empty.
    pub(crate) fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        self.validate_tables(inventory, case, true)?;
        self.validate_routes(inventory)?;
        guard.completed = true;
        Ok(())
    }

    pub(crate) fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        self.validate_tables(inventory, case, false)?;
        let dispatch = inventory.closed_plan().dispatch().get(closed_ordinal).ok_or(WorkflowError::Sequence)?;
        let (request, ordinal, output) = route(dispatch, CryptoFamily::Aes)?;
        let plan = self.plan(request)?;
        match output {
            CryptoOutput::Native(index) => {
                let mut target = write(cell(self.native_packets, index)?)?;
                empty(&target)?;
                *target = Some(guard.workflow.preissue_aes_native(plan, ordinal));
                ready(&target)?;
            }
            CryptoOutput::Outer(index) => {
                let mut target = write(cell(self.outer_packets, index)?)?;
                empty(&target)?;
                *target = Some(guard.workflow.preissue_aes_outer(plan, ordinal));
                ready(&target)?;
            }
            _ => return Err(WorkflowError::Sequence),
        }
        guard.completed = true;
        Ok(())
    }

    pub(crate) fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize, native_cache: &ProofCache, outer_cache: &OuterProofCache) -> Result<()>
    {
        let started = Instant::now();
        let mut guard = DriverGuard { workflow, completed: false };
        let dispatch = guard.workflow.validate_driver_step(inventory, case, closed_ordinal)?;
        self.validate_tables(inventory, case, false)?;
        fresh_caches(native_cache, outer_cache)?;
        let (request, ordinal, output) = route(&dispatch, CryptoFamily::Aes)?;
        let plan = self.plan(request)?;
        let binding = PhaseBinding::for_aes(plan, ordinal)?;
        let kind = plan.ordered_steps().get(ordinal).ok_or(WorkflowError::Sequence)?.kind;
        let mut report = value(slot(self.reports, request)?)?.try_borrow_mut().map_err(|_| WorkflowError::SlotBusy)?;
        let mut request_output = write(cell(self.requests, request)?)?;
        empty(&request_output)?;
        match (kind, output) {
            (OwnedAesStepKind::Endpoints, CryptoOutput::Endpoint(index)) if index == request => {
                input_shape(&dispatch, 0, 0)?;
                let mut target = write(cell(self.endpoints, index)?)?;
                empty(&target)?;
                let operation = plan.endpoint_operation(ordinal).map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                *target = Some(phase.attach_aes_endpoints(operation));
                report.record_endpoint(ready(&target)?, started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (OwnedAesStepKind::Native { .. }, CryptoOutput::Native(index)) => {
                input_shape(&dispatch, 0, 0)?;
                let mut target = write(cell(self.native, index)?)?;
                let mut packet = write(cell(self.native_packets, index)?)?;
                empty(&target)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native()?;
                let operation = plan.native_operation(ordinal, native_cache).map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet = take_ready(&mut packet)?;
                *target = Some(phase.produce_aes_native(operation, packet));
                report.record_native(ready(&target)?, started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (OwnedAesStepKind::Compile { .. }, CryptoOutput::Compiled(index)) => {
                input_shape(&dispatch, 2, 1)?;
                let (endpoint_step, CryptoOutput::Endpoint(endpoint_index)) = input(&dispatch, 1, CryptoFamily::Aes, request)?
                    else { return Err(WorkflowError::Identity); };
                let endpoints = read(cell(self.endpoints, endpoint_index)?)?;
                let endpoint_owner = ready(&endpoints)?;
                same_binding(endpoint_owner.binding(), PhaseBinding::for_aes(plan, endpoint_step)?)?;
                original_input(endpoint_owner.binding(), endpoint_owner.slot_id(), inventory, closed_ordinal, 1)?;
                let (native_step, CryptoOutput::Native(native_index)) = input(&dispatch, 0, CryptoFamily::Aes, request)?
                    else { return Err(WorkflowError::Identity); };
                let mut native = write(cell(self.native, native_index)?)?;
                let mut target = write(cell(self.compiled, index)?)?;
                empty(&target)?;
                same_binding(ready(&native)?.binding(), PhaseBinding::for_aes(plan, native_step)?)?;
                original_input(ready(&native)?.binding(), ready(&native)?.slot_id(), inventory, closed_ordinal, 0)?;
                let phase = guard.workflow.next_phase(binding)?;
                let operation = match plan.compile_operation_retaining(ordinal, endpoint_owner, take_ready(&mut native)?) {
                    Ok(operation) => operation,
                    Err((error, owner)) => {
                        *native = Some(Ok(owner));
                        *request_output = Some(Err(OwnedAesExecuteError::Source(error)));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_aes(operation));
                ready(&target)?;
                report.record_step_time(started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (OwnedAesStepKind::Merge { .. }, CryptoOutput::Compiled(index)) => {
                input_shape(&dispatch, 2, 2)?;
                let (left_step, CryptoOutput::Outer(left_index)) = input(&dispatch, 0, CryptoFamily::Aes, request)?
                    else { return Err(WorkflowError::Identity); };
                let (right_step, CryptoOutput::Outer(right_index)) = input(&dispatch, 1, CryptoFamily::Aes, request)?
                    else { return Err(WorkflowError::Identity); };
                let mut left = write(cell(self.outer, left_index)?)?;
                let mut right = write(cell(self.outer, right_index)?)?;
                let mut target = write(cell(self.compiled, index)?)?;
                empty(&target)?;
                same_binding(ready(&left)?.binding(), PhaseBinding::for_aes(plan, left_step)?)?;
                original_input(ready(&left)?.binding(), ready(&left)?.slot_id(), inventory, closed_ordinal, 0)?;
                same_binding(ready(&right)?.binding(), PhaseBinding::for_aes(plan, right_step)?)?;
                original_input(ready(&right)?.binding(), ready(&right)?.slot_id(), inventory, closed_ordinal, 1)?;
                let phase = guard.workflow.next_phase(binding)?;
                let left_owner = take_ready(&mut left)?;
                let right_owner = match take_ready(&mut right) {
                    Ok(value) => value,
                    Err(error) => { *left = Some(Ok(left_owner)); return Err(error); }
                };
                let operation = match plan.merge_operation_retaining(ordinal, left_owner, right_owner) {
                    Ok(operation) => operation,
                    Err((error, left_owner, right_owner)) => {
                        *left = Some(Ok(left_owner)); *right = Some(Ok(right_owner));
                        *request_output = Some(Err(OwnedAesExecuteError::Source(error)));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_aes_parent(operation));
                ready(&target)?;
                report.record_step_time(started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (OwnedAesStepKind::Outer { node }, CryptoOutput::Outer(index)) => {
                input_shape(&dispatch, 1, 1)?;
                let (compiler_step, CryptoOutput::Compiled(compiler_index)) = input(&dispatch, 0, CryptoFamily::Aes, request)?
                    else { return Err(WorkflowError::Identity); };
                let mut compiled = write(cell(self.compiled, compiler_index)?)?;
                let mut packet = write(cell(self.outer_packets, index)?)?;
                let mut target = write(cell(self.outer, index)?)?;
                empty(&target)?;
                same_binding(ready(&compiled)?.binding(), PhaseBinding::for_aes(plan, compiler_step)?)?;
                original_input(ready(&compiled)?.binding(), ready(&compiled)?.slot_id(), inventory, closed_ordinal, 0)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet_owner = take_ready(&mut packet)?;
                let compiled_owner = match take_ready(&mut compiled) {
                    Ok(value) => value,
                    Err(error) => { *packet = Some(Ok(packet_owner)); return Err(error); }
                };
                let operation = match plan.outer_operation_retaining(ordinal, compiled_owner, outer_cache) {
                    Ok(operation) => operation,
                    Err((error, owner)) => {
                        *compiled = Some(Ok(owner)); *packet = Some(Ok(packet_owner));
                        *request_output = Some(Err(OwnedAesExecuteError::Source(error)));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.prove_owned_aes_outer(operation, packet_owner));
                report.record_outer(plan, ordinal, ready(&target)?, started.elapsed().as_nanos()).map_err(|_| WorkflowError::Source)?;
                if node == plan.root_id() {
                    // The report and final root remain in their original slots
                    // until both endpoint and destination borrows are obtained.
                    let mut endpoints = write(cell(self.endpoints, request)?)?;
                    ready(&endpoints)?;
                    let root = take_ready(&mut target)?;
                    let endpoints_owner = match take_ready(&mut endpoints) {
                        Ok(value) => value,
                        Err(error) => { *target = Some(Ok(root)); return Err(error); }
                    };
                    match plan.finish_owned_request(root, endpoints_owner, *report) {
                        Ok(output) => *request_output = Some(Ok(output)),
                        Err((error, root, endpoints_owner)) => {
                            *target = Some(Ok(root)); *endpoints = Some(Ok(endpoints_owner));
                            *request_output = Some(Err(OwnedAesExecuteError::Source(error)));
                        }
                    }
                    ready(&request_output)?;
                }
            }
            _ => return Err(WorkflowError::Sequence),
        }
        guard.completed = true;
        Ok(())
    }
}

pub(super) fn forwarding_host_bytes() -> Result<usize> {
    use core::mem::size_of;
    macro_rules! shells {
        ($($ty:ty),+ $(,)?) => { [$(
            size_of::<$ty>(), size_of::<Option<$ty>>(),
            size_of::<RefCell<Option<$ty>>>(), size_of::<Ref<'static, Option<$ty>>>(),
            size_of::<RefMut<'static, Option<$ty>>>(),
            size_of::<Option<RefMut<'static, Option<$ty>>>>(),
            size_of::<Result<RefMut<'static, Option<$ty>>>>(),
            size_of::<Result<Ref<'static, Option<$ty>>>>(),
            size_of::<Result<&'static $ty>>(),
        )+] };
    }
    let shells = shells!(AesEndpointResult<'static>, AesNativeResult<'static>,
        ComponentCompiledResult<'static>, ComponentOuterResult<'static>,
        AesNativePreissueResult<'static, 'static>, AesOuterPreissueResult<'static, 'static>,
        AesRequestResult<'static>);
    shells.into_iter().chain([
        size_of::<AesRuntime<'static, 'static, 'static, 'static>>(),
        size_of::<OwnedAesRequestReport>(), size_of::<RefMut<'static, OwnedAesRequestReport>>(),
        size_of::<Result<RefMut<'static, OwnedAesRequestReport>>>(),
        size_of::<Result<&'static OwnedAesRequestPlan<'static>>>(),
    ]).try_fold(0usize, |sum, part|
        sum.checked_add(part.checked_mul(8).ok_or(WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow))
}
