use super::*;
use crate::graph_crypto::{PairedRequestPlan, PairedRequestReport, PairedExecuteError, RequestStepKind};

/// Each field borrows one concrete original table. Plan and output data
/// lifetimes remain explicit; no invariant CaseOwnerTable is shortened.
pub(crate) struct ShakeRuntime<'tables, 'case, 'plans, 'request> {
    pub(crate) plans: &'plans ShakePlanTable<'case, 'request>,
    pub(crate) endpoints: &'tables ShakeEndpointOutputs<'case, 'request>,
    pub(crate) native: &'tables ShakeNativeOutputs<'case, 'request>,
    pub(crate) compiled: &'tables ShakeCompiledOutputs<'case, 'request>,
    pub(crate) outer: &'tables ShakeOuterOutputs<'case, 'request>,
    pub(crate) native_packets: &'tables ShakeNativePreissues<'case, 'plans, 'request>,
    pub(crate) outer_packets: &'tables ShakeOuterPreissues<'case, 'plans, 'request>,
    pub(crate) requests: &'tables ShakeRequestOutputs<'case, 'request>,
    pub(crate) reports: &'tables ShakeReportTable<'case>,
}

impl<'tables, 'case, 'plans, 'request> ShakeRuntime<'tables, 'case, 'plans, 'request> {
    fn plan(&self, request: usize) -> Result<&'plans PairedRequestPlan<'request>> {
        value(slot(self.plans, request)?)?.as_ref().map_err(|_| WorkflowError::Source)
    }

    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let counts = metadata.counts();
        let requests = counts.family(ProducerFamily::Shake);
        original_table(self.plans, case, requests)?;
        for ordinal in 0..requests { self.plan(ordinal)?; }
        uninitialized_table(self.endpoints, case, requests)?;
        uninitialized_table(self.native, case, counts.shake_native())?;
        uninitialized_table(self.compiled, case, counts.shake_recursive())?;
        uninitialized_table(self.outer, case, counts.shake_recursive())?;
        uninitialized_table(self.native_packets, case, counts.shake_native())?;
        uninitialized_table(self.outer_packets, case, counts.shake_recursive())?;
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
            slot.install(RefCell::new(PairedRequestReport::default())).map_err(|_| WorkflowError::Sequence)?;
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
            if !matches!(dispatch.producer(), ProducerRoute::Crypto { family: CryptoFamily::Shake, .. }) { continue; }
            let (request, ordinal, output) = route(dispatch, CryptoFamily::Shake)?;
            let plan = self.plan(request)?;
            same_binding(PhaseBinding::for_paired(plan, ordinal)?, scheduled.binding)?;
            for input_index in 0..dispatch.inputs().len() {
                super::super::runtime_inputs::input_edge(inventory, closed_ordinal, input_index)?;
            }
            let (counter, index) = match output {
                CryptoOutput::Endpoint(index) => (0, index),
                CryptoOutput::Native(index) => (1, index),
                CryptoOutput::Compiled(index) => (2, index),
                CryptoOutput::Outer(index) => (3, index),
            };
            if counter == 2 {
                // Cohorts move independent compiler dispatches ahead of parent
                // compiles; every original output table entry still appears once.
                if index >= inventory.producer_counts().shake_recursive()
                    || closed.dispatch()[..closed_ordinal].iter().any(|prior|
                        matches!(prior.producer(), ProducerRoute::Crypto {
                            family: CryptoFamily::Shake, output: CryptoOutput::Compiled(previous), ..
                        } if previous == index)) { return Err(WorkflowError::Sequence); }
            } else if index != counts[counter] { return Err(WorkflowError::Sequence); }
            plus(&mut counts[counter], 1)?;
        }
        let source = inventory.producer_counts();
        let expected = [source.family(ProducerFamily::Shake), source.shake_native(),
            source.shake_recursive(), source.shake_recursive()];
        if counts != expected { return Err(WorkflowError::Sequence); }
        Ok(())
    }

    /// A prior preflight of another descriptor grants this value no authority.
    /// Counts come directly from the exact immutable metadata behind the seal.
    fn validate_tables(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState, require_empty: bool) -> Result<()>
    {
        let source = inventory.producer_counts();
        let counts = [source.family(ProducerFamily::Shake), source.shake_native(),
            source.shake_recursive(), source.shake_recursive()];
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
        let (request, ordinal, output) = route(dispatch, CryptoFamily::Shake)?;
        let plan = self.plan(request)?;
        match output {
            CryptoOutput::Native(index) => {
                let mut target = write(cell(self.native_packets, index)?)?;
                empty(&target)?;
                *target = Some(guard.workflow.preissue_paired_native(plan, ordinal));
                ready(&target)?;
            }
            CryptoOutput::Outer(index) => {
                let mut target = write(cell(self.outer_packets, index)?)?;
                empty(&target)?;
                *target = Some(guard.workflow.preissue_paired_outer(plan, ordinal));
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
        let (request, ordinal, output) = route(&dispatch, CryptoFamily::Shake)?;
        let plan = self.plan(request)?;
        let binding = PhaseBinding::for_paired(plan, ordinal)?;
        let kind = plan.ordered_steps().get(ordinal).ok_or(WorkflowError::Sequence)?.kind;
        let mut report = value(slot(self.reports, request)?)?.try_borrow_mut().map_err(|_| WorkflowError::SlotBusy)?;
        let mut request_output = write(cell(self.requests, request)?)?;
        empty(&request_output)?;
        match (kind, output) {
            (RequestStepKind::Endpoints, CryptoOutput::Endpoint(index)) if index == request => {
                input_shape(&dispatch, 0, 0)?;
                let mut target = write(cell(self.endpoints, index)?)?;
                empty(&target)?;
                let operation = plan.endpoint_operation(ordinal).map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                *target = Some(phase.prepare_endpoints(operation));
                report.record_endpoint(ready(&target)?, started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (RequestStepKind::Native { .. }, CryptoOutput::Native(index)) => {
                input_shape(&dispatch, 0, 0)?;
                let mut target = write(cell(self.native, index)?)?;
                let mut packet = write(cell(self.native_packets, index)?)?;
                empty(&target)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native()?;
                let operation = plan.native_operation(ordinal, native_cache).map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet = take_ready(&mut packet)?;
                *target = Some(phase.produce_native(operation, packet));
                report.record_native(ready(&target)?, started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (RequestStepKind::Group { node }, CryptoOutput::Compiled(index)) => {
                let span = plan.node_sources().get(node).and_then(|node| node.group).ok_or(WorkflowError::Source)?;
                let count = span.segment_count;
                if !(1..=2).contains(&count) { return Err(WorkflowError::Source); }
                input_shape(&dispatch, count + 1, count)?;
                let (endpoint_step, CryptoOutput::Endpoint(endpoint_index)) = input(&dispatch, count, CryptoFamily::Shake, request)?
                    else { return Err(WorkflowError::Identity); };
                let endpoints = read(cell(self.endpoints, endpoint_index)?)?;
                let endpoint_owner = ready(&endpoints)?;
                same_binding(endpoint_owner.binding(), PhaseBinding::for_paired(plan, endpoint_step)?)?;
                original_input(endpoint_owner.binding(), endpoint_owner.slot_id(), inventory, closed_ordinal, count)?;
                let (first_step, CryptoOutput::Native(first_index)) = input(&dispatch, 0, CryptoFamily::Shake, request)?
                    else { return Err(WorkflowError::Identity); };
                let mut first = write(cell(self.native, first_index)?)?;
                same_binding(ready(&first)?.binding(), PhaseBinding::for_paired(plan, first_step)?)?;
                original_input(ready(&first)?.binding(), ready(&first)?.slot_id(), inventory, closed_ordinal, 0)?;
                let mut second = if count == 2 {
                    let (step, CryptoOutput::Native(index)) = input(&dispatch, 1, CryptoFamily::Shake, request)?
                        else { return Err(WorkflowError::Identity); };
                    let cell = write(cell(self.native, index)?)?;
                    same_binding(ready(&cell)?.binding(), PhaseBinding::for_paired(plan, step)?)?;
                    original_input(ready(&cell)?.binding(), ready(&cell)?.slot_id(), inventory, closed_ordinal, 1)?;
                    Some(cell)
                } else { None };
                let mut target = write(cell(self.compiled, index)?)?;
                empty(&target)?;
                let phase = guard.workflow.next_phase(binding)?;
                let child0 = take_ready(&mut first)?;
                let child1 = match second.as_mut() {
                    Some(cell) => match take_ready(cell) {
                        Ok(value) => Some(value),
                        Err(error) => { *first = Some(Ok(child0)); return Err(error); }
                    },
                    None => None,
                };
                let operation = match plan.group_operation_retaining(ordinal, endpoint_owner, [Some(child0), child1]) {
                    Ok(operation) => operation,
                    Err((error, [first_owner, second_owner])) => {
                        *first = first_owner.map(Ok);
                        if let Some(cell) = second.as_mut() { **cell = second_owner.map(Ok); }
                        *request_output = Some(Err(PairedExecuteError::Source(error)));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_pair(operation));
                ready(&target)?;
                report.record_step_time(started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (RequestStepKind::Merge { .. }, CryptoOutput::Compiled(index)) => {
                input_shape(&dispatch, 2, 2)?;
                let (left_step, CryptoOutput::Outer(left_index)) = input(&dispatch, 0, CryptoFamily::Shake, request)?
                    else { return Err(WorkflowError::Identity); };
                let (right_step, CryptoOutput::Outer(right_index)) = input(&dispatch, 1, CryptoFamily::Shake, request)?
                    else { return Err(WorkflowError::Identity); };
                let mut left = write(cell(self.outer, left_index)?)?;
                let mut right = write(cell(self.outer, right_index)?)?;
                let mut target = write(cell(self.compiled, index)?)?;
                empty(&target)?;
                same_binding(ready(&left)?.binding(), PhaseBinding::for_paired(plan, left_step)?)?;
                original_input(ready(&left)?.binding(), ready(&left)?.slot_id(), inventory, closed_ordinal, 0)?;
                same_binding(ready(&right)?.binding(), PhaseBinding::for_paired(plan, right_step)?)?;
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
                        *request_output = Some(Err(PairedExecuteError::Source(error)));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.compile_parent(operation));
                ready(&target)?;
                report.record_step_time(started.elapsed().as_nanos()).map_err(|_| WorkflowError::Overflow)?;
            }
            (RequestStepKind::Outer { node }, CryptoOutput::Outer(index)) => {
                let (_, cohort_count) = plan.identity_cohort(node).map_err(|_| WorkflowError::Source)?;
                input_shape(&dispatch, cohort_count.max(1), 1)?;
                let (compiler_step, CryptoOutput::Compiled(compiler_index)) = input(&dispatch, 0, CryptoFamily::Shake, request)?
                    else { return Err(WorkflowError::Identity); };
                let mut compiled = write(cell(self.compiled, compiler_index)?)?;
                let mut packet = write(cell(self.outer_packets, index)?)?;
                let mut target = write(cell(self.outer, index)?)?;
                empty(&target)?;
                same_binding(ready(&compiled)?.binding(), PhaseBinding::for_paired(plan, compiler_step)?)?;
                original_input(ready(&compiled)?.binding(), ready(&compiled)?.slot_id(), inventory, closed_ordinal, 0)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                #[cfg(feature = "full-workflow-experiment")]
                let mut peers = crate::execution::workflow_resources::PairedIdentityPeers::default();
                #[cfg(feature = "full-workflow-experiment")]
                let mut peer_indices = [None; lattica_prover_p3::block_v2::machine::backend::identity_cpu::MAX_IDENTITY_STREAMS - 1];
                #[cfg(feature = "full-workflow-experiment")]
                for position in 1..cohort_count {
                    let (step, CryptoOutput::Compiled(peer_index)) = input(&dispatch, position, CryptoFamily::Shake, request)?
                        else { return Err(WorkflowError::Identity); };
                    let mut peer = write(cell(self.compiled, peer_index)?)?;
                    let owner = ready(&peer)?;
                    same_binding(owner.binding(), PhaseBinding::for_paired(plan, step)?)?;
                    original_input(owner.binding(), owner.slot_id(), inventory, closed_ordinal, position)?;
                    peer_indices[position - 1] = Some(peer_index);
                    peers.owners[position - 1] = Some(take_ready(&mut peer)?);
                }
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
                        *request_output = Some(Err(PairedExecuteError::Source(error)));
                        return Err(WorkflowError::Source);
                    }
                };
                #[cfg(feature = "full-workflow-experiment")]
                {
                    *target = Some(phase.prove_owned_outer_cohort(operation, packet_owner, &mut peers));
                    for (peer, index) in peers.owners.iter_mut().zip(peer_indices) {
                        if let Some(owner) = peer.take() {
                            let mut cell = write(cell(self.compiled, index.ok_or(WorkflowError::Identity)?)?)?;
                            empty(&cell)?;
                            *cell = Some(Ok(owner));
                        }
                    }
                }
                #[cfg(not(feature = "full-workflow-experiment"))]
                { *target = Some(phase.prove_owned_outer(operation, packet_owner)); }
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
                            *request_output = Some(Err(PairedExecuteError::Source(error)));
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
    let shells = shells!(ShakeEndpointResult<'static>, ShakeNativeResult<'static>,
        ComponentCompiledResult<'static>, ComponentOuterResult<'static>,
        ShakeNativePreissueResult<'static, 'static>, ShakeOuterPreissueResult<'static, 'static>,
        ShakeRequestResult<'static>);
    shells.into_iter().chain([
        size_of::<ShakeRuntime<'static, 'static, 'static, 'static>>(),
        size_of::<PairedRequestReport>(), size_of::<RefMut<'static, PairedRequestReport>>(),
        size_of::<Result<RefMut<'static, PairedRequestReport>>>(),
        size_of::<Result<&'static PairedRequestPlan<'static>>>(),
    ]).try_fold(0usize, |sum, part|
        sum.checked_add(part.checked_mul(8).ok_or(WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow))
}
