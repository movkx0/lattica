//! Fixed report updates and final owner assembly for stepwise complete replay.
use super::*;
use crate::execution::workflow_resources::PhaseBinding;

type FinishRefusal<'a> = (PairedFailure, Retained<PairedNode<'a>>, Retained<PairedEndpoints<'a>>);

impl PairedRequestReport {
    pub(crate) fn record_endpoint(&mut self, output: &Retained<PairedEndpoints<'_>>,
        step_ns: u128) -> Result<()>
    {
        let mut next = *self;
        next.endpoint_preparation_ns = output.get().elapsed_ns();
        next.record_step_time(step_ns)?;
        *self = next;
        Ok(())
    }

    pub(crate) fn record_native(&mut self, output: &RetainedNative<PairedNativeOutput<'_>>,
        step_ns: u128) -> Result<()>
    {
        let mut next = *self;
        next.native_proofs = add(next.native_proofs, 1)?;
        next.native_phase_ns = next.native_phase_ns.checked_add(output.get().elapsed_ns())
            .ok_or(PairedFailure::Overflow)?;
        next.record_step_time(step_ns)?;
        *self = next;
        Ok(())
    }

    pub(crate) fn record_outer(&mut self, plan: &PairedRequestPlan<'_>, ordinal: usize,
        output: &Retained<PairedNode<'_>>, step_ns: u128) -> Result<()>
    {
        let RequestStepKind::Outer { node } = plan.steps.get(ordinal)
            .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
        if output.binding() != PhaseBinding::for_paired(plan, ordinal)
            .map_err(|_| PairedFailure::Authority)? { return Err(PairedFailure::Authority); }
        let source = plan.nodes.get(node).ok_or(PairedFailure::Order)?;
        let report = output.get().report();
        let mut next = *self;
        if source.children.is_some() { next.recursive_parents = add(next.recursive_parents, 1)?; }
        else { next.recursive_leaves = add(next.recursive_leaves, 1)?; }
        next.active_rows = add(next.active_rows, report.active_rows)?;
        next.padded_rows = add(next.padded_rows, report.padded_rows)?;
        next.maximum_padded_rows = next.maximum_padded_rows.max(report.padded_rows);
        for (total, elapsed) in [
            (&mut next.compile_ns, report.compile_ns), (&mut next.setup_ns, report.setup_ns),
            (&mut next.registered_phase_ns, report.registered_phase_ns),
            (&mut next.proving_ns, report.proving_ns),
            (&mut next.cpu_verification_ns, report.cpu_verification_ns),
        ] { *total = total.checked_add(elapsed).ok_or(PairedFailure::Overflow)?; }
        next.record_step_time(step_ns)?;
        *self = next;
        Ok(())
    }

    /// The complete driver sums actual scheduled step wall times. Source
    /// preparation and preissue are measured separately by its workflow clock.
    pub(crate) fn record_step_time(&mut self, step_ns: u128) -> Result<()> {
        self.request_ns = self.request_ns.checked_add(step_ns).ok_or(PairedFailure::Overflow)?;
        Ok(())
    }
}

impl<'request> PairedRequestPlan<'request> {
    pub(crate) fn finish_owned_request(&self, root: Retained<PairedNode<'request>>,
        endpoints: Retained<PairedEndpoints<'request>>, report: PairedRequestReport)
        -> core::result::Result<PairedRequestOutput<'request>, FinishRefusal<'request>>
    {
        let checked = (|| {
            let root_ordinal = self.steps.iter().position(|step|
                step.kind == RequestStepKind::Outer { node: self.root }).ok_or(PairedFailure::Order)?;
            if root.binding() != PhaseBinding::for_paired(self, root_ordinal)
                    .map_err(|_| PairedFailure::Authority)?
                || endpoints.binding() != PhaseBinding::for_paired(self, 0)
                    .map_err(|_| PairedFailure::Authority)?
                || root.get().source() != self.root_source()
                || report.native_proofs != self.request.segments().len()
                || add(report.recursive_leaves, report.recursive_parents)? != self.nodes.len()
            { return Err(PairedFailure::Authority); }
            endpoints.get().check_source(self.request, &self.context)?;
            root.get().check_root(self.request, &self.context)
        })();
        match checked {
            Ok(()) => Ok(PairedRequestOutput { root, endpoints, report }),
            Err(error) => Err((error, root, endpoints)),
        }
    }
}

pub(in crate::graph_crypto::prover::paired) fn forwarding_bytes() -> Result<usize> {
    use core::mem::size_of;
    [
        size_of::<FinishRefusal<'static>>(),
        size_of::<core::result::Result<PairedRequestOutput<'static>, FinishRefusal<'static>>>(),
        size_of::<PairedRequestReport>(), size_of::<Result<()>>(),
        size_of::<crate::component_tree::paired_runtime::PairedNodeReport>(),
        size_of::<[(&mut u128, u128); 5]>(),
    ].into_iter().try_fold(0usize, |sum, part|
        add(sum, part.checked_mul(8).ok_or(PairedFailure::Overflow)?))
}
