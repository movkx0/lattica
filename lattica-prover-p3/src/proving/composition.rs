//! Local request composition uses explicit, single-use child slots. The caller
//! names the work before execution; overlapping stages cannot hide missing work.
//! No thread-local collector, implicit backend switch or serialized attestation.
use super::*;

#[derive(Clone, Debug, Serialize)]
pub struct ComponentObservation {
    pub id: &'static str,
    pub scope: CoverageScope,
    pub started: bool,
    pub cached: bool,
    pub succeeded: bool,
    pub stage_coverage_complete: bool,
}

/// Immutable compilation/preprocessing provenance. Only an actual completed run can
/// create this receipt; reuse records provenance without replaying device events.
#[derive(Clone, Debug)]
pub(crate) struct CachedScope {
    capabilities: Capabilities,
    complete: bool,
}

impl CachedScope {
    pub(crate) fn registry_compilation(report: &Report) -> Result<Self, Error> {
        if report.capabilities.scope != CoverageScope::RegistryCompilation
            || !report.succeeded
            || !report.stage_coverage_complete
            || report.observation_errors != 0
        {
            return Err(Error::ComponentRejected);
        }
        Ok(Self {
            capabilities: report.capabilities.clone(),
            complete: true,
        })
    }

    pub(crate) fn retained_host_bytes(&self) -> Result<usize, String> {
        self.capabilities
            .stages
            .capacity()
            .checked_mul(std::mem::size_of::<StageCapability>())
            .ok_or_else(|| "cached provenance storage overflow".into())
    }
    pub(crate) fn preprocessing(report: &Report) -> Result<Self, Error> {
        if report.capabilities.scope != CoverageScope::Preprocessing || !report.succeeded {
            return Err(Error::ComponentRejected);
        }
        Ok(Self {
            capabilities: report.capabilities.clone(),
            complete: report.stage_coverage_complete,
        })
    }
}

pub(super) struct Parent {
    state: Arc<Mutex<State>>,
    slot: usize,
    capabilities: Capabilities,
}

fn compatible_inventory(parent: &Capabilities, child: &Capabilities) -> bool {
    parent.profile == child.profile
        && parent.max_log_fri_arity == child.max_log_fri_arity
        && child
            .stages
            .iter()
            .all(|stage| parent.stages.contains(stage))
}

fn lose_observation(state: &mut State) {
    state.observation_errors = state.observation_errors.saturating_add(1);
}

impl Parent {
    pub(super) fn record(&self, report: &Report) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.finished {
            return;
        }
        if report.capabilities.scope != state.components[self.slot].scope {
            lose_observation(&mut state);
            return;
        }
        let inventory_matches = compatible_inventory(&self.capabilities, &report.capabilities);
        let component = &mut state.components[self.slot];
        component.succeeded = report.succeeded;
        component.stage_coverage_complete = report.stage_coverage_complete && inventory_matches;
        if !inventory_matches {
            lose_observation(&mut state);
        }
        state.observation_errors = state
            .observation_errors
            .saturating_add(report.observation_errors);
        for incoming in &report.observations {
            if let Some(current) = state
                .observations
                .iter_mut()
                .find(|o| o.stage == incoming.stage && o.backend == incoming.backend)
            {
                let sums = (
                    current.calls.checked_add(incoming.calls),
                    current
                        .completed_calls
                        .checked_add(incoming.completed_calls),
                    current.device_calls.checked_add(incoming.device_calls),
                    current.inclusive_ns.checked_add(incoming.inclusive_ns),
                    current.device_ns.checked_add(incoming.device_ns),
                );
                if let (
                    Some(calls),
                    Some(completed_calls),
                    Some(device_calls),
                    Some(inclusive_ns),
                    Some(device_ns),
                ) = sums
                {
                    current.calls = calls;
                    current.completed_calls = completed_calls;
                    current.device_calls = device_calls;
                    current.inclusive_ns = inclusive_ns;
                    current.device_ns = device_ns;
                } else {
                    lose_observation(&mut state);
                }
            } else {
                state.observations.push(Observation {
                    stage: incoming.stage,
                    backend: incoming.backend,
                    calls: incoming.calls,
                    completed_calls: incoming.completed_calls,
                    device_calls: incoming.device_calls,
                    inclusive_ns: incoming.inclusive_ns,
                    device_ns: incoming.device_ns,
                });
            }
        }
    }
}

impl Run {
    pub(crate) fn request(
        entry_point: &'static str,
        request: Request,
        capabilities: Capabilities,
        components: &[(&'static str, CoverageScope)],
    ) -> Result<Self, Error> {
        // A fixed bound keeps faulty or adversarial scheduling metadata from
        // turning a stage report into an unbounded queue.
        if capabilities.scope != CoverageScope::ProofRequest
            || components.is_empty()
            || components.len() > 16
            || components.iter().enumerate().any(|(i, (id, scope))| {
                id.is_empty()
                    || *scope == CoverageScope::ProofRequest
                    || components[..i].iter().any(|(other, _)| other == id)
            })
        {
            return Err(Error::ComponentRejected);
        }
        let run = Self::new(entry_point, request, capabilities)?;
        run.state.lock().unwrap().components = components
            .iter()
            .map(|&(id, scope)| ComponentObservation {
                id,
                scope,
                started: false,
                cached: false,
                succeeded: false,
                stage_coverage_complete: false,
            })
            .collect();
        Ok(run)
    }

    fn claim(&self, id: &str, capabilities: &Capabilities) -> Result<Parent, Error> {
        let mut state = self.state.lock().unwrap();
        if state.finished {
            return Err(Error::Finished);
        }
        let Some(slot) = state
            .components
            .iter()
            .position(|c| c.id == id && c.scope == capabilities.scope && !c.started)
        else {
            lose_observation(&mut state);
            return Err(Error::ComponentRejected);
        };
        if let Err(error) = self.request.admit(capabilities) {
            lose_observation(&mut state);
            return Err(error);
        }
        if self.request.policy == Policy::GpuRequired
            && !compatible_inventory(&self.capabilities, capabilities)
        {
            lose_observation(&mut state);
            return Err(Error::ComponentRejected);
        }
        state.components[slot].started = true;
        Ok(Parent {
            state: Arc::clone(&self.state),
            slot,
            capabilities: self.capabilities.clone(),
        })
    }

    pub(crate) fn child(
        &self,
        id: &str,
        entry_point: &'static str,
        capabilities: Capabilities,
    ) -> Result<Self, Error> {
        let parent = self.claim(id, &capabilities)?;
        let mut run = Self::new(entry_point, self.request, capabilities)?;
        run.parent = Some(parent);
        Ok(run)
    }

    pub(crate) fn reuse_preprocessing(&self, id: &str, cached: &CachedScope) -> Result<(), Error> {
        self.reuse_scope(id, cached, CoverageScope::Preprocessing)
    }

    pub(crate) fn reuse_registry_compilation(&self, cached: &CachedScope) -> Result<(), Error> {
        if !cached.complete {
            return Err(Error::ComponentRejected);
        }
        self.reuse_scope("registry", cached, CoverageScope::RegistryCompilation)
    }

    fn reuse_scope(
        &self,
        id: &str,
        cached: &CachedScope,
        scope: CoverageScope,
    ) -> Result<(), Error> {
        if cached.capabilities.scope != scope {
            lose_observation(&mut self.state.lock().unwrap());
            return Err(Error::ComponentRejected);
        }
        let parent = self.claim(id, &cached.capabilities)?;
        let mut state = self.state.lock().unwrap();
        if state.finished {
            return Err(Error::Finished);
        }
        let component = &mut state.components[parent.slot];
        component.cached = true;
        component.succeeded = true;
        component.stage_coverage_complete =
            cached.complete && compatible_inventory(&self.capabilities, &cached.capabilities);
        if component.stage_coverage_complete
            && cached
                .capabilities
                .stages
                .iter()
                .any(|stage| stage.stage == Stage::Preprocessing)
        {
            state.cached_preprocessing = true;
        }
        Ok(())
    }
}

#[cfg(all(
    test,
    any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda")
))]
mod tests;
