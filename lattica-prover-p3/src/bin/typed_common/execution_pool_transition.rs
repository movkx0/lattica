//! One host-authenticated live handoff. Startup identities remain immutable;
//! the committed overlay changes only the effective native selection on replay.
use super::*;

pub(super) const POST_SEAL_MS: u64 = 180_000;
const INTENT: &str = "prefix-transition-intent.json";
const COMMITTED: &str = "prefix-transition.json";

pub(super) fn storage_bytes() -> u64 {
    // Four bounded JSON envelopes and their decoded/clone/comparison backing.
    // The envelope cap is 128 KiB; the 64x allowance also covers cloned plan
    // assignment Values. This reserves metadata, never a second selection.
    (4 * 64 * JSON_LIMIT) as u64
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Seal {
    schema_version: u32,
    pool_workflow: pool_timing::Workflow,
    sealed_monotonic_ms: u64,
    deadline_monotonic_ms: u64,
}

impl Seal {
    pub(super) fn deadline(&self, workflow: &pool_timing::Workflow, now: u64) -> Result<u64, Error> {
        workflow.validate_at(&workflow.boot_id, workflow.started_monotonic_ms)?;
        let sealed = self.sealed_monotonic_ms.checked_sub(workflow.started_monotonic_ms)
            .ok_or("pool seal predates workflow")?;
        let deadline = self.deadline_monotonic_ms.checked_sub(workflow.started_monotonic_ms)
            .ok_or("pool seal deadline predates workflow")?;
        if self.schema_version != 1 || self.pool_workflow != *workflow
            || self.deadline_monotonic_ms != self.sealed_monotonic_ms.checked_add(POST_SEAL_MS)
                .ok_or("pool seal deadline overflow")?.min(workflow.deadline_monotonic_ms)
            || sealed > now || now >= deadline || deadline > pool_timing::CANDIDATE_MS
        {
            return Err("pool original post-seal deadline changed or expired".into());
        }
        Ok(deadline)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transition {
    schema_version: u32,
    original: native::Binding,
    workflow: pool_timing::Workflow,
    prefix_root: [u8; 32],
    final_root: [u8; 32],
    request: pool_service::Request,
    prepared_ms: u64,
}

impl Transition {
    pub(super) fn begin(
        plan: &Plan, request: &pool_service::Request, prefix_root: JobId,
        final_root: JobId, now: u64, out: &Path,
    ) -> Result<Self, Error> {
        request.validate_extension(plan, now)?;
        let value = Self {
            schema_version: 1,
            original: plan.native_host.clone().ok_or("handoff original native binding")?,
            workflow: plan.pool_workflow.clone().ok_or("handoff original workflow")?,
            prefix_root: prefix_root.to_bytes(), final_root: final_root.to_bytes(),
            request: request.clone(), prepared_ms: now,
        };
        pool_service::publish_json(&out.join(INTENT), &value)?;
        Ok(value)
    }

    pub(super) fn commit(&self, out: &Path) -> Result<(), Error> {
        // Called only after the durable candidate mutation. An interrupted
        // publication leaves its intent and journal intact and fails closed.
        pool_service::publish_json(&out.join(COMMITTED), self)
    }
}

/// Replay checks the supplied native authority and the CPU-verified final root.
/// This overlay never replaces the original plan used to reconcile old workers.
pub(super) fn effective_plan(source: &Path, previous: &Plan, root: JobId) -> Result<Plan, Error> {
    let mut effective = previous.clone();
    if !source.join(INTENT).exists() && !source.join(COMMITTED).exists() {
        return Ok(effective);
    }
    let intent: Transition = read_json(&source.join(INTENT))?;
    let committed: Transition = read_json(&source.join(COMMITTED))?;
    if serde_json::to_value(&intent)? != serde_json::to_value(&committed)?
        || intent.schema_version != 1 || intent.final_root != root.to_bytes()
        || intent.prefix_root == [0; 32]
        || serde_json::to_value(&previous.native_host)? != serde_json::to_value(Some(&intent.original))?
        || previous.pool_workflow.as_ref() != Some(&intent.workflow)
    {
        return Err("prefix transition recovery metadata differs from its committed selection".into());
    }
    intent.request.validate_extension(previous, intent.prepared_ms)?;
    effective.preseal_only = false;
    effective.pool_prefix_handoff = false;
    effective.native_host = Some(intent.request.native_host);
    for worker in &mut effective.workers {
        worker.assignment["native_host"] = serde_json::to_value(&effective.native_host)?;
    }
    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_horizon_is_capped_by_both_original_clocks() {
        let workflow = pool_timing::Workflow {
            schema_version: 1, boot_id: "00000000-0000-0000-0000-000000000001".into(),
            started_monotonic_ms: 1000, deadline_monotonic_ms: 601000,
        };
        for (sealed, deadline) in [(2000, 182000), (501000, 601000)] {
            let seal = Seal { schema_version: 1, pool_workflow: workflow.clone(),
                sealed_monotonic_ms: sealed, deadline_monotonic_ms: deadline };
            let now = sealed - 1000;
            assert_eq!(seal.deadline(&workflow, now).unwrap(), deadline - 1000);
            assert!(seal.deadline(&workflow, now - 1).is_err());
            assert!(seal.deadline(&workflow, deadline - 1000).is_err());
            for changed in [0, deadline - 1, deadline + 1, u64::MAX] {
                let mut bad = seal.clone(); bad.deadline_monotonic_ms = changed;
                assert!(bad.deadline(&workflow, now).is_err());
            }
            let mut bad = seal.clone(); bad.pool_workflow.started_monotonic_ms += 1;
            assert!(bad.deadline(&workflow, now).is_err());
        }
    }
}
