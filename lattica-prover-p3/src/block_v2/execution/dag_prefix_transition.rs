//! Seal an extension of a completed prefix without creating another clock or
//! candidate. One replacement closure uses the existing attachment allowance.
use super::*;

impl Dag {
    pub(super) fn candidate_closure(&self, root: JobId) -> Result<BTreeSet<JobId>, Error> {
        let root_job = &self
            .jobs
            .get(&root)
            .ok_or("execution unknown candidate root")?
            .job;
        if root_job.start() != 0
            || root_job.expected().level != DEPTH
            || root_job.expected().count == 0
        {
            return Err("execution candidate requires a complete nonempty tree".into());
        }
        let mut closure = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if closure.insert(id) {
                let job = &self
                    .jobs
                    .get(&id)
                    .ok_or("execution missing dependency")?
                    .job;
                stack.extend(job.dependencies());
                if closure.len() > crate::block_v2::profile::MAX_DAG_NODES {
                    return Err("execution candidate tree bound".into());
                }
            }
        }
        Ok(closure)
    }

    pub(in crate::block_v2::execution) fn seal_prefix_extension(
        &mut self,
        candidate: CandidateId,
        root: JobId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        self.unsealed_candidate_binding(candidate, eligibility, now_ms)?;
        let closure = self.candidate_closure(root)?;
        let old = &self.candidates[&candidate];
        let old_root = &self.jobs[&old.root].job;
        let next_root = &self.jobs[&root].job;
        if old_root.pin() != next_root.pin()
            || old_root.expected().context != next_root.expected().context
            || old_root.expected().count > next_root.expected().count
        {
            return Err(
                "execution sealed extension changed prefix registry, chain or count".into(),
            );
        }
        for id in &old.closure {
            let record = &self.jobs[id];
            if record.attempt.is_some() {
                return Err("execution prefix extension requires quiescent jobs".into());
            }
            if record.job.is_complete_non_root_subtree()
                && (record.output.is_none() || !closure.contains(id))
            {
                return Err("execution sealed extension lost a completed prefix subtree".into());
            }
            // Complete subtrees protect the even prefix. Also protect an odd
            // last wallet that had no complete pair yet, including exact bytes
            // and its position. Randomized replacement proofs are not a handoff.
            let wallets = record.job.wallet_inputs();
            if !wallets.is_empty() {
                let count = usize::from(record.job.expected().count);
                let next = closure
                    .iter()
                    .map(|id| &self.jobs[id].job)
                    .find(|job| {
                        job.start() == record.job.start() && !job.wallet_inputs().is_empty()
                    })
                    .ok_or("execution sealed extension omitted a prefix wallet")?;
                if count > wallets.len()
                    || count > next.wallet_inputs().len()
                    || wallets[..count] != next.wallet_inputs()[..count]
                {
                    return Err("execution sealed extension changed ordered prefix wallets".into());
                }
            }
        }
        // All validation precedes the root/scope mutation. The durable wrapper
        // publishes this as one snapshot, or poisons itself on interruption.
        for id in old.closure.difference(&closure) {
            let job = self.jobs.get_mut(id).unwrap();
            job.candidates.remove(&candidate);
            job.last_used_ms = now_ms;
        }
        for id in &closure {
            let job = self.jobs.get_mut(id).unwrap();
            job.candidates.insert(candidate);
            job.last_used_ms = now_ms;
        }
        let next = self.candidates.get_mut(&candidate).unwrap();
        next.root = root;
        next.closure = closure;
        next.sealed = true;
        next.last_used_ms = now_ms;
        // Identity, native eligibility, deadline and candidate sequence survive.
        Ok(())
    }
}
