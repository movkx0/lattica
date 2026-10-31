//! Reorder only independent native/leaf-compile blocks, before slot assignment.
//! Recursive nodes, native segments and the logical outer/merge order are fixed.
use super::*;
use lattica_prover_p3::block_v2::machine::backend::identity_batch::IdentityHashSchedule;

pub(crate) const MAX_IDENTITY_STREAMS: usize = 16;

impl PairedRequestPlan<'_> {
    pub(crate) fn identity_limits(&self) -> IdentityBatchLimits {
        self.identity_limits
    }

    pub(crate) fn with_identity_limits(mut self, limits: IdentityBatchLimits) -> Result<Self> {
        if self.identity_limits != IdentityBatchLimits::default() || self.endpoint_attempted.get() {
            return Err(PairedFailure::Order);
        }
        if limits.schedule == IdentityHashSchedule::Serial {
            return Ok(self);
        }
        #[cfg(not(feature = "identity-batch-experiment"))]
        {
            let _ = limits;
            Err(PairedFailure::Authority)
        }
        #[cfg(feature = "identity-batch-experiment")]
        {
            use lattica_prover_p3::block_v2::machine::backend::identity_batch::{
                IdentityBatchContext, IDENTITY_PREFIX_HOST_BYTES,
            };
            reorder(&mut self.steps, limits.max_streams())?;
            self.identity_limits = limits;
            self.identity_context = Some(IdentityBatchContext::new());
            let mut hash = Sha3_256::new();
            hash.update(b"lattica/owned-shake-identity-cohorts/v1");
            hash.update(self.source_fingerprint);
            hash.update((limits.max_streams() as u64).to_le_bytes());
            self.source_fingerprint = hash.finalize().into();
            for step in &mut self.steps {
                step.facts.source_fingerprint = self.source_fingerprint;
                if matches!(step.kind, RequestStepKind::Group { .. }) {
                    step.facts
                        .output
                        .add(
                            Category::RegisteredMetadata,
                            crate::execution::retained_resources::Bytes {
                                host: IDENTITY_PREFIX_HOST_BYTES,
                                device: 0,
                            },
                        )
                        .map_err(|_| PairedFailure::Overflow)?;
                    self.slots.compiled = maxima(self.slots.compiled, step.facts.output);
                }
            }
            Ok(self)
        }
    }

    /// The first leaf in each cohort borrows all compiled siblings. Others
    /// consume only their own compiler/prefix. Parents always stay serial.
    pub(crate) fn identity_cohort(
        &self,
        node: usize,
    ) -> Result<([usize; MAX_IDENTITY_STREAMS], usize)> {
        let mut nodes = [0; MAX_IDENTITY_STREAMS];
        if self.identity_limits.schedule == IdentityHashSchedule::Serial {
            return Ok((nodes, 0));
        }
        let position = self
            .nodes
            .iter()
            .filter(|n| n.group.is_some())
            .position(|n| n.id == node);
        let Some(position) = position else {
            return Ok((nodes, 0));
        };
        let width = self.identity_limits.max_streams();
        if position % width != 0 {
            return Ok((nodes, 0));
        }
        let mut count = 0;
        for source in self
            .nodes
            .iter()
            .filter(|n| n.group.is_some())
            .skip(position)
            .take(width)
        {
            nodes[count] = source.id;
            count += 1;
        }
        if count == 0 || nodes[0] != node {
            return Err(PairedFailure::Order);
        }
        Ok((nodes, count))
    }

    #[cfg(feature = "identity-batch-experiment")]
    pub(crate) fn identity_context(
        &self,
    ) -> Result<&lattica_prover_p3::block_v2::machine::backend::identity_batch::IdentityBatchContext>
    {
        self.identity_context
            .as_ref()
            .ok_or(PairedFailure::Authority)
    }
}

/// Move the next native+Group block before the first unexecuted Outer, using
/// in-place rotation. The non-leaf subsequence never changes; no second copy
/// of the compiler schedule or witness storage is allocated.
fn reorder(steps: &mut [RequestStep], width: usize) -> Result<()> {
    if !matches!(width, 1 | 2 | 4 | 8 | 16) {
        return Err(PairedFailure::Coverage);
    }
    let mut after = 0;
    loop {
        let Some(first) =
            (after..steps.len()).find(|&i| matches!(steps[i].kind, RequestStepKind::Group { .. }))
        else {
            break;
        };
        let mut insert = first + 1;
        let mut search = insert;
        for _ in 1..width {
            let Some(group) = (search..steps.len())
                .find(|&i| matches!(steps[i].kind, RequestStepKind::Group { .. }))
            else {
                break;
            };
            let mut start = group;
            while start > insert && matches!(steps[start - 1].kind, RequestStepKind::Native { .. })
            {
                start -= 1;
            }
            if start == group {
                return Err(PairedFailure::Order);
            }
            let length = group + 1 - start;
            steps[insert..=group].rotate_right(length);
            insert += length;
            search = group + 1;
        }
        after = insert;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step(kind: RequestStepKind) -> RequestStep {
        RequestStep {
            kind,
            facts: PhaseFacts {
                kind: PhaseKind::Native,
                source_fingerprint: [0; 32],
                compiled_source_fingerprint: [0; 32],
                output: Requirements::default(),
                scratch: Requirements::default(),
                failure: Requirements::default(),
            },
        }
    }
    #[test]
    fn identity_cohorts_keep_native_and_recursive_order_with_odd_tail() {
        use RequestStepKind::*;
        let original = [
            Endpoints,
            Native { index: 0 },
            Group { node: 0 },
            Outer { node: 0 },
            Native { index: 1 },
            Group { node: 1 },
            Outer { node: 1 },
            Merge {
                node: 2,
                left: 0,
                right: 1,
            },
            Outer { node: 2 },
            Native { index: 2 },
            Native { index: 3 },
            Group { node: 3 },
            Outer { node: 3 },
            Merge {
                node: 4,
                left: 2,
                right: 3,
            },
            Outer { node: 4 },
        ];
        for width in [1, 2, 4, 8, 16] {
            let mut steps: Vec<_> = original.iter().copied().map(step).collect();
            reorder(&mut steps, width).unwrap();
            let kinds: Vec<_> = steps.iter().map(|s| s.kind).collect();
            if width == 1 {
                assert_eq!(kinds, original);
            }
            let recursive = |kinds: &[RequestStepKind]| {
                kinds
                    .iter()
                    .copied()
                    .filter(|s| matches!(s, Outer { .. } | Merge { .. }))
                    .collect::<Vec<_>>()
            };
            assert_eq!(recursive(&kinds), recursive(&original));
            let native = |kinds: &[RequestStepKind]| {
                kinds
                    .iter()
                    .copied()
                    .filter(|s| matches!(s, Native { .. } | Group { .. }))
                    .collect::<Vec<_>>()
            };
            assert_eq!(native(&kinds), native(&original));
            for node in [0, 1, 3] {
                assert!(
                    kinds.iter().position(|s| *s == Group { node }).unwrap()
                        < kinds.iter().position(|s| *s == Outer { node }).unwrap()
                );
            }
            if width == 2 {
                assert_eq!(
                    &kinds[..6],
                    &[
                        Endpoints,
                        Native { index: 0 },
                        Group { node: 0 },
                        Native { index: 1 },
                        Group { node: 1 },
                        Outer { node: 0 }
                    ]
                );
            }
        }
    }
}
