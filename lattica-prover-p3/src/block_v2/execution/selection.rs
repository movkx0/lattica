//! Bounded immutable ordered selections for the local execution DAG.
//!
//! Inputs are already CPU-verified public wallet proofs. Their order is supplied
//! by the host, not arrival order. Host state/issuance checks and current
//! eligibility remain mandatory. This is not a block acceptance API.

use super::job::{Job, JobId, RegistryPin, VerifiedWallet};
use crate::block_v2::{
    commitment::{CAPACITY, DEPTH},
    recursive::{Error, WrapperConstruction},
};
use std::sync::Arc;

/// Exact public proof bytes bound to an existing verification ticket.
#[derive(Clone)]
pub struct PublicInput {
    wallet: VerifiedWallet,
    bytes: Arc<[u8]>,
}

impl PublicInput {
    pub fn new(wallet: VerifiedWallet, bytes: Vec<u8>) -> Result<Self, Error> {
        wallet.artifact().check_bytes(&bytes)?;
        Ok(Self {
            wallet,
            bytes: bytes.into(),
        })
    }
}

struct Entry {
    job: Job,
    inputs: Vec<PublicInput>,
}

/// Complete depth-six dense-prefix graph, in dependency-first admission order.
/// A new arrival creates another selection; it never mutates an existing one.
/// Equal jobs keep their semantic identity across selections and reuse the
/// DAG's accepted artifacts and frozen in-flight manifests.
pub struct Selection {
    entries: Vec<Entry>,
}

impl Selection {
    pub fn new(pin: RegistryPin, chain: [u8; 32], inputs: &[PublicInput]) -> Result<Self, Error> {
        if inputs.is_empty() || inputs.len() > CAPACITY {
            return Err("selection requires one to 64 total transactions".into());
        }
        // This registered circuit proves exactly two actual wallet proofs.
        // Never pad an odd input with a duplicate, witness, or weaker circuit.
        if !pin.is_typed()
            && pin.construction() == WrapperConstruction::GroupedPair
            && inputs.len() % 2 != 0
        {
            return Err("paired selection requires an even transaction count".into());
        }
        for input in inputs {
            let context = input.wallet.summary().context;
            if context.profile_id != pin.profile() || context.chain_id != chain {
                return Err("selection wallet context mismatch".into());
            }
        }
        let mut selection = Self {
            entries: Vec::with_capacity(2 * CAPACITY - 1),
        };
        let level = if pin.is_typed() {
            inputs.len().next_power_of_two().trailing_zeros().max(1) as u8
        } else {
            DEPTH
        };
        let mut root = selection.subtree(pin, chain, inputs, 0, level)?;
        if pin.is_typed() && level < DEPTH {
            root = Job::finalize(&root)?;
            selection.entries.push(Entry {
                job: root.clone(),
                inputs: vec![],
            });
        }
        if root.start() != 0
            || root.expected().level != DEPTH
            || root.expected().count as usize != inputs.len()
            || selection.entries.len() > 2 * CAPACITY - 1
        {
            return Err("selection tree invariant".into());
        }
        Ok(selection)
    }

    fn subtree(
        &mut self,
        pin: RegistryPin,
        chain: [u8; 32],
        inputs: &[PublicInput],
        start: u8,
        level: u8,
    ) -> Result<Job, Error> {
        let unit = if pin.construction() == WrapperConstruction::SingleWallet {
            0
        } else {
            1
        };
        let (job, wallets) = if start as usize >= inputs.len() {
            (Job::empty(pin, chain, start, level)?, vec![])
        } else if level == unit {
            let start_index = start as usize;
            if unit == 0 {
                let input = &inputs[start_index];
                (Job::wrap(start, input.wallet)?, vec![input.clone()])
            } else {
                let left = &inputs[start_index];
                if pin.is_typed() {
                    let right = inputs.get(start_index + 1);
                    (
                        Job::typed_pair(start, left.wallet, right.map(|r| r.wallet))?,
                        vec![left.clone(), right.unwrap_or(left).clone()],
                    )
                } else {
                    let right = &inputs[start_index + 1];
                    (
                        Job::wrap_pair(start, left.wallet, right.wallet)?,
                        vec![left.clone(), right.clone()],
                    )
                }
            }
        } else {
            let child_level = level.checked_sub(1).ok_or("selection wrapper geometry")?;
            let left = self.subtree(pin, chain, inputs, start, child_level)?;
            let right =
                self.subtree(pin, chain, inputs, start + (1 << child_level), child_level)?;
            (Job::merge(&left, &right)?, vec![])
        };
        // The requested construction must agree with every verified input ticket,
        // including when a caller pairs a pin with tickets from another registry.
        if job.pin() != pin {
            return Err("selection wallet registry/construction mismatch".into());
        }
        self.entries.push(Entry {
            job: job.clone(),
            inputs: wallets,
        });
        Ok(job)
    }

    pub fn root(&self) -> &Job {
        &self
            .entries
            .last()
            .expect("validated nonempty selection")
            .job
    }

    pub fn jobs(&self) -> impl ExactSizeIterator<Item = &Job> {
        self.entries.iter().map(|entry| &entry.job)
    }

    /// Admission is bounded and idempotent for existing semantic jobs. Failure
    /// can leave dormant admitted jobs, but grants no candidate/launch authority.
    #[cfg(target_os = "linux")]
    pub fn admit(
        &self,
        owner: &mut super::journal::DurableDag,
        now_ms: u64,
    ) -> Result<JobId, Error> {
        for entry in &self.entries {
            owner.admit(
                entry.job.clone(),
                entry
                    .inputs
                    .iter()
                    .map(|input| input.bytes.to_vec())
                    .collect(),
                now_ms,
            )?;
        }
        Ok(self.root().id())
    }

    /// Attach only after the entire graph is admitted. A replacement must be
    /// attached before cancelling the old candidate if shared work is to stay
    /// eligible. A crash between those actions may retain both candidates; only
    /// the host's freshly checked selection may be sealed/exported.
    #[cfg(target_os = "linux")]
    pub fn attach(
        &self,
        owner: &mut super::journal::DurableDag,
        eligibility: [u8; 32],
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<super::dag::CandidateId, Error> {
        self.admit(owner, now_ms)?;
        owner.attach(self.root().id(), eligibility, deadline_ms, now_ms)
    }
}

#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "typed_selection_tests.rs"]
mod typed_tests;
