use super::*;
use crate::block_v2::{gpu_hash::device::DomainSpec, profile::Challenge};
use p3_lookup::{Kind, Lookup};
use std::collections::HashMap;

/// Host work is restricted to deterministic names, indices and tuple lengths.
fn bus_layout(lookups: &[&[Lookup<Val>]]) -> Result<(Vec<Vec<usize>>, usize, usize), String> {
    let mut globals = HashMap::new();
    let mut next = 0;
    let mut width = 1;
    let mut count = 0usize;
    let mut ids = Vec::with_capacity(lookups.len());
    for contexts in lookups {
        let mut instance = Vec::with_capacity(contexts.len().min(resources::SCALAR_OUTPUTS));
        for lookup in *contexts {
            count = count.checked_add(1).ok_or("GPU lookup count overflow")?;
            if count > resources::SCALAR_OUTPUTS {
                return Err("GPU lookup scalar count exceeds admission".into());
            }
            for tuple in &lookup.elements {
                width = width.max(tuple.len());
            }
            let id = match &lookup.kind {
                Kind::Global(name) => *globals.entry(name.as_str()).or_insert_with(|| {
                    let id = next;
                    next += 1;
                    id
                }),
                Kind::Local => {
                    let id = next;
                    next += 1;
                    id
                }
            };
            instance.push(id);
        }
        ids.push(instance);
    }
    if width > u32::MAX as usize {
        return Err("GPU lookup message width exceeds admission".into());
    }
    Ok((ids, width, next))
}

fn words(value: Challenge) -> [u64; 3] {
    let c: &[Val] = value.as_basis_coefficients_slice();
    [
        c[0].as_canonical_u64(),
        c[1].as_canonical_u64(),
        c[2].as_canonical_u64(),
    ]
}
fn challenge(value: [u64; 3]) -> Challenge {
    Challenge::from_basis_coefficients_fn(|i| Val::new(value[i]))
}

impl CandidateChallenger {
    /// The caller selects this only for the owned GPU transcript. CPU batch
    /// proving continues to use the upstream BatchTranscript implementation.
    pub(crate) fn gpu_lookup_challenges(
        &mut self,
        lookups: &[&[Lookup<Val>]],
    ) -> Vec<Vec<Challenge>> {
        let Backend::Gpu(gpu) = &mut self.inner else {
            panic!("GPU lookup scalar derivation requires the GPU transcript");
        };
        let (ids, width, buses) = checked(gpu, bus_layout(lookups));
        checked(gpu, gpu.derive_scalars(|_| Ok(())));
        if buses == 0 {
            return ids.into_iter().map(|_| Vec::new()).collect();
        }
        // Exactly the upstream six base-field samples, alpha followed by beta.
        let sampled = gpu.sample_fields(6);
        let sampled = checked(gpu, sampled);
        let alpha = [sampled[0], sampled[1], sampled[2]];
        let beta = [sampled[3], sampled[4], sampled[5]];
        let prefixes = checked(
            gpu,
            gpu.derive_scalars(|session| session.lookup_prefixes(alpha, beta, width, buses)),
        );
        let beta = challenge(beta);
        ids.into_iter()
            .map(|ids| {
                ids.into_iter()
                    .flat_map(|id| [challenge(prefixes[id]), beta])
                    .collect()
            })
            .collect()
    }

    /// Compute each instance's next-row point once and reuse it for main,
    /// preprocessing and lookup rounds. Scalar operations never absorb data.
    pub(crate) fn next_points<F: crate::block_v2::gpu_hash::FriExtension>(
        &self,
        point: F,
        domains: &[DomainSpec],
    ) -> Vec<F> {
        match &self.inner {
            Backend::Cpu(_) => domains
                .iter()
                .map(|d| point * Val::TWO_ADIC_GENERATORS[d.log_size()])
                .collect(),
            Backend::Gpu(gpu) => {
                let result = gpu.derive_scalars(|session| {
                    if domains.is_empty() {
                        return Ok(Vec::new());
                    }
                    session.next_points_extension(
                        F::DEVICE_EXTENSION,
                        &point
                            .as_basis_coefficients_slice()
                            .iter()
                            .map(PrimeField64::as_canonical_u64)
                            .collect::<Vec<_>>(),
                        &domains.iter().map(|d| d.log_size()).collect::<Vec<_>>(),
                    )
                });
                checked(gpu, result)
                    .chunks_exact(F::DIMENSION)
                    .map(|value| F::from_basis_coefficients_fn(|i| Val::new(value[i])))
                    .collect()
            }
        }
    }
}

#[cfg(test)]
mod tests;
