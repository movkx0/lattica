use super::*;
use crate::block_v2::{gpu_hash::device::DomainSpec, profile::Challenge};
use p3_lookup::{Kind, Lookup};

fn lookup_count(lookups: &[&[Lookup<Val>]]) -> Result<usize, String> {
    let mut count = 0usize;
    for contexts in lookups {
        count = count
            .checked_add(contexts.len())
            .ok_or("GPU lookup count overflow")?;
        storage::Plan::lookup(lookups.len(), count)?;
    }
    storage::Plan::lookup(lookups.len(), count)?;
    Ok(count)
}

fn bus_layout(lookups: &[&[Lookup<Val>]]) -> Result<(Vec<Vec<usize>>, usize, usize), String> {
    lookup_count(lookups)?;
    super::lookup_layout::bus_layout(lookups)
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
        let count = checked(gpu, lookup_count(lookups));
        let plan = checked(gpu, storage::Plan::lookup(lookups.len(), count));
        let mut scope = checked(gpu, gpu.reserve_host_storage(plan));
        let (ids, width, buses) = checked(gpu, bus_layout(lookups));
        checked(gpu, gpu.derive_scalars(|_| Ok(())));
        let mut output = checked(gpu, storage::exact::<Vec<Challenge>>(ids.len()));
        for row in &ids {
            output.push(checked(gpu, storage::exact::<Challenge>(2 * row.len())));
        }
        if buses == 0 {
            return output;
        }
        // Exactly the upstream six base-field samples, alpha followed by beta.
        let sampled = gpu.sample_fields_scoped(6, &mut scope);
        let sampled = checked(gpu, sampled);
        let alpha = [sampled[0], sampled[1], sampled[2]];
        let beta = [sampled[3], sampled[4], sampled[5]];
        let prefixes = checked(
            gpu,
            gpu.derive_scalars(|session| {
                session.lookup_prefixes_scoped(alpha, beta, width, buses, &mut scope)
            }),
        );
        let beta = challenge(beta);
        for (row, ids) in output.iter_mut().zip(&ids) {
            for &id in ids {
                row.push(challenge(prefixes[id]));
                row.push(beta);
            }
        }
        output
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
                let plan = checked(gpu, storage::Plan::next_points(domains.len(), F::DIMENSION));
                let mut scope = checked(gpu, gpu.reserve_host_storage(plan));
                let mut output = checked(gpu, storage::exact::<F>(domains.len()));
                let result = gpu.derive_scalars(|session| {
                    if domains.is_empty() {
                        return Ok(Vec::new());
                    }
                    let mut words = [0u64; 3];
                    for (word, value) in words.iter_mut().zip(point.as_basis_coefficients_slice()) {
                        *word = value.as_canonical_u64();
                    }
                    let mut logs = storage::exact(domains.len())?;
                    logs.extend(domains.iter().map(|d| d.log_size()));
                    session.next_points_extension_scoped(
                        F::DEVICE_EXTENSION,
                        &words[..F::DIMENSION],
                        &logs,
                        &mut scope,
                    )
                });
                for value in checked(gpu, result).chunks_exact(F::DIMENSION) {
                    output.push(F::from_basis_coefficients_fn(|i| Val::new(value[i])));
                }
                output
            }
        }
    }
}

#[cfg(test)]
mod tests;
