//! Native lookup adapter: the six sampled coefficients and every derived pair
//! remain resident. CPU work assigns public bus IDs and instance word ranges.
use super::{lookup_layout, Backend, CandidateChallenger, Val};
use crate::{
    cuda_compute::{Buffer, Scalars},
    gpu_matrix::Extension,
};
use p3_lookup::Lookup;
use std::{ops::Range, sync::Arc};

pub(crate) struct CudaLookupChallenges {
    pub values: Option<Buffer>,
    pub instances: Vec<Range<usize>>,
}

impl CandidateChallenger {
    pub(crate) fn cuda_lookup_challenges(
        &mut self,
        scalars: &Arc<Scalars>,
        lookups: &[&[Lookup<Val>]],
    ) -> Result<CudaLookupChallenges, String> {
        let Backend::Cuda(gpu) = &mut self.inner else {
            return Err("native CUDA lookup challenges require a CUDA transcript".into());
        };
        let result = (|| {
            gpu.check_scalars(scalars)?;
            let (ids, width, buses) = lookup_layout::bus_layout(lookups)?;
            let mut instances = lookup_layout::exact(ids.len())?;
            let count: usize = ids.iter().map(Vec::len).sum(); // validated <= 4096
            let mut flat = lookup_layout::exact(count)?;
            for row in &ids {
                let start = flat.len() * 6;
                flat.extend_from_slice(row);
                instances.push(start..flat.len() * 6);
            }
            if buses == 0 {
                return Ok(CudaLookupChallenges {
                    values: None,
                    instances,
                });
            }
            // Prepare every ID/output allocation and admit the six sample words
            // before consuming the transcript. There is no host challenge draw.
            let prepared = scalars.prepare_lookup(Extension::Cubic, width, &flat)?;
            let sampled = gpu.sample_resident(6)?;
            let values = gpu.derive_scalars(scalars, || prepared.finish(&sampled))?;
            Ok(CudaLookupChallenges {
                values: Some(values),
                instances,
            })
        })();
        if result.is_err() {
            gpu.retire();
        }
        result
    }
}

#[cfg(test)]
mod tests;
