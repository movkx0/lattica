//! Conservative coexistence of initial PCS queries, every FRI query batch and
//! the host assembly arrays. Engine/transcript storage and allocator overhead
//! remain separate. Geometry is admitted before folding or transcript changes.
use super::*;
use crate::block_v2::gpu_hash::FriData;
use core::mem::size_of;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct Layer {
    pub log_height: usize,
    pub log_arity: usize,
}

pub(super) struct Geometry<'a> {
    pub input_heights: &'a [usize],
    pub log_blowup: usize,
    pub log_final_len: usize,
    pub max_log_arity: usize,
    pub queries: usize,
    pub initial_rounds: usize,
}

#[derive(Debug)]
pub(super) struct Plan {
    layers: [Layer; 25],
    pub layer_count: usize,
    pub initial_query_bytes: usize,
    pub fri_query_bytes: usize,
    pub assembly_bytes: usize,
    pub total_bytes: usize,
    pub limit: usize,
}

impl Plan {
    pub fn new<F: FriExtension>(
        g: Geometry<'_>,
        initial_query_bytes: usize,
        limit: usize,
    ) -> Result<Self, String> {
        let heights = g.input_heights;
        let final_height = g
            .log_blowup
            .checked_add(g.log_final_len)
            .ok_or("FRI storage height overflow")?;
        if limit > HOST_QUERY_ALLOWANCE
            || initial_query_bytes > limit
            || heights.is_empty()
            || heights.len() > 26
            || heights[0] > 25
            || final_height > 25
            || g.log_final_len > 16
            || !(1..=4).contains(&g.max_log_arity)
            || g.queries == 0
            || g.queries > profile::NUM_QUERIES
            || g.initial_rounds > 256
            || (g.initial_rounds == 0 && initial_query_bytes != 0)
            || heights.windows(2).any(|p| p[0] <= p[1])
            || heights
                .iter()
                .any(|h| *h < final_height || (g.log_final_len > 0 && *h == final_height))
            || size_of::<F>() != F::DIMENSION * 8
        {
            return Err("FRI proof storage geometry or allowance".into());
        }
        let mut layers = [Layer::default(); 25];
        let mut height = heights[0];
        let mut next = 1;
        let mut layer_count = 0;
        let mut fri_query_bytes = 0usize;
        let mut cap_bytes = 0usize;
        while height > final_height {
            let log_arity = p3_fri::compute_log_arity_for_round(
                height,
                heights.get(next).copied(),
                final_height,
                g.max_log_arity,
            );
            height -= log_arity;
            layers[layer_count] = Layer {
                log_height: height,
                log_arity,
            };
            layer_count += 1;
            fri_query_bytes = fri_query_bytes
                .checked_add(FriData::query_host_bytes::<F>(
                    height,
                    1 << log_arity,
                    g.queries,
                )?)
                .ok_or("FRI query storage overflow")?;
            // Tree cap, proof cap, and temporary observation copy. Existing
            // engine staging is charged by the enclosing engine reservation.
            cap_bytes += 3 * (1usize << height.min(profile::CAP_HEIGHT)) * size_of::<[Val; 4]>();
            if heights.get(next) == Some(&height) {
                next += 1;
            }
        }
        if next != heights.len() {
            return Err("FRI storage schedule did not consume input heights".into());
        }
        type Input = BatchOpening<Val, CandidateMmcs>;
        type Step<F> = CommitPhaseProofStep<F, FriExtensionMmcs<F>>;
        type Query<F> = QueryProof<F, FriExtensionMmcs<F>, Vec<Input>>;
        // Sum temporary local-index arrays rather than recycling their charge.
        // The FRI row retains its full arity capacity after removing the queried
        // element in place; query_host_bytes includes that full row.
        let assembly_bytes = cap_bytes
            + layer_count
                * (size_of::<<CandidateMmcs as Mmcs<Val>>::Commitment>()
                    + size_of::<(FriData, usize)>()
                    + size_of::<Val>())
            + g.queries * size_of::<usize>() * (1 + g.initial_rounds + layer_count)
            + g.queries * (size_of::<Vec<Input>>() + g.initial_rounds * size_of::<Input>())
            + g.queries * (size_of::<Vec<Step<F>>>() + layer_count * size_of::<Step<F>>())
            + g.queries * size_of::<Query<F>>()
            + 2 * (1usize << g.log_final_len) * size_of::<F>();
        let total_bytes = initial_query_bytes
            .checked_add(fri_query_bytes)
            .and_then(|n| n.checked_add(assembly_bytes))
            .filter(|n| *n <= limit)
            .ok_or("FRI proof material exceeds combined host allowance")?;
        Ok(Self {
            layers,
            layer_count,
            initial_query_bytes,
            fri_query_bytes,
            assembly_bytes,
            total_bytes,
            limit,
        })
    }

    pub fn layers(&self) -> &[Layer] {
        &self.layers[..self.layer_count]
    }

    pub fn report(&self) {
        eprintln!("bounded_fri_proof_storage layers={} initial_query_bytes={} fri_query_bytes={} assembly_bytes={} planned_bytes={} limit_bytes={}",
            self.layer_count, self.initial_query_bytes, self.fri_query_bytes, self.assembly_bytes, self.total_bytes, self.limit);
    }
}

#[cfg(test)]
mod tests;
