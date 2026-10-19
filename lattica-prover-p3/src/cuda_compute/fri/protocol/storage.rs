//! Bounded host coexistence for native FRI protocol and proof assembly.
//! Device stages retain their own preflight and retire the attempt on failure.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(in crate::cuda_compute) struct Layer {
    pub input_log: usize,
    pub log_arity: usize,
    pub cap_bytes: usize,
    pub query_bytes: usize,
}

pub(in crate::cuda_compute) struct Plan {
    pub layers: Vec<Layer>,
    pub final_bytes: usize,
    pub host_peak: usize,
}

impl Plan {
    pub fn new(
        params: FriParameters,
        heights: &[usize],
        degree: usize,
        // Each input commitment's raw query allowance and matrix count.
        initial: &[(usize, usize)],
        host_bytes: usize,
    ) -> Result<Self> {
        let final_log = params
            .log_blowup
            .checked_add(params.log_final_poly_len)
            .ok_or("CUDA FRI final height overflow")?;
        if !matches!(degree, 2 | 3)
            || heights.is_empty()
            || heights.len() > 26
            || heights[0] > 25
            || heights.windows(2).any(|p| p[0] <= p[1])
            || final_log > 25
            || params.log_final_poly_len > 16
            || heights
                .iter()
                .any(|&h| h < final_log || (params.log_final_poly_len > 0 && h == final_log))
            || !(1..=4).contains(&params.max_log_arity)
            || !(1..=256).contains(&params.num_queries)
            || params.cap_height > 25
            || params.commit_proof_of_work_bits > crate::transcript_limits::GRIND_BITS
            || params.query_proof_of_work_bits > crate::transcript_limits::GRIND_BITS
            || initial.is_empty()
            || initial.len() > 256
            || initial
                .iter()
                .any(|&(bytes, matrices)| bytes == 0 || !(1..=256).contains(&matrices))
        {
            return Err("unsupported CUDA FRI parameters, input ordering or query geometry".into());
        }
        let final_bytes = (1usize << params.log_final_poly_len) * degree * 8;
        let mut raw = final_bytes + params.num_queries * 16;
        let mut assembly = 64usize << 10;
        let mut add = |bytes: usize, overhead: usize| -> Result<()> {
            raw = raw
                .checked_add(bytes)
                .ok_or("CUDA FRI host output overflow")?;
            assembly = assembly
                .checked_add(overhead)
                .ok_or("CUDA FRI assembly overflow")?;
            Ok(())
        };
        for &(bytes, matrices) in initial {
            // Outer BatchOpening and two vectors per matrix, plus paths.
            add(bytes, params.num_queries * (matrices + 1) * 128)?;
        }
        let mut layers = vector(25)?;
        let mut height = heights[0];
        let mut next = 1;
        while height > final_log {
            let log_arity = p3_fri::compute_log_arity_for_round(
                height,
                heights.get(next).copied(),
                final_log,
                params.max_log_arity,
            );
            let leaf_log = height - log_arity;
            let cap_log = params.cap_height.min(leaf_log);
            let cap_bytes = (1usize << cap_log) * 4 * 8;
            let path_words = (leaf_log - cap_log) * 4;
            let query_bytes =
                params.num_queries * ((1 << log_arity) * degree + 4 + path_words + 1) * 8
                    + (64 << 10);
            add(cap_bytes + query_bytes + 8, params.num_queries * 256 + 512)?;
            layers.push(Layer {
                input_log: height,
                log_arity,
                cap_bytes,
                query_bytes,
            });
            height = leaf_log;
            if heights.get(next) == Some(&height) {
                next += 1;
            }
        }
        if next != heights.len() {
            return Err("CUDA FRI schedule leaves an input unconsumed".into());
        }
        // Raw u64 egress can coexist with its typed proof representation.
        // This deliberately retains all batches in the bound even though
        // execution converts and releases each raw batch before the next.
        let host_peak = raw
            .checked_mul(2)
            .and_then(|n| n.checked_add(assembly))
            .ok_or("CUDA FRI aggregate host storage overflow")?;
        if host_peak > host_bytes {
            return Err("CUDA FRI proof exceeds aggregate host allowance".into());
        }
        Ok(Self {
            layers,
            final_bytes,
            host_peak,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_and_aggregate_admission_cover_mixed_heights() {
        let params = FriParameters {
            log_blowup: 4,
            log_final_poly_len: 0,
            max_log_arity: 4,
            num_queries: 96,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 16,
            cap_height: 6,
        };
        let plan = Plan::new(params, &[18, 13, 9, 4], 3, &[(1 << 20, 3)], 64 << 20).unwrap();
        assert_eq!(
            plan.layers.iter().map(|s| s.log_arity).collect::<Vec<_>>(),
            [4, 1, 4, 4, 1]
        );
        assert!(Plan::new(
            params,
            &[18, 13, 9, 4],
            3,
            &[(1 << 20, 3)],
            plan.host_peak - 1
        )
        .is_err());
        assert_eq!(
            Plan::new(params, &[18, 13, 9, 4], 3, &[(1 << 20, 3)], plan.host_peak)
                .unwrap()
                .host_peak,
            plan.host_peak
        );
        for heights in [vec![], vec![26], vec![8, 8], vec![8, 3], vec![7, 8]] {
            assert!(Plan::new(params, &heights, 3, &[(1 << 20, 3)], 64 << 20).is_err());
        }
        assert!(Plan::new(params, &[8], 3, &[(usize::MAX, 1)], usize::MAX).is_err());
        assert!(Plan::new(params, &[8], 3, &[], usize::MAX).is_err());
        assert!(Plan::new(
            FriParameters {
                num_queries: 257,
                ..params
            },
            &[8],
            3,
            &[(1, 1)],
            usize::MAX
        )
        .is_err());
        let no_rounds = Plan::new(params, &[4], 2, &[(1, 1)], 1 << 20).unwrap();
        assert!(no_rounds.layers.is_empty());
        let final_params = FriParameters {
            log_final_poly_len: 3,
            ..params
        };
        assert!(Plan::new(final_params, &[7], 2, &[(1, 1)], 1 << 20).is_err());
        let plan = Plan::new(final_params, &[13, 8], 2, &[(1, 1)], 1 << 20).unwrap();
        assert_eq!(plan.final_bytes, 8 * 2 * 8);
    }
}
