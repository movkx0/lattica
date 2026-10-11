//! Keep the candidate's optimized host path and strict binary admission while
//! selecting the generic owned prover for the legacy quadratic profile.
use super::*;
use crate::block_v2::gpu_hash::{device, FriExtension, FriExtensionMmcs};

#[cfg(test)]
mod tests;

pub trait OpeningField: FriExtension + TwoAdicField {
    fn open_host(
        mmcs: &CandidateMmcs,
        fri: &FriParameters<FriExtensionMmcs<Self>>,
        rounds: Vec<(&ProverData, Vec<Vec<Self>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<Self>, InnerProof<Self>);

    fn fold_host(
        beta: Self,
        log_arity: usize,
        leaves: RowMajorMatrixView<'_, Self>,
    ) -> Option<Vec<Self>>;

    fn prove_owned(
        session: &device::DeviceSession,
        mmcs: &CandidateMmcs,
        fri: &FriParameters<FriExtensionMmcs<Self>>,
        input: Vec<device::DeviceMatrix>,
        challenger: &mut Challenger,
        max_height: usize,
        rounds: &[(&ProverData, Vec<Vec<Self>>)],
    ) -> Result<InnerProof<Self>, String>;
}

impl OpeningField for Challenge {
    fn open_host(
        mmcs: &CandidateMmcs,
        fri: &FriParameters<ChallengeMmcs>,
        rounds: Vec<(&ProverData, Vec<Vec<Self>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<Self>, InnerProof<Self>) {
        open(mmcs, fri, rounds, challenger)
    }

    fn fold_host(
        beta: Self,
        log_arity: usize,
        leaves: RowMajorMatrixView<'_, Self>,
    ) -> Option<Vec<Self>> {
        if log_arity == 1 {
            super::super::gpu_hash::fold_fri(beta, leaves.values)
                .expect("candidate GPU FRI folding failed; no silent fallback")
        } else {
            None
        }
    }

    fn prove_owned(
        session: &device::DeviceSession,
        mmcs: &CandidateMmcs,
        fri: &FriParameters<ChallengeMmcs>,
        input: Vec<device::DeviceMatrix>,
        challenger: &mut Challenger,
        max_height: usize,
        rounds: &[(&ProverData, Vec<Vec<Self>>)],
    ) -> Result<InnerProof<Self>, String> {
        owned_fri::prove(session, mmcs, fri, input, challenger, max_height, rounds)
    }
}

impl OpeningField for crate::config::Challenge {
    fn open_host(
        mmcs: &CandidateMmcs,
        fri: &FriParameters<FriExtensionMmcs<Self>>,
        rounds: Vec<(&ProverData, Vec<Vec<Self>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<Self>, InnerProof<Self>) {
        // This branch is only for explicitly selected host openings. Share the
        // active salt streams; constructing an adapter must not replay them.
        // Upstream expects complete LDE matrices. A retained degree prefix is
        // only sufficient for our owned opening evaluator, not this host path.
        assert!(
            rounds.iter().all(|(data, _)| !matches!(
                data,
                super::super::gpu_hash::ProverData::Compact(_)
                    | super::super::gpu_hash::ProverData::DeviceOnly { .. }
            )),
            "quadratic compact PCS requires owned GPU openings"
        );
        let params = FriParameters {
            log_blowup: fri.log_blowup,
            log_final_poly_len: fri.log_final_poly_len,
            max_log_arity: fri.max_log_arity,
            num_queries: fri.num_queries,
            commit_proof_of_work_bits: fri.commit_proof_of_work_bits,
            query_proof_of_work_bits: fri.query_proof_of_work_bits,
            mmcs: FriExtensionMmcs::new(
                fri.mmcs
                    .inner()
                    .share_for_resident()
                    .expect("shared FRI MMCS"),
            ),
        };
        let pcs = InnerPcs::<Self>::new(
            crate::config::Dft::default(),
            mmcs.share_for_resident().expect("shared input MMCS"),
            params,
        );
        pcs.open(rounds, challenger)
    }

    fn fold_host(_: Self, _: usize, _: RowMajorMatrixView<'_, Self>) -> Option<Vec<Self>> {
        // The explicit host-FRI mode uses the upstream generic folding strategy.
        None
    }

    fn prove_owned(
        session: &device::DeviceSession,
        mmcs: &CandidateMmcs,
        fri: &FriParameters<FriExtensionMmcs<Self>>,
        input: Vec<device::DeviceMatrix>,
        challenger: &mut Challenger,
        max_height: usize,
        rounds: &[(&ProverData, Vec<Vec<Self>>)],
    ) -> Result<InnerProof<Self>, String> {
        let data: Vec<_> = rounds.iter().map(|(data, _)| *data).collect();
        owned_fri::general::prove(session, mmcs, fri, input, challenger, max_height, &data)
    }
}
