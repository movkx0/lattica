//! Adapted from Plonky3 p3-commit 0.6.1 extension_mmcs.rs (MIT OR Apache-2.0).
//! Identical base/extension encoding, with crate-private access to the original
//! MMCS salt stream for device FRI. No cloned or alternate random stream.
//! License: gpu_quotient_prover/LICENSE-APACHE.
use core::marker::PhantomData;
use core::ops::Deref;
use std::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::extension::FlatMatrixView;
use p3_matrix::{Dimensions, Matrix};

use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};

/// A wrapper to lift an MMCS from a base field `F` to an extension field `EF`.
///
/// `CandidateExtensionMmcs` allows committing to and opening matrices over an extension field by internally
/// using an MMCS defined on the base field. It works by flattening each extension field element
/// into its base field coordinates for commitment, and then reconstructing them on opening.
#[derive(Clone, Debug)]
pub struct CandidateExtensionMmcs<F, EF, InnerMmcs> {
    /// The inner MMCS instance used to handle commitments at the base field level.
    pub(crate) inner: InnerMmcs,

    pub(crate) _phantom: PhantomData<(F, EF)>,
}

impl<F, EF, InnerMmcs> CandidateExtensionMmcs<F, EF, InnerMmcs> {
    pub(crate) fn inner(&self) -> &InnerMmcs {
        &self.inner
    }

    pub const fn new(inner: InnerMmcs) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<F, EF, InnerMmcs> Mmcs<EF> for CandidateExtensionMmcs<F, EF, InnerMmcs>
where
    F: Field,
    EF: ExtensionField<F>,
    InnerMmcs: Mmcs<F>,
{
    type ProverData<M> = InnerMmcs::ProverData<FlatMatrixView<F, EF, M>>;
    type Commitment = InnerMmcs::Commitment;
    type Proof = InnerMmcs::Proof;
    type Error = InnerMmcs::Error;

    fn commit<M: Matrix<EF>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        self.inner
            .commit(inputs.into_iter().map(FlatMatrixView::new).collect())
    }

    fn open_batch<M: Matrix<EF>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<EF, Self> {
        let (inner_opened_values, inner_proof) = self.inner.open_batch(index, prover_data).unpack();
        let opened_ext_values = inner_opened_values
            .into_iter()
            .map(EF::reconstitute_from_base)
            .collect();
        BatchOpening::new(opened_ext_values, inner_proof)
    }

    fn get_matrices<'a, M: Matrix<EF>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.inner
            .get_matrices(prover_data)
            .into_iter()
            .map(|mat| mat.deref())
            .collect()
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, EF, Self>,
    ) -> Result<(), Self::Error> {
        let opened_base_values: Vec<Vec<F>> = batch_opening
            .opened_values
            .iter()
            .cloned()
            .map(EF::flatten_to_base)
            .collect();
        let base_dimensions = dimensions
            .iter()
            .map(|dim| Dimensions {
                width: dim.width * EF::DIMENSION,
                height: dim.height,
            })
            .collect::<Vec<_>>();
        self.inner.verify_batch(
            commit,
            &base_dimensions,
            index,
            BatchOpeningRef::new(&opened_base_values, batch_opening.opening_proof),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block_v2::profile::Challenge,
        config::{MyCompress, MyHash, Val, ValMmcs},
    };
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn extension_adapter_matches_upstream_encoding_salts_and_verification() {
        let make = || {
            let perm = default_goldilocks_poseidon2_8();
            ValMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm),
                2,
                ChaCha20Rng::from_seed([41; 32]),
            )
        };
        let actual = CandidateExtensionMmcs::<Val, Challenge, _>::new(make());
        let reference = p3_commit::ExtensionMmcs::<Val, Challenge, _>::new(make());
        let mut rng = ChaCha20Rng::from_seed([89; 32]);
        for _ in 0..3 {
            let inputs = vec![
                RowMajorMatrix::rand(&mut rng, 32, 3),
                RowMajorMatrix::rand(&mut rng, 16, 7),
            ];
            let dims: Vec<_> = inputs.iter().map(|m| m.dimensions()).collect();
            let (cap, data) = actual.commit(inputs.clone());
            let (expected, original) = reference.commit(inputs);
            assert_eq!(cap, expected);
            for index in [0, 7, 31, 0] {
                let (values, proof) = actual.open_batch(index, &data).unpack();
                let (other, other_proof) = reference.open_batch(index, &original).unpack();
                assert_eq!(values, other);
                assert_eq!(
                    postcard::to_allocvec(&proof).unwrap(),
                    postcard::to_allocvec(&other_proof).unwrap()
                );
                reference
                    .verify_batch(&cap, &dims, index, BatchOpeningRef::new(&values, &proof))
                    .unwrap();
                actual
                    .verify_batch(
                        &expected,
                        &dims,
                        index,
                        BatchOpeningRef::new(&other, &other_proof),
                    )
                    .unwrap();
            }
        }
    }
}
