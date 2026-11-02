//! Public arithmetic layouts live only for one admitted graph-preparation scope.
//! Every evaluation still enters OperationContext, including its failed-scope
//! check, buffer scrubbing and completion accounting. No witness is cached.
use super::*;
use std::cell::RefCell;

pub(in crate::rust_verify::committed_backend) struct PreparedDevice<'a, 'run> {
    operations: &'a OperationContext<'run>,
    ntt: RefCell<[Option<ArithmeticOperationSpec>; 2]>,
    mul: RefCell<[Option<ArithmeticOperationSpec>; 2]>,
}
impl<'a, 'run> PreparedDevice<'a, 'run> {
    pub(in crate::rust_verify::committed_backend) fn new(
        operations: &'a OperationContext<'run>,
    ) -> Self {
        Self {
            operations,
            ntt: RefCell::new([None, None]),
            mul: RefCell::new([None, None]),
        }
    }
    fn index(q: u64) -> Result<usize, String> {
        match q {
            Q => Ok(0),
            QHAT => Ok(1),
            _ => Err("unsupported graph operation modulus".into()),
        }
    }
}
macro_rules! forward {
    ($name:ident($($arg:ident: $ty:ty),*) -> $out:ty) => {
        fn $name(&self, $($arg: $ty),*) -> Result<$out, String> {
            GraphDevice::$name(self.operations, $($arg),*)
        }
    };
}
impl GraphDevice for PreparedDevice<'_, '_> {
    fn deferred_commitments(&self) -> bool { true }
    fn commit_nodes(&self, nodes: &[lattica_prover_p3::block_v2::native_gpu::NodeCommitment<'_>]) -> Result<Vec<[Val; 4]>, String> {
        use p3_field::PrimeCharacteristicRing;
        Ok(self.operations.commit_node_batch(nodes)?.into_iter().map(|root| root.map(Val::from_u64)).collect())
    }
    forward!(canonical(kind: CanonicalOperation, left: &[u64], right: &[u64], q: u64) -> Vec<u64>);
    forward!(signed(kind: SignedOperation, input: &[u64], count: usize) -> Vec<u64>);
    forward!(convert(input: &[i64], q: u64) -> Vec<u64>);
    forward!(aut_poly(input: &RawPoly) -> RawPoly);
    forward!(inverse_challenge_poly(input: &RawSigned) -> RawSigned);
    forward!(commit_canonical(input: &RawPoly, q: u64) -> [Val; 4]);
    forward!(commit_signed(input: &RawSigned) -> [Val; 4]);
    forward!(commit_bytes(input: &[u8; 32]) -> [Val; 4]);
    forward!(parameters(seed: &[u8; 32], context: &[u8; 32]) -> primitives::Parameters);
    forward!(sample_g(seed: &[u8; 32]) -> Vec<RawPoly>);
    forward!(expand_alpha(seed: &[u8; 32]) -> (Vec<RawPoly>, RawSigned));
    forward!(hash_alpha(input: &[u8]) -> [u8; 32]);
    forward!(hash_x(input: &[u8]) -> RawSigned);

    fn ntt_poly(&self, input: &RawSigned, q: u64) -> Result<RawPoly, String> {
        let mut layouts = self.ntt.borrow_mut();
        let slot = &mut layouts[Self::index(q)?];
        if slot.is_none() {
            *slot = Some(
                NttAir::new(q, 1)
                    .map_err(|e| format!("{e:?}"))?
                    .raw_operation_spec()?,
            );
        }
        let raw = input.map(|v| v as u64);
        polynomial(
            self.operations
                .arithmetic_output(slot.as_ref().unwrap(), &raw)?,
        )
    }
    fn mul_poly(&self, left: &RawPoly, right: &RawPoly, q: u64) -> Result<RawPoly, String> {
        let mut layouts = self.mul.borrow_mut();
        let slot = &mut layouts[Self::index(q)?];
        if slot.is_none() {
            *slot = Some(
                MulAir::new(q, 1)
                    .map_err(|e| format!("{e:?}"))?
                    .raw_operation_spec()?,
            );
        }
        let raw: [u64; 2 * D] =
            core::array::from_fn(|i| if i < D { left[i] } else { right[i - D] });
        polynomial(
            self.operations
                .arithmetic_output(slot.as_ref().unwrap(), &raw)?,
        )
    }
}
