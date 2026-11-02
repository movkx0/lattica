//! Fixed recipes using existing raw GPU operations. Device values are replayed
//! into the exact scalar expression order; no extra polynomial nodes are made.
use super::gpu::GraphDevice;
use super::*;
use lattica_prover_p3::block_v2::native_gpu::operations_arithmetic::CanonicalOperation;
type RawPoly = [u64; D];
use crate::preparation_options::{reuse_count, ReuseCounter};

// Includes overlapping input, intermediate, output and returned frames, plus
// reference arrays. This is charged before entering the raw preparation scope.
pub(super) const FRAME_BYTES: usize = 8
    * (16 * core::mem::size_of::<RawPoly>() + 16 * core::mem::size_of::<Polynomial<ResidueRef>>());

fn four(
    device: &dyn GraphDevice,
    kind: CanonicalOperation,
    a: &[u64; 4],
    b: &[u64; 4],
) -> Result<[u64; 4], String> {
    device
        .canonical(kind, a, b, Q)?
        .try_into()
        .map_err(|_| "GPU adjustment output shape".into())
}
impl CommittedBackend<'_> {
    fn recipe_input(&self, input: &Polynomial<ResidueRef>) -> RawPoly {
        input.map(|value| {
            self.check_residue(value, Q);
            value.value
        })
    }
    fn recipe_result(
        &mut self,
        a: ResidueRef,
        b: ResidueRef,
        value: u64,
        subtract: bool,
    ) -> ResidueRef {
        if self.canonical_constant(a).is_some() && self.canonical_constant(b).is_some() {
            return self.constant(value, Q);
        }
        let expr = self.expression(if subtract {
            Expression::Sub {
                left: a.expr,
                right: b.expr,
                modulus: Q,
            }
        } else {
            Expression::Add {
                left: a.expr,
                right: b.expr,
                modulus: Q,
            }
        });
        ResidueRef {
            owner: self.graph.owner,
            expr,
            modulus: Q,
            value,
        }
    }
    pub(super) fn vector_relation_balance(
        &mut self,
        a: &Polynomial<ResidueRef>,
        aut: &Polynomial<ResidueRef>,
        out0: &Polynomial<ResidueRef>,
        out1: &Polynomial<ResidueRef>,
        z0: &Polynomial<ResidueRef>,
    ) -> Polynomial<ResidueRef> {
        let (av, autv, ov0, ov1, zv) = (
            self.recipe_input(a),
            self.recipe_input(aut),
            self.recipe_input(out0),
            self.recipe_input(out1),
            self.recipe_input(z0),
        );
        reuse_count(ReuseCounter::VectorRecipes);
        let raw = self
            .on_device(|device| {
                let twice = device.add_poly(&autv, &autv, Q)?;
                let first = device.sub_poly(&av, &twice, Q)?;
                let second = device.add_poly(&first, &ov0, Q)?;
                let third = device.add_poly(&second, &ov1, Q)?;
                let last = device.sub_poly(&third, &zv, Q)?;
                Ok([twice, first, second, third, last])
            })
            .expect("vector recipe requires device")
            .unwrap_or([[0; D]; 5]);
        core::array::from_fn(|i| {
            let twice = self.recipe_result(aut[i], aut[i], raw[0][i], false);
            let value = self.recipe_result(a[i], twice, raw[1][i], true);
            let value = self.recipe_result(value, out0[i], raw[2][i], false);
            let value = self.recipe_result(value, out1[i], raw[3][i], false);
            self.recipe_result(value, z0[i], raw[4][i], true)
        })
    }
    pub(super) fn vector_relation_coin_term(
        &mut self,
        aut: &Polynomial<ResidueRef>,
        coin0: &Polynomial<ResidueRef>,
        coin1: &Polynomial<ResidueRef>,
        c: &Polynomial<ResidueRef>,
    ) -> Polynomial<ResidueRef> {
        let (av, c0, c1, cv) = (
            self.recipe_input(aut),
            self.recipe_input(coin0),
            self.recipe_input(coin1),
            self.recipe_input(c),
        );
        reuse_count(ReuseCounter::VectorRecipes);
        let raw = self
            .on_device(|device| {
                let twice = device.add_poly(&av, &av, Q)?;
                let first = device.sub_poly(&twice, &c0, Q)?;
                let second = device.sub_poly(&first, &c1, Q)?;
                let last = device.sub_poly(&second, &cv, Q)?;
                Ok([twice, first, second, last])
            })
            .expect("vector recipe requires device")
            .unwrap_or([[0; D]; 4]);
        core::array::from_fn(|i| {
            let value = self.recipe_result(aut[i], aut[i], raw[0][i], false);
            let value = self.recipe_result(value, coin0[i], raw[1][i], true);
            let value = self.recipe_result(value, coin1[i], raw[2][i], true);
            self.recipe_result(value, c[i], raw[3][i], true)
        })
    }
    pub(super) fn vector_relation_adjust(
        &mut self,
        w: &mut Polynomial<ResidueRef>,
        f10: &Polynomial<ResidueRef>,
        f11: &Polynomial<ResidueRef>,
    ) {
        // Validate all operands before issuing the first device operation.
        let (wv, a, b) = (
            self.recipe_input(w),
            self.recipe_input(f10),
            self.recipe_input(f11),
        );
        let (left, right, wl, wr, al, ar, bl, br): (
            _,
            _,
            [u64; 4],
            [u64; 4],
            [u64; 4],
            [u64; 4],
            [u64; 4],
            [u64; 4],
        ) = (
            CanonicalOperation::Add,
            CanonicalOperation::Subtract,
            core::array::from_fn(|i| wv[124 + i]),
            core::array::from_fn(|i| wv[128 + i]),
            core::array::from_fn(|i| a[124 + i]),
            core::array::from_fn(|i| a[128 + i]),
            core::array::from_fn(|i| b[124 + i]),
            core::array::from_fn(|i| b[128 + i]),
        );
        reuse_count(ReuseCounter::VectorRecipes);
        let raw = self
            .on_device(|device| {
                let delta = four(device, right, &al, &bl)?;
                let twice = four(device, left, &delta, &delta)?;
                let lower = four(device, left, &wl, &twice)?;
                let other = four(device, right, &br, &ar)?;
                let upper = four(device, left, &wr, &other)?;
                Ok([delta, twice, lower, other, upper])
            })
            .expect("vector recipe requires device")
            .unwrap_or([[0; 4]; 5]);
        for i in 0..4 {
            let j = 124 + i;
            let delta = self.recipe_result(f10[j], f11[j], raw[0][i], true);
            let twice = self.recipe_result(delta, delta, raw[1][i], false);
            w[j] = self.recipe_result(w[j], twice, raw[2][i], false);
            let j = 128 + i;
            let delta = self.recipe_result(f11[j], f10[j], raw[3][i], true);
            w[j] = self.recipe_result(w[j], delta, raw[4][i], false);
        }
    }
    pub(super) fn vector_inverse_challenge(
        &mut self,
        x: &Polynomial<SignedRef>,
    ) -> Polynomial<SignedRef> {
        let values = x.map(|value| {
            self.check_signed(value);
            value.value
        });
        reuse_count(ReuseCounter::VectorRecipes);
        let raw = self
            .on_device(|device| device.inverse_challenge_poly(&values))
            .expect("vector recipe requires device")
            .unwrap_or([0; D]);
        core::array::from_fn(|i| {
            let input = x[(3 * i) % D];
            if !(86..171).contains(&i) {
                return input;
            }
            let expr = self.expression(Expression::SignedNeg {
                input: input.expr,
                bound: input.bound,
            });
            SignedRef {
                owner: self.graph.owner,
                expr,
                bound: input.bound,
                value: raw[i],
            }
        })
    }
}
