//! Shared CPU/AIR oracle fixture for both GPU quotient transports.
use super::Program;
use crate::{
    block_v2::{machine::symbolic::Constraints, pcs_field::FriExtension},
    config::Val,
};
use p3_air::{
    symbolic::{AirLayout, SymbolicExpressionExt},
    Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess,
};
use p3_field::{Algebra, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;
pub(crate) struct ExtensionAir<F>(F);

impl<F: FriExtension> BaseAir<Val> for ExtensionAir<F> {
    fn width(&self) -> usize {
        3
    }
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
}

impl<F: FriExtension, AB: PermutationAirBuilder<F = Val, EF = F>> Air<AB> for ExtensionAir<F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pre = builder.preprocessed().clone();
        let permutation = builder.permutation();
        let m = main.current_slice();
        let n = main.next_slice();
        let p = pre.current_slice();
        let pn = pre.next_slice();
        let q = permutation.current_slice();
        let qn = permutation.next_slice();
        let public = builder.public_values().to_vec();
        let random = builder.permutation_randomness().to_vec();
        let terminal: AB::ExprEF = builder.permutation_values()[0].clone().into();
        let c0: AB::ExprEF = random[0].into();
        let c1: AB::ExprEF = random[1].into();
        let constant = AB::ExprEF::from(self.0);
        let permutation0: AB::ExprEF = q[0].into();
        let local: AB::Expr = m[0].into();
        let public0: AB::Expr = public[0].into();
        let public1: AB::Expr = public[1].into();
        builder.assert_zero(-(local.clone() + public0) * (n[1].into() - pn[0]));
        builder.assert_zero_ext(
            -(qn[0].into() + c0.clone()) * (q[1].into() - terminal.clone() + constant.clone()),
        );
        builder.when_first_row().assert_zero(p[0].into() - m[2]);
        builder
            .when_last_row()
            .assert_zero_ext(c1 * permutation0 + constant);
        builder.when_transition().assert_zero(n[0].into() - m[1]);
        builder.assert_zero_ext((qn[1].into() + terminal) * (c0 + AB::ExprEF::from(local)));
        builder.assert_zero(public1 - n[2]);
    }
}

pub(crate) fn constant<F: FriExtension>() -> F {
    F::from_basis_coefficients_fn(|i| Val::new(0xffff_ffff_0000_0000 - i as u64))
}

pub(crate) fn program<F: FriExtension>() -> Program
where
    SymbolicExpressionExt<Val, F>: Algebra<F>,
{
    let air = ExtensionAir(constant::<F>());
    let layout = AirLayout {
        permutation_width: 2,
        num_permutation_challenges: 2,
        num_permutation_values: 1,
        ..AirLayout::from_air::<Val>(&air)
    };
    let mut builder = InteractionSymbolicBuilder::<Val, F>::new(layout);
    air.eval(&mut builder);
    Program::from_constraints(
        layout,
        &Constraints {
            order: builder.constraint_layout(),
            base: builder.base_constraints(),
            extension: builder.extension_constraints(),
        },
    )
    .unwrap()
}

pub(crate) fn words<F: FriExtension>(value: F) -> Vec<u64> {
    value
        .as_basis_coefficients_slice()
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}
