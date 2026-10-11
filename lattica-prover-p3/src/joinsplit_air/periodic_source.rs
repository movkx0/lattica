//! Allocation-free columns; `super::periodic` remains the independent oracle.
use super::*;

pub(crate) fn len(index: usize) -> Option<usize> {
    if index < P_OWN_IN {
        crate::poseidon2_air::periodic_source::len(index)
    } else {
        (index < N_PERIODIC).then_some(HEIGHT)
    }
}

pub(crate) fn fill(index: usize, output: &mut [Val]) -> bool {
    if len(index) != Some(output.len()) {
        return false;
    }
    if index < P_OWN_IN {
        return crate::poseidon2_air::periodic_source::fill(index, output);
    }
    output.fill(Val::ZERO);
    let mut set = |column: usize, row: usize, value: Val| {
        if column == index {
            output[row] = value;
        }
    };
    for i in 0..N_IN {
        set(P_OWN_IN, own_in_row(i), Val::ONE);
        set(P_RECIP_LINK, own_out_row(i), Val::ONE);
        set(P_COMMIT_A_IN, commit_a_in_row(i), Val::ONE);
        set(P_CHAIN_LINK, commit_a_out_row(i), Val::ONE);
        set(P_COMMIT_B, commit_b_in_row(i), Val::ONE);
        for d in 0..DEPTH {
            let row = (input_base(i) + 2 + d) * BLOCK + BLOCK - 1;
            set(P_MEM_LINK, row, Val::ONE);
            set(P_POS_COEFF, row, Val::from_u64(1u64 << d));
        }
        set(P_ROOT, root_row(i), Val::ONE);
        set(P_NULL_IN, null_in_row(i), Val::ONE);
        set(P_REGION_LAST, null_out_row(i), Val::ONE);
        set(P_NULLOUT + i, null_out_row(i), Val::ONE);
        range(&mut set, commit_a_in_row(i));
    }
    for j in 0..M_OUT {
        set(P_CHAIN_LINK, out_a_out_row(j), Val::ONE);
        set(P_COMMIT_B, out_b_in_row(j), Val::ONE);
        set(P_OUT_A_IN, out_in_row(j), Val::ONE);
        set(
            P_REGION_LAST,
            out_in_row(j) + OUT_BLOCKS * BLOCK - 1,
            Val::ONE,
        );
        set(P_OUTOUT + j, out_out_row(j), Val::ONE);
        range(&mut set, out_in_row(j));
    }
    set(P_FEE_IN, fee_in_row(), Val::ONE);
    set(P_MINT_IN, mint_in_row(), Val::ONE);
    set(
        P_REGION_LAST,
        fee_in_row() + FEE_BLOCKS * BLOCK - 1,
        Val::ONE,
    );
    set(
        P_REGION_LAST,
        mint_in_row() + MINT_BLOCKS * BLOCK - 1,
        Val::ONE,
    );
    range(&mut set, fee_in_row());
    range(&mut set, mint_in_row());
    set(P_ROW0, 0, Val::ONE);
    set(P_FINAL, mint_in_row() + MINT_BLOCKS * BLOCK - 1, Val::ONE);
    true
}

fn range(set: &mut impl FnMut(usize, usize, Val), start: usize) {
    set(P_RANGE_SEED, start, Val::ONE);
    for row in start..start + BITS {
        set(P_RANGE_ACTIVE, row, Val::ONE);
    }
    set(P_RANGE_CLOSE, start + BITS, Val::ONE);
}
