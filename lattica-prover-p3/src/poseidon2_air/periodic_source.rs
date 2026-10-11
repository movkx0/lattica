//! Allocation-free round-schedule columns for the admitted v2 compiler.
use super::*;

pub(crate) fn len(index: usize) -> Option<usize> {
    (index < N_PERIODIC).then_some(BLOCK)
}

pub(crate) fn fill(index: usize, output: &mut [Val]) -> bool {
    if len(index) != Some(output.len()) {
        return false;
    }
    output.fill(Val::ZERO);
    let mut set = |column: usize, row: usize, value: Val| {
        if column == index {
            output[row] = value;
        }
    };
    set(0, 0, Val::ONE);
    for r in 0..FULL_HALF {
        let row = 1 + r;
        set(1, row, Val::ONE);
        for i in 0..W {
            set(3 + i, row, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL[r][i]);
        }
    }
    for r in 0..PARTIAL {
        let row = 1 + FULL_HALF + r;
        set(2, row, Val::ONE);
        set(3, row, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[r]);
    }
    for r in 0..FULL_HALF {
        let row = 1 + FULL_HALF + PARTIAL + r;
        set(1, row, Val::ONE);
        for i in 0..W {
            set(3 + i, row, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL[r][i]);
        }
    }
    true
}
