//! Validate the entire interpreter envelope before native device indexing.
use super::*;

impl Program {
    pub(crate) fn validate_quotient(&self) -> Result<(), String> {
        if !matches!(self.extension, Extension::Quadratic | Extension::Cubic)
            || self.registers == 0
            || self.registers > MAX_NODES
            || self.constraints == 0
            || self.constraints > MAX_CONSTRAINTS
            || self.instructions.is_empty()
            || self.instructions.len() % WORDS_PER_INSTRUCTION != 0
            || self.instructions.capacity() > (MAX_NODES + MAX_CONSTRAINTS) * WORDS_PER_INSTRUCTION
            || (self.row_words, self.parameter_words)
                != Self::input_shape_extension(self.layout, self.extension)?
        {
            return Err("invalid bounded quotient program geometry".into());
        }
        let mut initialized = vec![false; self.registers];
        let mut folds = 0;
        let degree = self.extension.degree() as u64;
        for instruction in self.instructions.chunks_exact(WORDS_PER_INSTRUCTION) {
            let [op, dst, a, b, _] = <[u64; 5]>::try_from(instruction).unwrap();
            if op > FOLD_EXT || (op < FOLD_BASE && dst >= self.registers as u64) {
                return Err("invalid quotient opcode or destination".into());
            }
            if op >= ADD_BASE && (a >= self.registers as u64 || !initialized[a as usize]) {
                return Err("quotient reads an uninitialized or out-of-bounds register".into());
            }
            if matches!(
                op,
                ADD_BASE | SUB_BASE | MUL_BASE | ADD_EXT | SUB_EXT | MUL_EXT
            ) && (b >= self.registers as u64 || !initialized[b as usize])
            {
                return Err(
                    "quotient reads an uninitialized or out-of-bounds second operand".into(),
                );
            }
            if matches!(op, ROW_BASE | ROW_EXT | PARAM_BASE | PARAM_EXT) {
                let words = if matches!(op, ROW_BASE | PARAM_BASE) {
                    1
                } else {
                    degree
                };
                let limit = if op <= ROW_EXT {
                    self.row_words
                } else {
                    self.parameter_words
                };
                if a.checked_add(words).is_none_or(|end| end > limit as u64) {
                    return Err("quotient row or parameter load exceeds its bounds".into());
                }
            }
            if op >= FOLD_BASE {
                if b != folds as u64 || folds >= self.constraints {
                    return Err("quotient folds differ from global constraint order".into());
                }
                folds += 1;
            } else {
                initialized[dst as usize] = true;
            }
        }
        if folds != self.constraints {
            return Err("quotient program omits constraints".into());
        }
        Ok(())
    }
}
