//! Integer-only evaluator geometry, shared by admission and runtime planning.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgramShape {
    pub extension: Extension,
    pub instruction_words: usize,
    pub registers: usize,
    pub constraints: usize,
    pub row_words: usize,
    pub parameter_words: usize,
}

impl ProgramShape {
    pub(crate) fn for_recording(
        recorded: &crate::block_v2::machine::symbolic::RecordedUni,
        extension: Extension,
    ) -> Result<Self, String> {
        let nodes = recorded.node_bound();
        let constraints = recorded.constraints();
        if nodes == 0 || nodes > MAX_NODES || constraints == 0 || constraints > MAX_CONSTRAINTS {
            return Err("recorded quotient program exceeds evaluator bounds".into());
        }
        let mut layout = recorded.layout();
        layout.preprocessed_width = layout.num_periodic_columns;
        layout.num_periodic_columns = 0;
        let (row_words, parameter_words) = Program::input_shape_extension(layout, extension)?;
        // Normalization either retains one operation, replaces it with a leaf
        // or negation, or selects a child. It never expands a recorded node into
        // multiple instructions. Structural interning only removes duplicates.
        // Thus nodes bounds instructions (apart from one fold per constraint)
        // and simultaneously live registers, regardless of folded field values.
        // This is intentionally not the raw expression's degree_multiple.
        Ok(Self {
            extension,
            instruction_words: (nodes + constraints) * WORDS_PER_INSTRUCTION,
            registers: nodes,
            constraints,
            row_words,
            parameter_words,
        })
    }

    pub(crate) fn check(&self, program: &Program) -> Result<(), String> {
        let actual = program.shape();
        if actual.extension != self.extension
            || actual.constraints != self.constraints
            || actual.row_words != self.row_words
            || actual.parameter_words != self.parameter_words
            || actual.registers > self.registers
            || actual.instruction_words > self.instruction_words
        {
            return Err("compiled quotient exceeds recorded admission geometry".into());
        }
        Ok(())
    }
}
