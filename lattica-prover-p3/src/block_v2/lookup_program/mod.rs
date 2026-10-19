//! Bounded base-expression programs for the pinned LogUp witness generator.

use super::quotient_program::{Compiler, MAX_NODES, MAX_ROW_WORDS, WORDS_PER_INSTRUCTION};
use crate::config::Val;
use p3_air::symbolic::AirLayout;
use p3_lookup::Lookup;

pub(crate) const MAX_LOOKUPS: usize = 256;
pub(crate) const MAX_TUPLES: usize = 4096;

#[derive(Debug)]
pub(crate) struct LookupProgram {
    pub instructions: Vec<u64>,
    pub registers: usize,
    pub layout: AirLayout,
    pub row_words: usize,
    pub expression_words: usize,
    /// Three words per tuple: lookup index, multiplicity offset, tuple length.
    pub tuples: Vec<u64>,
    /// Prefix boundaries in the tuple array, one more than the lookup count.
    pub boundaries: Vec<u64>,
}

impl LookupProgram {
    pub(crate) fn compile(layout: AirLayout, lookups: &[Lookup<Val>]) -> Result<Self, String> {
        if lookups.is_empty()
            || lookups.len() > MAX_LOOKUPS
            || layout.num_periodic_columns != 0
            || layout.permutation_width != 0
            || layout.num_permutation_values != 0
            || layout.num_permutation_challenges != 0
        {
            return Err("unsupported GPU lookup witness layout".into());
        }
        let row_words = layout
            .main_width
            .checked_add(layout.preprocessed_width)
            .and_then(|n| n.checked_mul(2))
            .ok_or("lookup row width overflow")?;
        if row_words == 0 || row_words > MAX_ROW_WORDS || layout.num_public_values > MAX_ROW_WORDS {
            return Err("lookup inputs exceed bounded evaluator".into());
        }
        let mut compiler = Compiler::new(layout);
        let mut expression_words = 0usize;
        let mut tuples = Vec::new();
        let mut boundaries = vec![0];
        for (index, lookup) in lookups.iter().enumerate() {
            if lookup.column != index || lookup.elements.len() != lookup.multiplicities.len() {
                return Err(
                    "GPU lookup slots and multiplicities must match the reference layout".into(),
                );
            }
            for (elements, multiplicity) in lookup.elements.iter().zip(&lookup.multiplicities) {
                if tuples.len() / 3 == MAX_TUPLES
                    || elements.len() >= MAX_ROW_WORDS
                    || expression_words
                        .checked_add(elements.len() + 1)
                        .is_none_or(|n| n > MAX_ROW_WORDS)
                {
                    return Err("GPU lookup tuple expressions exceed their bound".into());
                }
                tuples.extend_from_slice(&[
                    index as u64,
                    expression_words as u64,
                    elements.len() as u64,
                ]);
                compiler.store_base(multiplicity, expression_words)?;
                expression_words += 1;
                for element in elements {
                    compiler.store_base(element, expression_words)?;
                    expression_words += 1;
                }
            }
            boundaries.push((tuples.len() / 3) as u64);
        }
        let (instructions, registers) = if expression_words == 0 {
            (Vec::new(), 0)
        } else {
            compiler.lower()?
        };
        if instructions.len() > (MAX_NODES + MAX_ROW_WORDS) * WORDS_PER_INSTRUCTION {
            return Err("GPU lookup instruction stream exceeds its bound".into());
        }
        Ok(Self {
            instructions,
            registers,
            layout,
            row_words,
            expression_words,
            tuples,
            boundaries,
        })
    }

    pub(crate) fn lookup_count(&self) -> usize {
        self.boundaries.len() - 1
    }
    pub(crate) fn tuple_count(&self) -> usize {
        self.tuples.len() / 3
    }
}

pub(crate) mod kernels;
pub(crate) mod plan;
