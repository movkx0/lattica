//! Allocation-free canonical program encoding. Borrow rows and hints; only
//! fixed-size operation address arrays are copied onto the stack.
use super::*;

type Sink<'a> = dyn FnMut(u64) -> Result<(), String> + 'a;

fn words(values: impl IntoIterator<Item = u64>, emit: &mut Sink<'_>) -> Result<(), String> {
    for value in values {
        emit(value)?;
    }
    Ok(())
}

fn wires(values: &[Wire], emit: &mut Sink<'_>) -> Result<(), String> {
    emit(values.len() as u64)?;
    words(values.iter().map(|w| w.0 as u64), emit)
}

fn operation(op: &Op, emit: &mut Sink<'_>) -> Result<(), String> {
    emit(op.code() as u64)?;
    match op {
        Op::Input { index, .. } => words([0, *index as u64], emit)?,
        Op::Bit { source, bit, .. } => words([1, source.0 as u64, *bit as u64], emit)?,
        Op::SelectHint { entries, bits, .. } => {
            emit(2)?;
            wires(entries, emit)?;
            wires(bits, emit)?;
        }
        Op::Constant { value, .. } => emit(value.as_canonical_u64())?,
        _ => (),
    }
    match op {
        Op::Input { .. } | Op::Bit { .. } | Op::SelectHint { .. } | Op::Constant { .. } => emit(0)?,
        Op::Add { a, b, .. } | Op::Mul { a, b, .. } | Op::Equal { a, b } => wires(&[*a, *b], emit)?,
        Op::Boolean { a } | Op::Inverse { a, .. } => wires(&[*a], emit)?,
        Op::Select { bit, a, b, .. } => wires(&[*a, *b, *bit], emit)?,
        Op::CubicMul { a, b, .. } => {
            emit(6)?;
            words(a.iter().chain(b).map(|w| w.0 as u64), emit)?;
        }
        Op::CubicInverse { a, .. } => wires(a, emit)?,
        Op::Poseidon { input, .. } => {
            emit(input.len() as u64)?;
            words(input.iter().copied().map(u64::from), emit)?;
        }
    }
    match op {
        Op::Input { out, .. }
        | Op::Bit { out, .. }
        | Op::SelectHint { out, .. }
        | Op::Constant { out, .. }
        | Op::Add { out, .. }
        | Op::Mul { out, .. }
        | Op::Inverse { out, .. }
        | Op::Select { out, .. } => wires(&[*out], emit),
        Op::CubicMul { out, .. } | Op::CubicInverse { out, .. } => wires(out, emit),
        Op::Equal { .. } | Op::Boolean { .. } => emit(0),
        Op::Poseidon { output, .. } => {
            emit(output.len() as u64)?;
            words(output.iter().copied().map(u64::from), emit)
        }
    }
}

impl Program {
    pub(crate) fn emit_manifest(&self, emit: &mut Sink<'_>) -> Result<(), String> {
        words(
            [
                if cfg!(feature = "block-v2-wide-lanes") {
                    6
                } else {
                    3
                },
                self.publics as u64,
                self.witnesses as u64,
                self.height as u64,
                self.references.len() as u64,
                self.rows.len() as u64,
            ],
            emit,
        )?;
        #[cfg(feature = "block-v2-wide-lanes")]
        words(
            [
                LANES as u64,
                EXT_LANES as u64,
                PUBLICS_PER_ROW as u64,
                crate::block_v2::profile::NODE_CODEC_REVISION,
            ],
            emit,
        )?;
        for row in &self.rows {
            match row {
                Row::Public(bank) => words([3, *bank as u64, 0], emit)?,
                Row::Alu(ops) | Row::Cubic(ops) => {
                    words(
                        [
                            if matches!(row, Row::Alu(_)) { 0 } else { 2 },
                            ops.len() as u64,
                        ],
                        emit,
                    )?;
                    for index in ops {
                        operation(
                            self.operation(*index)
                                .map_err(|_| "invalid row operation index")?,
                            emit,
                        )?;
                    }
                }
                Row::Poseidon(index) => {
                    words([1, 1], emit)?;
                    let op = self
                        .operation(*index)
                        .map_err(|_| "invalid row operation index")?;
                    if !matches!(op, Op::Poseidon { .. }) {
                        return Err("invalid hash row operation".into());
                    }
                    operation(op, emit)?;
                }
            }
        }
        words(self.references.iter().map(|&r| u64::from(r)), emit)
    }
}

#[cfg(test)]
mod tests;
