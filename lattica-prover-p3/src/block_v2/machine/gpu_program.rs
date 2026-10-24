//! Bounded, immutable execution metadata for GPU recursive witness construction.
//! Compilation performs only address/layout/dependency work. Hints have real
//! execution dependencies even though they deliberately have no AIR bus reads.
use super::{air, program::*};
use p3_field::PrimeField64;

mod schedule;
pub(crate) use schedule::WitnessSchedule;

pub(crate) const HEADER_WORDS: usize = 24;
pub(crate) const INSTRUCTION_WORDS: usize = 18;
pub(super) const ROW_WORDS: usize = 4;
pub(super) const PORT_WORDS: usize = 7;

pub(crate) struct WitnessProgram {
    pub(crate) words: Vec<u64>,
    pub(crate) waves: Vec<std::ops::Range<usize>>,
    pub(crate) wires: usize,
    pub(crate) publics: usize,
    pub(crate) witnesses: usize,
    pub(crate) height: usize,
    pub(crate) host_peak_bytes: usize,
    pub(crate) schedule_host_bytes: usize,
}

fn add(a: usize, b: usize) -> Result<usize, ExecutionError> {
    a.checked_add(b).ok_or(ExecutionError::TooLarge)
}
fn mul(a: usize, b: usize) -> Result<usize, ExecutionError> {
    a.checked_mul(b).ok_or(ExecutionError::TooLarge)
}

/// Allocation layout shared by admission and metadata emission. Padding
/// changes trace height, but adds no row or port records to the metadata.
pub(super) struct Layout {
    instruction_offset: usize,
    hint_offset: usize,
    row_offset: usize,
    port_offset: usize,
    public_offset: usize,
    pub(super) words: usize,
    pub(super) host_peak_bytes: usize,
    pub(super) schedule_host_bytes: usize,
}

impl Layout {
    pub(super) fn new(program: &Program) -> Result<Self, ExecutionError> {
        let wires = program.references.len();
        let operations = program.operations.len();
        if wires > MAX_WIRES
            || program.publics > MAX_PUBLIC_VALUES
            || program.publics > wires
            || operations > u32::MAX as usize
            || program.witnesses > u32::MAX as usize
            || !program.height.is_power_of_two()
            || !(8..=1 << 24).contains(&program.height)
            || program.rows.len() > program.height
        {
            return Err(ExecutionError::TooLarge);
        }
        let mut hint_words = 0;
        for op in &program.operations {
            if let Op::SelectHint { entries, bits, .. } = op {
                if bits.len() > 24 || entries.len() != 1 << bits.len() {
                    return Err(ExecutionError::InvalidWire);
                }
                hint_words = add(hint_words, add(entries.len(), bits.len())?)?;
            }
        }
        let mut ports = 0;
        for row in &program.rows {
            if let Row::Alu(indices) | Row::Cubic(indices) = row {
                for index in indices {
                    let op = program.operation(*index)?;
                    let valid = match row {
                        Row::Alu(_) => op.code() <= 7,
                        Row::Cubic(_) => {
                            matches!(op, Op::CubicMul { .. } | Op::CubicInverse { .. })
                        }
                        _ => unreachable!(),
                    };
                    if !valid {
                        return Err(ExecutionError::InvalidWire);
                    }
                }
            }
            ports = add(
                ports,
                match row {
                    Row::Public(bank) if *bank < program.publics.div_ceil(PUBLICS_PER_ROW) => 0,
                    Row::Alu(ops) if ops.len() <= LANES => ops.len(),
                    Row::Cubic(ops) if ops.len() <= EXT_LANES => ops.len() * 3,
                    Row::Poseidon(index)
                        if matches!(program.operation(*index)?, Op::Poseidon { .. }) =>
                    {
                        8
                    }
                    _ => return Err(ExecutionError::InvalidWire),
                },
            )?;
        }
        let instruction_offset = HEADER_WORDS;
        let hint_offset = add(instruction_offset, mul(operations, INSTRUCTION_WORDS)?)?;
        let row_offset = add(hint_offset, hint_words)?;
        let port_offset = add(row_offset, mul(program.rows.len(), ROW_WORDS)?)?;
        let public_offset = add(port_offset, mul(ports, PORT_WORDS)?)?;
        let words = add(public_offset, program.publics)?;
        // Readiness, level, stable index order and retained wave ranges; the
        // source Program is caller-owned and has its separate enclosing budget.
        let host_peak_bytes = add(mul(add(words, add(wires, mul(operations, 4)?)?)?, 8)?, 1024)?;
        // At most one dependency wave per operation. Only the compact wave
        // array and scalar schedule survive metadata upload, not ready/level/
        // order scratch or the operation-capacity compiler wave vector.
        let schedule_host_bytes = WitnessSchedule::storage_bound(operations)?;
        Ok(Self {
            instruction_offset,
            hint_offset,
            row_offset,
            port_offset,
            public_offset,
            words,
            host_peak_bytes,
            schedule_host_bytes,
        })
    }
}

impl WitnessProgram {
    pub(crate) fn compile(
        program: &Program,
        host_allowance: usize,
    ) -> Result<Self, ExecutionError> {
        let wires = program.references.len();
        let operations = program.operations.len();
        let Layout {
            instruction_offset,
            hint_offset,
            row_offset,
            port_offset,
            public_offset,
            words,
            host_peak_bytes,
            schedule_host_bytes,
        } = Layout::new(program)?;
        if host_peak_bytes > host_allowance {
            return Err(ExecutionError::TooLarge);
        }
        let mut ready = vec![usize::MAX; wires];
        ready[..program.publics].fill(0);
        let mut levels = Vec::with_capacity(operations);
        for op in &program.operations {
            let mut level = 0;
            let mut read = |w: Wire| -> Result<(), ExecutionError> {
                let time = *ready.get(w.0).ok_or(ExecutionError::InvalidWire)?;
                if time == usize::MAX {
                    return Err(ExecutionError::InvalidWire);
                }
                level = level.max(time);
                Ok(())
            };
            match op {
                Op::Bit { source, bit, .. } => {
                    if *bit >= 64 {
                        return Err(ExecutionError::InvalidWire);
                    }
                    read(*source)?;
                }
                Op::SelectHint { entries, bits, .. } => {
                    for &w in entries.iter().chain(bits) {
                        read(w)?;
                    }
                }
                Op::Input { index, .. } if *index >= program.witnesses => {
                    return Err(ExecutionError::WitnessCount);
                }
                _ => {
                    for w in op.reads() {
                        read(w)?;
                    }
                }
            }
            for w in op.writes() {
                let slot = ready.get_mut(w.0).ok_or(ExecutionError::InvalidWire)?;
                if *slot != usize::MAX {
                    return Err(ExecutionError::InvalidWire);
                }
                *slot = level + 1;
            }
            levels.push(level);
        }
        if ready.contains(&usize::MAX) {
            return Err(ExecutionError::InvalidWire);
        }
        let mut order: Vec<_> = (0..operations).collect();
        order.sort_unstable_by_key(|&i| (levels[i], i));
        let mut waves = Vec::with_capacity(operations);
        for (i, &index) in order.iter().enumerate() {
            if i == 0 || levels[index] != levels[order[i - 1]] {
                waves.push(i..i + 1);
            } else {
                waves.last_mut().unwrap().end = i + 1;
            }
        }
        let mut data = vec![0u64; words];
        let header = [
            program.height,
            program.rows.len(),
            air::WIDTH,
            air::PREPROCESSED_WIDTH,
            LANES,
            air::ADDR_A,
            air::ADDR_B,
            air::ADDR_C,
            air::ADDR_D,
            air::MULT_C,
            air::IS_HASH,
            air::EXT_MUL,
            air::EXT_INV,
            air::PUBLIC_BANK,
            program.publics,
            wires,
            instruction_offset,
            hint_offset,
            row_offset,
            port_offset,
            public_offset,
            program.witnesses,
        ];
        for (dst, value) in data.iter_mut().zip(header) {
            *dst = value as u64;
        }
        let mut hint_at = hint_offset;
        for (i, &index) in order.iter().enumerate() {
            let instruction = encode(&program.operations[index], &mut data, &mut hint_at);
            data[instruction_offset + i * INSTRUCTION_WORDS
                ..instruction_offset + (i + 1) * INSTRUCTION_WORDS]
                .copy_from_slice(&instruction);
        }
        // Word 17 is reserved by every instruction encoding. Store each wave's
        // length at its first instruction so OpenCL can execute several narrow
        // dependency levels without another allocation or host upload.
        #[cfg(feature = "gpu")]
        for wave in &waves {
            let marker = instruction_offset + wave.start * INSTRUCTION_WORDS + 17;
            debug_assert_eq!(data[marker], 0);
            data[marker] = wave.len() as u64;
        }
        assert_eq!(hint_at, row_offset);
        data[public_offset..].copy_from_slice(
            &program.references[..program.publics]
                .iter()
                .map(|&n| u64::from(n))
                .collect::<Vec<_>>(),
        );
        let mut port_at = port_offset;
        for (r, row) in program.rows.iter().enumerate() {
            let first = (port_at - port_offset) / PORT_WORDS;
            let (kind, count, bank) = match row {
                Row::Public(bank) => (4, 0, *bank),
                Row::Alu(ops) => {
                    for index in ops {
                        let op = program.operation(*index)?;
                        if op.code() > 7 {
                            return Err(ExecutionError::InvalidWire);
                        }
                        let reads = op.reads();
                        let writes = op.writes();
                        let constant = if let Op::Constant { value, .. } = op {
                            value.as_canonical_u64()
                        } else {
                            0
                        };
                        port(
                            &mut data,
                            &mut port_at,
                            program,
                            op.code(),
                            [
                                reads.first().copied(),
                                reads.get(1).copied(),
                                writes.first().copied(),
                                reads.get(2).copied(),
                            ],
                            constant,
                        )?;
                    }
                    (1, ops.len(), 0)
                }
                Row::Cubic(ops) => {
                    for index in ops {
                        let op = program.operation(*index)?;
                        let (a, b, out) = match op {
                            Op::CubicMul { a, b, out } => (a, Some(b), out),
                            Op::CubicInverse { a, out } => (a, None, out),
                            _ => return Err(ExecutionError::InvalidWire),
                        };
                        for i in 0..3 {
                            port(
                                &mut data,
                                &mut port_at,
                                program,
                                op.code(),
                                [Some(a[i]), b.map(|b| b[i]), Some(out[i]), None],
                                0,
                            )?;
                        }
                    }
                    (2, ops.len() * 3, 0)
                }
                Row::Poseidon(index) => {
                    let Op::Poseidon { input, output } = program.operation(*index)? else {
                        return Err(ExecutionError::InvalidWire);
                    };
                    for i in 0..8 {
                        port(
                            &mut data,
                            &mut port_at,
                            program,
                            0,
                            [
                                Some(Wire(input[i] as usize)),
                                None,
                                Some(Wire(output[i] as usize)),
                                None,
                            ],
                            0,
                        )?;
                    }
                    (3, 8, 0)
                }
            };
            data[row_offset + r * ROW_WORDS..row_offset + (r + 1) * ROW_WORDS].copy_from_slice(&[
                kind,
                first as u64,
                count as u64,
                bank as u64,
            ]);
        }
        assert_eq!(port_at, public_offset);
        Ok(Self {
            words: data,
            waves,
            wires,
            publics: program.publics,
            witnesses: program.witnesses,
            height: program.height,
            host_peak_bytes,
            schedule_host_bytes,
        })
    }
    pub(crate) fn trace_width(&self) -> usize {
        air::WIDTH
    }
    pub(crate) fn preprocessing_width(&self) -> usize {
        air::PREPROCESSED_WIDTH
    }
}

fn port(
    data: &mut [u64],
    at: &mut usize,
    program: &Program,
    opcode: usize,
    wires: [Option<Wire>; 4],
    constant: u64,
) -> Result<(), ExecutionError> {
    let mut output = [0; PORT_WORDS];
    output[0] = opcode as u64;
    for (i, wire) in wires.into_iter().enumerate() {
        if let Some(w) = wire {
            if w.0 >= program.references.len() {
                return Err(ExecutionError::InvalidWire);
            }
            output[i + 1] = w.0 as u64 + 1;
            if i == 2 {
                output[5] = u64::from(program.references[w.0]);
            }
        }
    }
    output[6] = constant;
    data[*at..*at + PORT_WORDS].copy_from_slice(&output);
    *at += PORT_WORDS;
    Ok(())
}

fn encode(op: &Op, words: &mut [u64], hint_at: &mut usize) -> [u64; INSTRUCTION_WORDS] {
    let mut c = [0u64; INSTRUCTION_WORDS];
    c[0] = op.code() as u64;
    match op {
        Op::Input { index, out } => {
            c[1] = out.0 as u64;
            c[2] = *index as u64;
        }
        Op::Constant { value, out } => {
            c[1] = out.0 as u64;
            c[2] = value.as_canonical_u64();
        }
        Op::Add { a, b, out } | Op::Mul { a, b, out } => {
            c[1..4].copy_from_slice(&[out.0 as u64, a.0 as u64, b.0 as u64]);
        }
        Op::Equal { a, b } => {
            c[1] = a.0 as u64;
            c[2] = b.0 as u64;
        }
        Op::Boolean { a } => {
            c[1] = a.0 as u64;
        }
        Op::Inverse { a, out } => {
            c[1] = out.0 as u64;
            c[2] = a.0 as u64;
        }
        Op::Select { bit, a, b, out } => {
            c[1..5].copy_from_slice(&[out.0 as u64, bit.0 as u64, a.0 as u64, b.0 as u64]);
        }
        Op::Bit { source, bit, out } => {
            c[0] = 11;
            c[1] = out.0 as u64;
            c[2] = source.0 as u64;
            c[3] = *bit as u64;
        }
        Op::SelectHint { entries, bits, out } => {
            c[0] = 12;
            c[1] = out.0 as u64;
            c[2] = *hint_at as u64;
            c[3] = bits.len() as u64;
            for w in bits.iter().chain(entries) {
                words[*hint_at] = w.0 as u64;
                *hint_at += 1;
            }
        }
        Op::CubicMul { a, b, out } => {
            for (dst, w) in c[1..].iter_mut().zip(out.iter().chain(a).chain(b)) {
                *dst = w.0 as u64;
            }
        }
        Op::CubicInverse { a, out } => {
            for (dst, w) in c[1..].iter_mut().zip(out.iter().chain(a)) {
                *dst = w.0 as u64;
            }
        }
        Op::Poseidon { input, output } => {
            for (dst, w) in c[1..].iter_mut().zip(input.iter().chain(output)) {
                *dst = u64::from(*w);
            }
        }
    }
    c
}

#[cfg(test)]
mod tests;
