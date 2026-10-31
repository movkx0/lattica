//! Resumable canonical encoding without a flattened manifest or replay per chunk.
use super::*;

#[derive(Clone)]
pub(crate) struct ManifestCursor<'a> {
    program: &'a Program,
    words: [u64; 32],
    used: usize,
    next: usize,
    row: usize,
    operation: usize,
    row_header: bool,
    reference: usize,
    hint: Option<(&'a [Wire], &'a [Wire], Wire, usize)>,
    failed: bool,
}

impl<'a> ManifestCursor<'a> {
    pub(crate) fn new(program: &'a Program) -> Self {
        let mut this = Self {
            program, words: [0; 32], used: 6, next: 0, row: 0,
            operation: 0, row_header: false, reference: 0, hint: None, failed: false,
        };
        this.words[..6].copy_from_slice(&[
            if cfg!(feature = "block-v2-wide-lanes") { 6 } else { 3 },
            program.publics as u64, program.witnesses as u64, program.height as u64,
            program.references.len() as u64, program.rows.len() as u64,
        ]);
        #[cfg(feature = "block-v2-wide-lanes")]
        {
            this.words[6..10].copy_from_slice(&[
                LANES as u64, EXT_LANES as u64, PUBLICS_PER_ROW as u64,
                crate::block_v2::profile::NODE_CODEC_REVISION,
            ]);
            this.used = 10;
        }
        this
    }

    fn fail(&mut self, message: &str) -> Option<Result<u64, String>> {
        self.failed = true;
        Some(Err(message.into()))
    }

    fn advance_row(&mut self) {
        self.row += 1;
        self.operation = 0;
        self.row_header = false;
    }
}

impl Iterator for ManifestCursor<'_> {
    type Item = Result<u64, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed { return None; }
        loop {
            if self.next < self.used {
                let word = self.words[self.next];
                self.next += 1;
                return Some(Ok(word));
            }
            if let Some((entries, bits, out, position)) = self.hint.as_mut() {
                let n = entries.len();
                let b = bits.len();
                let word = match *position {
                    0 => 0, 1 => 2, 2 => n as u64,
                    p if p < 3 + n => entries[p - 3].0 as u64,
                    p if p == 3 + n => b as u64,
                    p if p < 4 + n + b => bits[p - 4 - n].0 as u64,
                    p if p == 4 + n + b => 0,
                    p if p == 5 + n + b => 1,
                    _ => out.0 as u64,
                };
                *position += 1;
                if *position == 7 + n + b { self.hint = None; }
                return Some(Ok(word));
            }
            self.used = 0;
            self.next = 0;
            let Some(row) = self.program.rows.get(self.row) else {
                let word = self.program.references.get(self.reference)?;
                self.reference += 1;
                return Some(Ok(u64::from(*word)));
            };
            if !self.row_header {
                let (tag, count) = match row {
                    Row::Public(bank) => {
                        self.words[..3].copy_from_slice(&[3, *bank as u64, 0]);
                        self.used = 3;
                        self.advance_row();
                        continue;
                    }
                    Row::Alu(ops) => (0, ops.len()),
                    Row::Cubic(ops) => (2, ops.len()),
                    Row::Poseidon(_) => (1, 1),
                };
                self.words[..2].copy_from_slice(&[tag, count as u64]);
                self.used = 2;
                self.row_header = true;
                continue;
            }
            let index = match row {
                Row::Alu(ops) | Row::Cubic(ops) => ops.get(self.operation).copied(),
                Row::Poseidon(index) => (self.operation == 0).then_some(*index),
                Row::Public(_) => unreachable!(),
            };
            let Some(index) = index else { self.advance_row(); continue; };
            let Ok(op) = self.program.operation(index) else {
                return self.fail("invalid row operation index");
            };
            if matches!(row, Row::Poseidon(_)) && !matches!(op, Op::Poseidon { .. }) {
                return self.fail("invalid hash row operation");
            }
            self.operation += 1;
            if let Op::SelectHint { entries, bits, out } = op {
                self.hint = Some((entries, bits, *out, 0));
            } else if let Err(message) = operation(op, &mut |word| {
                let slot = self.words.get_mut(self.used).ok_or("manifest cursor operation bound")?;
                *slot = word;
                self.used += 1;
                Ok(())
            }) {
                return self.fail(&message);
            }
        }
    }
}

impl std::iter::FusedIterator for ManifestCursor<'_> {}
