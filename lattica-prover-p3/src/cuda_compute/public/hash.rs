use super::*;
use crate::{
    block_v2::{commitment, machine::programs},
    cuda_compute::Argument,
};

type FieldSink<'a> = dyn FnMut(u64) -> Result<()> + 'a;

fn stream_length(
    domain: u64,
    produce: &mut impl FnMut(&mut FieldSink<'_>) -> Result<()>,
) -> Result<usize> {
    if domain >= MODULUS {
        return Err("CUDA public hash requires a canonical domain".into());
    }
    let mut length = 0usize;
    let mut failed = false;
    produce(&mut |field| {
        let next = length.checked_add(1);
        if failed || field >= MODULUS || next.is_none_or(|n| n as u128 >= MODULUS as u128) {
            failed = true;
            return Err("CUDA public hash requires canonical fields and length".into());
        }
        length = next.unwrap();
        Ok(())
    })?;
    if failed {
        return Err("CUDA public hash rejected stream".into());
    }
    Ok(length)
}

fn batches(
    expected: usize,
    produce: &mut impl FnMut(&mut FieldSink<'_>) -> Result<()>,
    mut consume: impl FnMut(&[u64], bool) -> Result<()>,
) -> Result<()> {
    let mut scratch = [0; BATCH_WORDS];
    let (mut received, mut used, mut first, mut failed) = (0usize, 0usize, true, false);
    produce(&mut |field| {
        if failed || received == expected || field >= MODULUS {
            failed = true;
            return Err("CUDA public hash stream length or field changed".into());
        }
        scratch[used] = field;
        used += 1;
        received += 1;
        if used == BATCH_WORDS {
            // A producer cannot hide a rejected upload or failed completion by
            // discarding the callback error and then returning success.
            failed = true;
            consume(&scratch, first)?;
            failed = false;
            first = false;
            used = 0;
        }
        Ok(())
    })?;
    if failed || received != expected {
        return Err("CUDA public hash stream length or field changed".into());
    }
    if used != 0 || first {
        consume(&scratch[..used], first)?;
    }
    Ok(())
}

impl PublicArithmetic {
    pub(crate) fn hash_public_fields_reported(
        &self,
        domain: u64,
        fields: &[u64],
        run: &Run,
        stage: Stage,
    ) -> Result<[u64; 4]> {
        self.hash_public_stream_reported(
            domain,
            |sink| {
                for &field in fields {
                    sink(field)?;
                }
                Ok(())
            },
            run,
            stage,
        )
    }

    /// The producer must replay the same immutable public fields on both calls.
    /// Canonical values and length are checked before allocation and on replay;
    /// a fixed staging array prevents growth with the source program's size.
    pub(crate) fn hash_public_stream_reported(
        &self,
        domain: u64,
        mut produce: impl FnMut(&mut FieldSink<'_>) -> Result<()>,
        run: &Run,
        stage: Stage,
    ) -> Result<[u64; 4]> {
        self.check(run, stage)?;
        let length = stream_length(domain, &mut produce)?;
        self.admit(&[BATCH_WORDS, 4])?;
        let input = self.runtime.allocate(BATCH_WORDS)?;
        let state = self.runtime.allocate(4)?;
        let kernel = &self.hash[usize::from(stage == Stage::Preprocessing)];
        batches(length, &mut produce, |words, first| {
            if !words.is_empty() {
                input.write(0, words)?;
            }
            // One thread owns the four-word state. Every nonfinal batch is a
            // multiple of the rate; only the final chunk receives zero padding.
            self.record(run, stage, unsafe {
                kernel.launch(
                    SINGLE,
                    &[
                        Argument::Buffer(&state),
                        Argument::Buffer(&input),
                        Argument::U64(domain),
                        Argument::U64(length as u64),
                        Argument::U32(u32::from(first)),
                        Argument::U32(words.len() as u32),
                        Argument::Buffer(&self.poseidon),
                    ],
                )
            })
        })?;
        let mut result = [0; 4];
        state.read(0, &mut result)?;
        if result.iter().any(|&v| v >= MODULUS) {
            return Err("CUDA public hash returned a noncanonical digest".into());
        }
        Ok(result)
    }

    pub(crate) fn validate_public_summary_reported(
        &self,
        words: &[u64; programs::PUBLIC_VALUES],
        modes: u64,
        run: &Run,
        stage: Stage,
    ) -> Result<()> {
        self.check(run, stage)?;
        if stage != Stage::PublicValues {
            return Err("CUDA summary requires a statement scope".into());
        }
        self.admit(&[words.len(), 1])?;
        let input = self.runtime.allocate(words.len())?;
        let status = self.runtime.allocate(1)?;
        input.write(0, words)?;
        const _: () = assert!(commitment::DEPTH < 64);
        // Fixed protocol indices are in the admitted input. The kernel checks
        // level before shifting and downloads only the validity status.
        self.record(run, stage, unsafe {
            self.summary.launch(
                SINGLE,
                &[
                    Argument::Buffer(&input),
                    Argument::Buffer(&status),
                    Argument::U64(modes),
                    Argument::U32(programs::MODE as u32),
                    Argument::U32(programs::LEVEL as u32),
                    Argument::U32(programs::COUNT as u32),
                    Argument::U32(programs::ROOT as u32),
                    Argument::U32(u32::from(commitment::DEPTH)),
                ],
            )
        })?;
        let mut result = [u64::MAX];
        status.read(0, &mut result)?;
        match result[0] {
            0 => Ok(()),
            1 => Err("noncanonical context limb".into()),
            2 => Err("node metadata range".into()),
            3 => Err(commitment::CommitmentError::NonCanonicalField.to_string()),
            _ => Err("CUDA public summary returned an invalid status".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_hash_stream_checks_both_passes_and_latches_callback_failures() {
        assert!(stream_length(MODULUS, &mut |_| Ok(())).is_err());
        assert!(stream_length(1, &mut |sink| {
            let _ = sink(MODULUS);
            Ok(())
        })
        .is_err());
        for length in [
            0,
            1,
            3,
            4,
            BATCH_WORDS - 1,
            BATCH_WORDS,
            BATCH_WORDS + 1,
            2 * BATCH_WORDS,
        ] {
            let mut producer = |sink: &mut FieldSink<'_>| {
                for i in 0..length {
                    sink(i as u64)?;
                }
                Ok(())
            };
            assert_eq!(stream_length(7, &mut producer).unwrap(), length);
            let mut seen = Vec::new();
            let mut calls = 0;
            batches(length, &mut producer, |words, first| {
                assert_eq!(first, calls == 0);
                assert!(words.len() <= BATCH_WORDS);
                seen.extend_from_slice(words);
                calls += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, (0..length as u64).collect::<Vec<_>>());
            assert_eq!(calls, length.div_ceil(BATCH_WORDS).max(1));
        }
        for fields in [vec![], vec![1, 2], vec![MODULUS]] {
            assert!(batches(
                1,
                &mut |sink| {
                    for &field in &fields {
                        let _ = sink(field);
                    }
                    Ok(())
                },
                |_, _| Ok(())
            )
            .is_err());
        }
        let mut calls = 0;
        assert!(batches(
            2 * BATCH_WORDS,
            &mut |sink| {
                for _ in 0..2 * BATCH_WORDS {
                    let _ = sink(1);
                }
                Ok(())
            },
            |_, _| {
                calls += 1;
                Err("injected consumer failure".into())
            }
        )
        .is_err());
        assert_eq!(calls, 1);
    }
}
