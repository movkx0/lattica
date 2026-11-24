//! A single private witness handed from a bounded CPU worker to the GPU owner.
use super::*;

/// Consumed by one proof attempt. Private traces never enter the public cache.
/// Only this module constructs the payload, bound to exact source and publics.
#[derive(Debug)]
pub struct PreparedRecursionWitness {
    pub(super) identity: [u8; 32],
    pub(super) public: Vec<Val>,
    pub(super) traces: Vec<RowMajorMatrix<Val>>,
    pub(super) seconds: f64,
    pub(super) preparation_bytes: usize,
}

impl PreparedRecursionWitness {
    pub(super) fn matches(&self, template: &RecursionTemplate, public: &[Val]) -> bool {
        self.identity == template.identity() && self.public == public
    }
}

impl RecursionTemplate {
    /// Conservative peak for source, original inputs, evaluated wires, and all
    /// ready traces. The caller keeps this charged to its running/ready permit.
    pub fn witness_preparation_bytes(&self) -> Result<usize, String> {
        let mut bytes = self.program.construction_host_bytes();
        let mut add = |n: usize| -> Result<(), String> {
            bytes = bytes
                .checked_add(n)
                .ok_or("recursion witness storage overflow")?;
            Ok(())
        };
        for rows in &self.rows {
            add(rows
                .len()
                .checked_mul(4)
                .ok_or("recursion witness indices overflow")?)?;
        }
        add(self.typed.backing_bytes())?;
        add(self
            .tables
            .len()
            .checked_mul(core::mem::size_of::<super::super::layout::TableSpan>())
            .ok_or("recursion witness tables overflow")?)?;
        // Two input capacities cover the compiler's growing witness vector;
        // public values also have a private binding copy in the ready payload.
        for (count, width) in [
            (self.program.wire_count(), 8),
            (self.program.witness_values(), 16),
            (self.program.public_values(), 24),
        ] {
            add(count
                .checked_mul(width)
                .ok_or("recursion witness values overflow")?)?;
        }
        for air in self.airs() {
            add(air
                .height
                .checked_mul(air.width())
                .and_then(|n| n.checked_mul(8))
                .ok_or("recursion witness traces overflow")?)?;
        }
        add(64 << 10)?;
        Ok(bytes)
    }

    /// CPU-only preparation; no GPU context, public setup, or private proof
    /// randomness is created here. An oversized job stays on the serial path.
    pub fn prepare_gpu_witness(
        &self,
        public: &[Val],
        witness: &[Val],
        allowance: usize,
    ) -> Result<Option<PreparedRecursionWitness>, String> {
        let preparation_bytes = self.witness_preparation_bytes()?;
        if preparation_bytes > allowance {
            return Ok(None);
        }
        let started = Instant::now();
        let traces = self
            .traces(public, witness)
            .map_err(|e| format!("prepared recursion witness: {e:?}"))?;
        Ok(Some(PreparedRecursionWitness {
            identity: self.identity(),
            public: public.to_vec(),
            traces,
            seconds: started.elapsed().as_secs_f64(),
            preparation_bytes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::machine::ProgramBuilder;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_symmetric::Permutation;

    #[test]
    fn prepared_witness_admission_binding_and_reference_traces() {
        let mut b = ProgramBuilder::new(8).unwrap();
        let input = core::array::from_fn(|_| b.input());
        let out = b.poseidon(input);
        for (i, wire) in out.into_iter().enumerate() {
            let public = b.public(i).unwrap();
            b.assert_equal(wire, public);
        }
        let template = RecursionTemplate::new(Arc::new(b.finish(None).unwrap()), [81; 32]).unwrap();
        let witness = core::array::from_fn::<_, 8, _>(|i| Val::from_usize(i + 1));
        let public = default_goldilocks_poseidon2_8().permute(witness);
        let bytes = template.witness_preparation_bytes().unwrap();
        assert!(template
            .prepare_gpu_witness(&public, &witness, bytes - 1)
            .unwrap()
            .is_none());
        let source_refs = Arc::strong_count(&template.program);
        let ready = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    template
                        .prepare_gpu_witness(&public, &witness, bytes)
                        .unwrap()
                        .unwrap()
                })
                .join()
                .unwrap()
        });
        assert_eq!(Arc::strong_count(&template.program), source_refs);
        assert_eq!(ready.preparation_bytes, bytes);
        let expected = template.traces(&public, &witness).unwrap();
        assert_eq!(ready.traces.len(), expected.len());
        for (actual, expected) in ready.traces.iter().zip(expected) {
            assert_eq!(actual.width, expected.width);
            assert_eq!(actual.values, expected.values);
        }
        assert!(ready.matches(&template, &public));
        let mut wrong = public;
        wrong[0] += Val::ONE;
        assert!(!ready.matches(&template, &wrong));
        let other = RecursionTemplate::new(Arc::clone(&template.program), [82; 32]).unwrap();
        assert!(!ready.matches(&other, &public));
        assert!(template
            .prepare_gpu_witness(&public, &witness[..7], bytes)
            .is_err());
    }
}
