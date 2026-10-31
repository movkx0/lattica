//! Every backing request is charged before allocation. No growth or clones.
use super::*;

pub(super) struct Storage { backing: Backing }

impl Storage {
    pub(super) fn new() -> Self { Self { backing: Backing::default() } }
    pub(super) fn backing(&self) -> Backing { self.backing }

    fn vector<T>(&mut self, count: usize, mut element: impl FnMut(&mut Self, usize) -> R<T>) -> R<Vec<T>> {
        let bytes = product(count, size_of::<T>())?;
        self.backing.bytes = sum(self.backing.bytes, bytes)?;
        if self.backing.bytes > DECODE_LIMIT { return Err(Error::FixtureStorage); }
        self.backing.allocations = sum(self.backing.allocations, usize::from(bytes != 0))?;
        self.backing.max_vector = self.backing.max_vector.max(count);
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| Error::Allocation)?;
        require(values.capacity() == count)?;
        for index in 0..count { values.push(element(self, index)?); }
        Ok(values)
    }

    fn cap(&mut self, log: usize, word: Val) -> R<Cap> {
        let count = 1usize.checked_shl(u32::try_from(log.min(6)).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        Ok(Cap::new(self.vector(count, |_, _| Ok([word; 4]))?))
    }

    fn authentication(&mut self, matrices: usize, path: usize, word: Val) -> R<(Vec<Vec<Val>>, Vec<[Val; 4]>)> {
        Ok((self.vector(matrices, |storage, _| storage.vector(4, |_, _| Ok(word)))?,
            self.vector(path, |_, _| Ok([word; 4]))?))
    }
}

pub(super) fn make(rows: usize, word: Val, storage: &mut Storage) -> R<Proof> {
    require((8..=1 << 20).contains(&rows) && rows.is_power_of_two())?;
    let degree = sum(rows.ilog2() as usize, 1)?;
    let log_lde = sum(degree, 4)?;
    let extension = Challenge::new([word; 3]);
    let matrices = [1, 1, 16, 1, 1];
    let points = [1, 1, 1, 1, 2];
    let widths = [3, 94, 3, 200, 54];
    // These fields mirror the pinned concrete schema, not a proving API.
    Ok(Proof {
        commitments: BatchCommitments {
            main: storage.cap(log_lde, word)?,
            permutation: Some(storage.cap(log_lde, word)?),
            quotient_chunks: storage.cap(log_lde, word)?,
            random: Some(storage.cap(log_lde, word)?),
        },
        opened_values: BatchOpenedValues {
            instances: storage.vector(1, |storage, _| Ok(LookupValues {
                base_opened_values: Values {
                    trace_local: storage.vector(94, |_, _| Ok(extension))?,
                    trace_next: None,
                    preprocessed_local: Some(storage.vector(200, |_, _| Ok(extension))?),
                    preprocessed_next: None,
                    quotient_chunks: storage.vector(16, |storage, _|
                        storage.vector(3, |_, _| Ok(extension)))?,
                    random: Some(storage.vector(3, |_, _| Ok(extension))?),
                },
                permutation_local: storage.vector(54, |_, _| Ok(extension))?,
                permutation_next: storage.vector(54, |_, _| Ok(extension))?,
            }))?,
        },
        opening_proof: (
            storage.vector(5, |storage, round|
                storage.vector(matrices[round], |storage, _|
                    storage.vector(points[round], |storage, _|
                        storage.vector(if round == 3 { 0 } else { 4 }, |_, _| Ok(extension)))))?,
            Fri {
                commit_phase_commits: storage.vector(degree, |storage, layer|
                    storage.cap(log_lde.checked_sub(sum(layer, 1)?).ok_or(Error::Overflow)?, word))?,
                commit_pow_witnesses: storage.vector(degree, |_, _| Ok(word))?,
                query_proofs: storage.vector(128, |storage, _| Ok(Query {
                    input_proof: storage.vector(5, |storage, round| Ok(Opening {
                        opened_values: storage.vector(matrices[round], |storage, _|
                            storage.vector(sum(widths[round], if round == 3 { 0 } else { 4 })?,
                                |_, _| Ok(word)))?,
                        opening_proof: storage.authentication(matrices[round], log_lde.saturating_sub(6), word)?,
                    }))?,
                    commit_phase_openings: storage.vector(degree, |storage, layer| Ok(Step {
                        log_arity: 1,
                        sibling_values: storage.vector(1, |_, _| Ok(extension))?,
                        opening_proof: storage.authentication(1,
                            log_lde.checked_sub(sum(layer, 1)?).ok_or(Error::Overflow)?.saturating_sub(6), word)?,
                    }))?,
                }))?,
                final_poly: storage.vector(1, |_, _| Ok(extension))?,
                query_pow_witness: word,
            },
        ),
        // The transparent terminal is zero; the remaining canonical words
        // may be maximal. The object has no valid-proof claim in either case.
        lookup_terminals: storage.vector(1, |_, _| Ok(Some(Default::default())))?,
        degree_bits: storage.vector(1, |_, _| Ok(degree))?,
    })
}
