//! Exact prefix of the existing execution-program identity, before cap roots.
use super::*;
use super::super::program::ManifestCursor;

pub(super) fn header(air: &MachineAir) -> [u64; 10] {
    [1, super::super::WIDTH as u64, air.preprocessed_width() as u64,
        profile::LOG_BLOWUP as u64, profile::NUM_QUERIES as u64, profile::CAP_HEIGHT as u64,
        profile::NUM_RANDOM_CODEWORDS as u64, profile::QUERY_POW_BITS as u64, 3, 1]
}

pub(super) fn trailer(analysis: &super::super::analysis::MachineAnalysis) -> [u64; 18] {
    [1, 0xffff_ffff, 3, crate::block_v2::commitment::MODULUS - 1,
        crate::block_v2::commitment::MODULUS - 1, 0, 1, 8, 4, 4, 4, 0, 1,
        analysis.permutation_width_base as u64, analysis.quotient_chunks as u64,
        analysis.constraints as u64, analysis.max_constraint_degree as u64,
        analysis.query_multiplicity_bound]
}

#[derive(Clone)]
pub(super) struct Cursor<'a> {
    header: [u64; 10], trailer: [u64; 18], manifest: ManifestCursor<'a>,
    fingerprint: &'a [u64], phase: u8, offset: usize,
}
impl<'a> Cursor<'a> {
    pub(super) fn new(air: &'a MachineAir, analysis: &super::super::analysis::MachineAnalysis,
        fingerprint: &'a [u64]) -> Self {
        Self { header: header(air), trailer: trailer(analysis),
            manifest: ManifestCursor::new(air.program()), fingerprint, phase: 0, offset: 0 }
    }
}
impl Iterator for Cursor<'_> {
    type Item = Result<u64, String>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let word = match self.phase {
                0 => self.header.get(self.offset),
                1 => {
                    if let Some(word) = self.manifest.next() {
                        if word.is_err() { self.phase = 4; }
                        return Some(word);
                    }
                    self.phase = 2; self.offset = 0; continue;
                }
                2 => self.trailer.get(self.offset),
                3 => self.fingerprint.get(self.offset),
                _ => return None,
            };
            if let Some(&word) = word { self.offset += 1; return Some(Ok(word)); }
            self.phase += 1; self.offset = 0;
        }
    }
}
impl std::iter::FusedIterator for Cursor<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resumable_identity_prefix_is_the_original_canonical_stream() {
        let mut b = super::super::super::ProgramBuilder::new(1).unwrap();
        let input = b.input(); b.assert_equal(b.public(0).unwrap(), input);
        let air = MachineAir::new(b.finish(Some(64)).unwrap());
        let analysis = super::super::super::analysis::analyze(&air).unwrap();
        let roots = vec![[Val::from_u64(17); 4]; 1 << profile::CAP_HEIGHT];
        let common = common_from_cap(&air, p3_symmetric::MerkleCap::new(roots.clone())).unwrap();
        let prepared = super::super::super::symbolic::prepare_machine(&air,
            super::super::super::compiler_constants::Constants::cpu()).unwrap();
        let (_, constraints) = prepared.into_parts();
        let fingerprint = super::super::super::fingerprint::bounded::encode(
            &constraints.base, &constraints.extension, &constraints.order,
            super::super::super::fingerprint::bounded::HOST_BYTES).unwrap();
        let mut expected = Vec::new();
        emit_program_identity(&air, &common, &analysis, &fingerprint, &mut |v| { expected.push(v); Ok(()) }).unwrap();
        let mut actual = Cursor::new(&air, &analysis, &fingerprint).collect::<Result<Vec<_>, _>>().unwrap();
        actual.extend(roots.iter().flatten().map(|x| x.as_canonical_u64()));
        assert_eq!(actual, expected);
    }
}
