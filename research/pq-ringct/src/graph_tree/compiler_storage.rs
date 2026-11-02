//! Pure split of an already established construction ceiling. Callers must
//! check immutable Program capacity before retiring the scratch original.
use crate::execution::retained_resources::{Bytes, Category, Requirements};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::OperationCounts;

pub(super) fn split(
    output: Requirements,
    mut scratch: Requirements,
    construction: usize,
    counts: OperationCounts,
    publics: usize,
    wires: usize,
    hints: usize,
) -> Result<(Requirements, Requirements), ()> {
    let retained = counts
        .retained_program_host_ceiling(publics, wires, hints)
        .map_err(|_| ())?;
    let temporary = construction.checked_sub(retained).ok_or(())?;
    let mut packed = Requirements::default();
    for category in Category::ALL {
        let mut value = output.get(category);
        if category == Category::SymbolicCompiler {
            value.host = value.host.checked_sub(temporary as u64).ok_or(())?;
        }
        packed.add(category, value).map_err(|_| ())?;
    }
    scratch
        .add(
            Category::PhaseScratch,
            Bytes {
                host: temporary as u64,
                device: 0,
            },
        )
        .map_err(|_| ())?;
    Ok((packed, scratch))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn construction_bytes_remain_charged_until_scratch_retires() {
        let old = Requirements::single(
            Category::SymbolicCompiler,
            Bytes {
                host: 2 << 30,
                device: 0,
            },
        );
        let scratch = Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: 123456,
                device: 0,
            },
        );
        let (packed, temporary) = split(
            old,
            scratch,
            2 << 30,
            OperationCounts {
                scalar: 100,
                cubic: 8,
                poseidon: 2,
            },
            28,
            500,
            32,
        )
        .unwrap();
        assert!(packed.total().unwrap().host < 1 << 20);
        assert_eq!(
            packed.total().unwrap().host + temporary.total().unwrap().host,
            (2 << 30) + 123456
        );
        assert_eq!(packed.total().unwrap().device, 0);
        assert!(split(
            old,
            scratch,
            1,
            OperationCounts {
                scalar: 100,
                cubic: 8,
                poseidon: 2
            },
            28,
            500,
            32
        )
        .is_err());
    }
}
