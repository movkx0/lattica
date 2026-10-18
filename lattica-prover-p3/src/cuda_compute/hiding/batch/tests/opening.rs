use super::*;
use crate::cuda_compute::{FieldSpan, Openings};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::BasedVectorSpace;

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_hidden_commitment_openings_match_cpu_polynomials() {
    let runtime = runtime(4 << 20, 2 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let openings = Openings::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let (trace, cpu_trace) = upload(&runtime, 3, 2, Extension::Base, 1, 7);
    let random = randoms.import(rng(33)).unwrap();
    let salts = randoms.import(rng(77)).unwrap();
    let prepared = hiding.prepare_trace(&trace, &random, 8, 2).unwrap();
    let data = hiding
        .commit_batch(&commitments, &[HidingInput::Trace(&prepared)], &salts, 0)
        .unwrap();
    let point = Challenge::from_basis_coefficients_fn(|j| Val::from_u64([17, 19][j]));
    let points = runtime.allocate(4).unwrap();
    points.write(1, &[17, 19]).unwrap();
    let span = FieldSpan {
        buffer: &points,
        first: 1,
    };
    let before = runtime.snapshot();
    assert!(data
        .with_opening(&openings, 1, Extension::Quadratic, span, 1, |_| Ok(()))
        .is_err());
    assert!(data
        .with_opening(&openings, 0, Extension::Quadratic, span, 0, |_| Ok(()))
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let pressure = fill_budget(&runtime, 4 << 20, 2 << 20);
    let pressured = runtime.snapshot();
    assert!(data
        .with_opening(&openings, 0, Extension::Quadratic, span, 1, |_| Ok(()))
        .is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    random.check_live().unwrap();
    salts.check_live().unwrap();
    let before = runtime.snapshot();
    let actual = data
        .with_opening(&openings, 0, Extension::Quadratic, span, 1, |o| {
            o.values(1024)
        })
        .unwrap();
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        (actual.len() * 8 + 8) as u64
    );
    assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);

    // Derive the polynomial from the independent upstream hidden commitment,
    // without downloading any of the native prefix or hidden LDE.
    let oracle = mmcs(rng(77), 0);
    let pcs = pcs(rng(33), oracle.clone());
    let (_, cpu_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(
        &pcs,
        [(Domain::new(Val::ONE, 4).unwrap(), cpu_trace)],
    );
    let matrices = oracle.get_matrices(&cpu_data);
    let width = matrices[0].width();
    let prefix = RowMajorMatrix::new(
        (0usize..16)
            .flat_map(|row| {
                let physical = row.reverse_bits() >> (usize::BITS - 4);
                (0..width).map(move |col| (physical, col))
            })
            .map(|(row, col)| matrices[0].get(row, col).unwrap())
            .collect(),
        width,
    );
    let coefficients = Dft::default().coset_idft_batch(prefix, Val::from_u64(GENERATOR));
    let expected: Vec<u64> = (0..width)
        .flat_map(|col| {
            let value = coefficients
                .values
                .chunks_exact(width)
                .rev()
                .fold(Challenge::ZERO, |v, row| v * point + row[col]);
            <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&value)
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(actual, expected);
    random.check_live().unwrap();
    salts.check_live().unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_hidden_opening_failures_retire_all_participating_families() {
    for fault in 0..3 {
        let runtime = runtime(4 << 20, 2 << 20);
        let hiding = Hiding::new(&runtime).unwrap();
        let commitments = Commitments::new(&runtime).unwrap();
        let openings = Openings::new(&runtime).unwrap();
        let randoms = Randoms::new(&runtime).unwrap();
        let (trace, _) = upload(&runtime, 3, 2, Extension::Base, 1, 7);
        let random = randoms.import(rng(33)).unwrap();
        let salts = randoms.import(rng(77)).unwrap();
        let prepared = hiding.prepare_trace(&trace, &random, 8, 2).unwrap();
        let data = hiding
            .commit_batch(&commitments, &[HidingInput::Trace(&prepared)], &salts, 0)
            .unwrap();
        let points = runtime.allocate(2).unwrap();
        points
            .write(
                0,
                if fault == 0 {
                    &[GENERATOR, 0]
                } else {
                    &[17, 19]
                },
            )
            .unwrap();
        let before = runtime.snapshot();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            data.with_opening(
                &openings,
                0,
                Extension::Quadratic,
                FieldSpan {
                    buffer: &points,
                    first: 0,
                },
                1,
                |_| -> Result<()> {
                    if fault == 2 {
                        panic!("injected CUDA opening consumer unwind");
                    }
                    Err("injected CUDA opening consumer failure".into())
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(random.check_live().is_err());
        assert!(salts.check_live().is_err());
        assert!(data.cap(32).is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
}
