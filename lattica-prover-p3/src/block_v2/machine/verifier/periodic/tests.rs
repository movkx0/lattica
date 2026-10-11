use super::*;
use crate::block_v2::{machine::Wire, profile};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

#[test]
fn all_leaf_columns_match_unchanged_air_tables_and_reject_bad_buffers() {
    let js = ContextJoinSplitAir;
    let issuance = ContextAir(crate::joinsplit_air::JoinSplitAir);
    let htlc = ContextAir(crate::htlc_air::HtlcAir);
    for (source, columns) in [
        (&js as &dyn Source, js.periodic_columns()),
        (&issuance as &dyn Source, issuance.periodic_columns()),
        (&htlc as &dyn Source, htlc.periodic_columns()),
    ] {
        assert_eq!(source.count(), columns.len());
        let mut total = 0;
        let mut largest = 0;
        for (index, column) in columns.iter().enumerate() {
            let n = source.len(index).unwrap();
            assert_eq!(n, column.len());
            let mut actual = vec![Val::NEG_ONE; n];
            source.fill(index, &mut actual).unwrap();
            assert_eq!(&actual, column, "column {index}");
            for bad_len in [0, n - 1, n + 1] {
                let mut bad = vec![Val::NEG_ONE; bad_len];
                assert!(source.fill(index, &mut bad).is_err());
                assert!(bad.iter().all(|&v| v == Val::NEG_ONE));
            }
            total += n * std::mem::size_of::<Val>();
            largest = largest.max(n * std::mem::size_of::<Val>());
        }
        for index in [source.count(), usize::MAX] {
            assert_eq!(source.len(index), None);
            let mut bad = [Val::NEG_ONE; 3];
            assert!(source.fill(index, &mut bad).is_err());
            assert_eq!(bad, [Val::NEG_ONE; 3]);
        }
        eprintln!(
            "periodic_source_parity columns={} total_source_bytes={} largest_column_bytes={}",
            source.count(),
            total,
            largest
        );
    }
}

struct BadGeometry {
    lengths: [usize; 2],
    fills: Cell<usize>,
}
impl Source for BadGeometry {
    fn count(&self) -> usize {
        2
    }
    fn len(&self, i: usize) -> Option<usize> {
        self.lengths.get(i).copied()
    }
    fn fill(&self, _: usize, _: &mut [Val]) -> Result<(), CompileError> {
        self.fills.set(self.fills.get() + 1);
        panic!("invalid geometry reached source callback")
    }
}

#[test]
fn invalid_geometry_rejects_all_columns_before_fill_or_arithmetic() {
    use crate::proving::{Request, Run, Stage};
    let run = Run::new(
        "source geometry",
        Request::compatible(),
        profile::public_scope_capabilities(Stage::Preprocessing),
    )
    .unwrap();
    for (lengths, log, count) in [
        ([4, 0], 4, 2),
        ([4, 3], 4, 2),
        ([4, 32], 4, 2),
        ([4, usize::MAX], 4, 2),
        ([4, 4], 33, 2),
        ([4, 4], 4, 1),
    ] {
        let source = BadGeometry {
            lengths,
            fills: Cell::new(0),
        };
        let mut b = ScopedProgramBuilder::new(0).unwrap();
        let mut output = vec![[Wire(42); 3]; count];
        assert!(values_into(
            &mut b,
            &source,
            [Wire(0); 3],
            log,
            Constants::cpu_reported(&run),
            &mut output
        )
        .is_err());
        assert_eq!(output, vec![[Wire(42); 3]; count]);
        assert_eq!(source.fills.get(), 0);
    }
    assert!(run.finish(false).unwrap().observations.is_empty());
}

#[test]
fn generated_column_evaluation_preserves_cpu_program_and_values() {
    let columns = vec![
        (0..8).map(|i| Val::from_usize(3 * i + 1)).collect(),
        (0..4).map(|i| Val::from_usize(7 * i + 2)).collect(),
    ];
    let compile = |generated: bool| {
        let mut b = ScopedProgramBuilder::new(0).unwrap();
        let zeta = b.ext_constant([Val::from_u64(17), Val::ONE, Val::from_u64(2)]);
        let mut output = [[Wire(0); 3]; 2];
        if generated {
            values_into(
                &mut b,
                &Borrowed(&columns),
                zeta,
                4,
                Constants::cpu(),
                &mut output,
            )
            .unwrap();
        } else {
            expressions::periodic_values_into(
                &mut b,
                &columns,
                zeta,
                4,
                Constants::cpu(),
                &mut output,
            )
            .unwrap();
        }
        (b.finish(None).unwrap(), output)
    };
    let (reference, outputs) = compile(false);
    let (actual, actual_outputs) = compile(true);
    assert_eq!(actual, reference);
    assert_eq!(actual_outputs, outputs);
    assert_eq!(
        actual.evaluate(&[], &[]).unwrap(),
        reference.evaluate(&[], &[]).unwrap()
    );
}

struct Counter {
    tables: AtomicUsize,
    fills: AtomicUsize,
}
impl BaseAir<Val> for Counter {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.tables.fetch_add(1, Relaxed);
        vec![(1..=8).map(Val::from_u64).collect()]
    }
}
impl Source for Counter {
    fn count(&self) -> usize {
        1
    }
    fn len(&self, i: usize) -> Option<usize> {
        (i == 0).then_some(8)
    }
    fn fill(&self, index: usize, out: &mut [Val]) -> Result<(), CompileError> {
        if index != 0 || out.len() != 8 {
            return Err(CompileError::Shape("test source"));
        }
        self.fills.fetch_add(1, Relaxed);
        for (i, x) in out.iter_mut().enumerate() {
            *x = Val::from_usize(i + 1);
        }
        Ok(())
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Counter {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let local: AB::Expr = main.current_slice()[0].into();
        let next: AB::Expr = main.next_slice()[0].into();
        let public: AB::Expr = b.public_values()[0].into();
        let periodic: AB::Expr = b.periodic_values()[0].into();
        b.when_first_row().assert_zero(local.clone() - public);
        b.when_transition().assert_zero(next - local - periodic);
    }
}

#[test]
fn registered_uni_uses_admitted_source_and_preserves_real_proof_rejection() {
    use super::super::{uni, ProofInputs};
    let air = Counter {
        tables: AtomicUsize::new(0),
        fills: AtomicUsize::new(0),
    };
    let config = profile::make_config();
    let public = [Val::from_u64(37)];
    let mut value = public[0];
    let trace = RowMajorMatrix::new(
        (0..16)
            .map(|i| {
                let row = value;
                value += Val::from_usize(i % 8 + 1);
                row
            })
            .collect(),
        1,
    );
    let proof = p3_uni_stark::prove(&config, &air, trace, &public);
    p3_uni_stark::verify(&config, &air, &proof, &public).unwrap();
    let compile = |registered: bool, proof: &p3_uni_stark::Proof<profile::Config>| {
        let mut b = ScopedProgramBuilder::new(1).unwrap();
        let public = [b.public(0).unwrap()];
        let mut inputs = ProofInputs::default();
        air.tables.store(0, Relaxed);
        air.fills.store(0, Relaxed);
        if registered {
            uni::verify_with_constants(
                &mut b,
                &mut inputs,
                &air,
                16,
                &public,
                proof,
                Constants::cpu(),
            )
            .unwrap();
            assert_eq!(air.tables.load(Relaxed), 0);
            assert_eq!(air.fills.load(Relaxed), 1);
        } else {
            uni::verify(&mut b, &mut inputs, &air, 16, &public, proof).unwrap();
            assert_eq!(air.tables.load(Relaxed), 1);
        }
        (b.finish(None).unwrap(), inputs.values)
    };
    let (reference, reference_inputs) = compile(false, &proof);
    let (program, inputs) = compile(true, &proof);
    assert_eq!(program, reference);
    assert_eq!(inputs, reference_inputs);
    program.evaluate(&public, &inputs).unwrap();
    assert!(program.evaluate(&[public[0] + Val::ONE], &inputs).is_err());
    let mut altered = proof;
    altered.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(p3_uni_stark::verify(&config, &air, &altered, &public).is_err());
    let (bad, bad_inputs) = compile(true, &altered);
    assert_eq!(bad, program);
    assert!(bad.evaluate(&public, &bad_inputs).is_err());
}
