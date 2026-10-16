use super::*;
use crate::block_v2::machine::verifier::CompileError;
use p3_air::{AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

struct TableAir {
    fills: AtomicUsize,
    length_calls: AtomicUsize,
    count_calls: AtomicUsize,
    declared_count: usize,
    count: usize,
    len: usize,
    change_length_after: Option<usize>,
    change_count: bool,
    fail_fill: bool,
}
impl BaseAir<Val> for TableAir {
    fn width(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        self.declared_count
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        panic!("GPU preparation must not call the owned AIR table generator")
    }
}
impl StaticPeriodicSource for TableAir {
    fn count(&self) -> usize {
        let calls = self.count_calls.fetch_add(1, SeqCst);
        self.count + usize::from(self.change_count && calls != 0)
    }
    fn len(&self, index: usize) -> Option<usize> {
        let calls = self.length_calls.fetch_add(1, SeqCst);
        if index >= self.count || self.len == usize::MAX {
            return None;
        }
        Some(if self.change_length_after.is_some_and(|n| calls >= n) {
            self.len * 2
        } else {
            self.len
        })
    }
    fn fill(&self, _: usize, output: &mut [Val]) -> Result<(), CompileError> {
        self.fills.fetch_add(1, SeqCst);
        if self.fail_fill {
            return Err(CompileError::Shape("test source failure"));
        }
        assert_eq!(output.len(), self.len);
        output.fill(Val::ONE);
        Ok(())
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for TableAir {
    fn eval(&self, b: &mut AB) {
        b.assert_zero(AB::Expr::ZERO);
    }
}
fn air(count: usize, len: usize) -> TableAir {
    TableAir {
        fills: AtomicUsize::new(0),
        length_calls: AtomicUsize::new(0),
        count_calls: AtomicUsize::new(0),
        declared_count: count,
        count,
        len,
        change_length_after: None,
        change_count: false,
        fail_fill: false,
    }
}

#[test]
fn malformed_periodic_metadata_rejects_before_any_fill() {
    let mut mismatch = air(1, 4);
    mismatch.declared_count = 2;
    for air in [
        mismatch,
        air(1, 0),
        air(1, 3),
        air(1, 512),
        air(1, usize::MAX),
    ] {
        assert!(Prepared::new(&air, 256, Extension::Cubic, symbolic::HOST_BYTES as usize).is_err());
        assert_eq!(air.fills.load(SeqCst), 0);
    }
    let air = air(1, 4);
    for rows in [0, 3] {
        assert!(Source::new(&air, rows, usize::MAX).is_err());
    }
    assert_eq!(air.fills.load(SeqCst), 0);
}

#[test]
fn construction_and_staging_allowance_is_checked_before_fill() {
    let air = air(1, 4);
    let bytes = 4 * (core::mem::size_of::<Val>() + 2 * core::mem::size_of::<u64>())
        + core::mem::size_of::<Vec<Val>>()
        + core::mem::size_of::<Vec<u64>>()
        + 2 * core::mem::size_of::<u64>()
        + core::mem::size_of::<usize>();
    assert!(Source::new(&air, 256, bytes - 1).is_err());
    assert_eq!(air.fills.load(SeqCst), 0);
    let source = Source::new(&air, 256, bytes).unwrap().unwrap();
    assert_eq!(source.columns, [vec![Val::ONE; 4]]);
    assert_eq!(source.columns.capacity(), 1);
    assert_eq!(source.columns[0].capacity(), 4);
    assert_eq!(air.fills.load(SeqCst), 1);
}

#[test]
fn aggregate_preparation_allowance_rejects_before_periodic_fill_in_both_fields() {
    // One four-element column: retained fields, encoded words, flattened
    // upload, two outer vector entries, captured length and offset/length pair.
    let staging = 4 * (core::mem::size_of::<Val>() + 2 * core::mem::size_of::<u64>())
        + core::mem::size_of::<Vec<Val>>()
        + core::mem::size_of::<Vec<u64>>()
        + core::mem::size_of::<usize>()
        + 2 * core::mem::size_of::<u64>();
    let required = symbolic::HOST_BYTES as usize + staging;
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let air = air(1, 4);
        let error = match Prepared::new(&air, 256, extension, required - 1) {
            Ok(_) => panic!("overlapping owners must not reuse the host allowance"),
            Err(error) => error,
        };
        assert!(error.contains("periodic source capacity and staging"));
        assert_eq!(air.fills.load(SeqCst), 0);
        let prepared = Prepared::new(&air, 256, extension, required).unwrap();
        assert_eq!(prepared.required_host_bytes().unwrap(), required);
        assert_eq!(prepared.periodic_host_bytes(), staging);
        assert_eq!(air.fills.load(SeqCst), 1);
        // A different runtime configuration must preserve the aggregate too.
        assert!(prepared.check_host_allowance(required - 1).is_err());
        assert!(prepared.check_host_allowance(required).is_ok());
        assert_eq!(prepared.periodic.unwrap().columns(), &[vec![Val::ONE; 4]]);
    }
}

#[test]
fn preparation_without_periodic_columns_needs_only_the_symbolic_envelope() {
    let air = air(0, 0);
    let bytes = symbolic::HOST_BYTES as usize;
    let prepared = Prepared::new(&air, 256, Extension::Cubic, bytes).unwrap();
    assert_eq!(prepared.required_host_bytes().unwrap(), bytes);
    assert_eq!(prepared.periodic_host_bytes(), 0);
    assert!(prepared.check_host_allowance(bytes - 1).is_err());
    assert!(prepared.check_host_allowance(bytes).is_ok());
    assert_eq!(air.fills.load(SeqCst), 0);
    assert!(prepared.operation_host_allowance().is_err());
    assert!(prepared.minimum().is_err());
}

#[test]
fn operation_budget_is_disjoint_and_runtime_cannot_change_the_admitted_partition() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let air = air(1, 4);
        let prepared = Prepared::new(&air, 256, extension, 1 << 30).unwrap();
        let remaining = prepared.operation_host_allowance().unwrap();
        assert!(remaining < (1 << 30) - symbolic::HOST_BYTES as usize);
        assert_eq!(remaining + prepared.required_host_bytes().unwrap(), 1 << 30);
        assert!(prepared.check_operation_host_allowance(remaining).is_ok());
        for changed in [0, remaining - 1, remaining + 1, 1 << 30, usize::MAX] {
            assert!(prepared.check_operation_host_allowance(changed).is_err());
        }
        // Reject the wrong field before entropy, GPU state or configuration.
        if extension == Extension::Quadratic {
            assert!(prepared
                .config::<crate::block_v2::profile::Challenge>()
                .is_err());
        } else {
            assert!(prepared.config::<crate::config::Challenge>().is_err());
        }
    }
}

#[test]
fn changed_metadata_rejects_all_columns_before_any_fill() {
    // Two columns: detect changes during capture and during the final recheck.
    for calls in [2, 3, 4, 5] {
        let mut air = air(2, 4);
        air.change_length_after = Some(calls);
        assert!(Source::new(&air, 256, 4096).is_err());
        assert_eq!(air.fills.load(SeqCst), 0);
    }
    let mut air = air(2, 4);
    air.change_count = true;
    assert!(Source::new(&air, 256, 4096).is_err());
    assert_eq!(air.fills.load(SeqCst), 0);
}

#[test]
fn zero_columns_need_no_table_or_fill() {
    let air = air(0, 0);
    assert!(Source::new(&air, 256, 0).unwrap().is_none());
    assert_eq!(air.length_calls.load(SeqCst), 0);
    assert_eq!(air.fills.load(SeqCst), 0);
}

#[test]
fn fill_failure_propagates_without_returning_a_partial_source() {
    let mut air = air(2, 4);
    air.fail_fill = true;
    assert!(Source::new(&air, 256, 4096).is_err());
    assert_eq!(air.fills.load(SeqCst), 1);
}

#[test]
fn retained_source_is_filled_once_and_shared_expansion_plan_checks_exact_boundaries() {
    let air = air(1, 4);
    let prepared = Prepared::new(&air, 256, Extension::Cubic, 1 << 30).unwrap();
    let source = prepared.periodic.as_ref().unwrap();
    let shape = source.shape();
    assert_eq!(source.columns(), &[vec![Val::ONE; 4]]);
    assert_eq!(air.fills.load(SeqCst), 1);
    let allocation: usize = shape.allocation_bytes().iter().sum();
    let baseline = 47;
    assert!(shape
        .plan(baseline, baseline + allocation - 1, 4096)
        .is_err());
    assert!(shape
        .plan(baseline, baseline + allocation, shape.output.bytes() - 1)
        .is_err());
    assert!(shape.plan(baseline, baseline + allocation, 4096).is_ok());
    assert_eq!(
        shape.input_words(),
        4,
        "compact source, not trace-height storage"
    );
}
