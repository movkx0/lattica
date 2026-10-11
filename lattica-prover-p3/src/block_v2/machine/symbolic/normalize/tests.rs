use super::super::expression::{Base, Extension};
use super::*;
use p3_air::{symbolic::AirLayout, AirBuilder};
use std::mem::size_of;

pub(crate) fn reject_allowance(constants: Constants<'_>) {
    let storage = Storage::limited(0, !matches!(constants, Constants::Cpu(None)));
    let mut builder = Builder::new(AirLayout::default()).unwrap();
    let input = (Base::ONE + Base::ONE).0;
    builder.base.push(input.clone());
    assert!(matches!(
        admit(&builder, &storage),
        Err(CompileError::Shape("symbolic normalization allowance"))
    ));
    let mut normalizer = Normalizer::new(constants, &storage);
    assert!(normalizer.base(&input, 0).is_err());
    // A fresh quota also rejects child storage before its callback; subsequent
    // folding calls must not reach the backend after a resource failure.
    let storage = Storage::limited(0, !matches!(constants, Constants::Cpu(None)));
    let mut normalizer = Normalizer::new(constants, &storage);
    assert!(normalizer.base(&input, 0).is_err());
    assert!(normalizer
        .fold(FoldOperation::Add, Val::ONE, Val::ONE)
        .is_err());
}

#[test]
fn normalization_quota_failure_prevents_backend_callbacks() {
    use crate::proving::{Capabilities, Profile, Request, Run};
    let run = Run::new(
        "normalization_allowance",
        Request::compatible(),
        Capabilities::cpu(Profile::BlockV2Cubic, true, true),
    )
    .unwrap();
    reject_allowance(Constants::cpu_reported(&run));
    assert!(run.finish(false).unwrap().observations.is_empty());
}

#[test]
fn memo_preserves_pointer_identity_without_structural_interning() {
    let storage = Storage::new(false);
    let mut normalizer = Normalizer::new(Constants::cpu(), &storage);
    let builder = Builder::new(AirLayout::default()).unwrap();
    let raw = (builder.is_first_row() + builder.is_last_row()).0;
    let a = Arc::new(raw.clone());
    let b = Arc::new(raw);
    let normalized_a = normalizer.base_arc(&a, 0).unwrap();
    let alias = normalizer.base_arc(&a, 0).unwrap();
    let normalized_b = normalizer.base_arc(&b, 0).unwrap();
    assert!(Arc::ptr_eq(&normalized_a, &alias));
    assert!(!Arc::ptr_eq(&normalized_a, &normalized_b));
    let (SymbolicExpr::Add { x: ax, y: ay, .. }, SymbolicExpr::Add { x: bx, y: by, .. }) =
        (&*normalized_a, &*normalized_b)
    else {
        panic!("expected raw variable sum")
    };
    assert!(Arc::ptr_eq(ax, bx) && Arc::ptr_eq(ay, by));
    let ext_a = Arc::new(Extension::from(Base::ONE).0);
    let normalized = normalizer.ext_arc(&ext_a, 0).unwrap();
    assert!(Arc::ptr_eq(
        &normalized,
        &normalizer.ext_arc(&ext_a, 0).unwrap()
    ));
}

#[test]
fn output_and_memo_nodes_share_the_same_storage_quota() {
    let storage = Storage::limited(size_of::<BaseExpr>(), false);
    let input = (Base::ONE + Base::ONE).0;
    let mut normalizer = Normalizer::new(Constants::cpu(), &storage);
    assert!(storage.vector(1, |_| normalizer.base(&input, 0)).is_err());
    assert!(storage.check().is_err());
    assert!(normalizer.base(&Base::ONE.0, 0).is_err());
}
