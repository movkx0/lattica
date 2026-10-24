use super::*;
use crate::block_v2::machine::program::{ExecutionError, Wire};
use std::mem::size_of;

#[test]
fn nested_scratch_admits_combined_live_storage_before_callbacks() {
    let item = size_of::<[Wire; 3]>();
    for limit in [5 * item - 1, 5 * item] {
        let mut b = ScopedProgramBuilder::new(0).unwrap();
        b.memory.limit = Some(limit);
        let mut called = false;
        let result = b.with_compiler_scratch("outer-test", 2, [Wire(0); 3], |b, outer| {
            assert_eq!(b.memory.live, 2 * item);
            outer[0] = [Wire(7); 3];
            b.with_compiler_scratch("inner-test", 3, [Wire(1); 3], |b, inner| {
                called = true;
                assert_eq!(b.memory.live, 5 * item);
                assert_eq!(outer[0], [Wire(7); 3]);
                assert_eq!(inner, &[[Wire(1); 3]; 3]);
                Ok(())
            })
        });
        assert_eq!(result.is_ok(), limit == 5 * item);
        assert_eq!(called, result.is_ok());
        assert_eq!(b.memory.live, 0);
        assert!(b.memory.peak <= limit);
        assert_eq!(b.resource_failure().is_some(), result.is_err());
    }
}

#[test]
fn scratch_releases_on_success_error_and_unwind_while_preserving_peak() {
    for mode in 0..3 {
        let mut b = ScopedProgramBuilder::new(0).unwrap();
        let bytes = 9 * size_of::<Option<[Wire; 3]>>();
        b.memory.limit = Some(bytes);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.with_compiler_scratch("release-test", 9, None::<[Wire; 3]>, |_, values| {
                values[0] = Some([Wire(9); 3]);
                match mode {
                    0 => Ok(()),
                    1 => Err(CompileError::Shape("ordinary scratch error")),
                    _ => panic!("exercise scratch unwind"),
                }
            })
        }));
        assert_eq!(caught.is_err(), mode == 2);
        if let Ok(result) = caught {
            assert_eq!(result.is_ok(), mode == 0);
        }
        assert_eq!(b.memory.live, 0);
        assert_eq!(b.memory.peak, bytes);
        assert!(b.resource_failure().is_none());
        b.with_compiler_scratch("reuse-test", 9, None::<[Wire; 3]>, |_, _| Ok(()))
            .unwrap();
        assert_eq!(b.memory.live, 0);
        assert_eq!(b.memory.peak, bytes);
    }
}

#[test]
fn scratch_overflow_and_latched_failure_skip_callback_without_storage() {
    for count in [usize::MAX, 1] {
        let mut b = ScopedProgramBuilder::new(0).unwrap();
        b.memory.limit = Some(0);
        assert!(b
            .with_compiler_scratch(
                "rejected-test",
                count,
                [Wire(0); 3],
                |_, _| -> Result<(), CompileError> {
                    panic!("rejected allocation invoked callback")
                }
            )
            .is_err());
        assert_eq!(b.memory.live, 0);
        assert_eq!(b.memory.peak, 0);
        assert!(b
            .with_compiler_scratch(
                "latched-test",
                0,
                [Wire(0); 3],
                |_, _| -> Result<(), CompileError> { panic!("latched rejection invoked callback") }
            )
            .is_err());
        assert_eq!(b.finish(None).unwrap_err(), ExecutionError::TooLarge);
    }
}

#[test]
fn scratch_keeps_program_and_memo_reservations_after_scope_exit() {
    let mut b = ScopedProgramBuilder::new(0).unwrap();
    let before = b.memory.live;
    let scratch_bytes = 17 * size_of::<[Wire; 3]>();
    let inside = b
        .with_compiler_scratch("mixed-test", 17, [Wire(0); 3], |b, _| {
            let input = b.input();
            let mut memo = super::super::compiler_memo::CompilerMemo::new();
            memo.insert(0, [input; 3], b)?;
            let retained = b.memory.live - scratch_bytes;
            let memo_bytes = b.memory.live;
            memo.release(b, "scratch-test");
            assert!(b.memory.live < memo_bytes);
            Ok(retained - (memo_bytes - b.memory.live))
        })
        .unwrap();
    assert!(inside > before);
    assert_eq!(b.memory.live, inside);
    assert!(b.memory.peak >= inside + scratch_bytes);
    assert!(b.finish(None).is_ok());
}

#[test]
fn sparse_periodic_emission_still_obeys_builder_allowance() {
    use crate::block_v2::machine::{program::Val, verifier::expressions};
    use p3_field::PrimeCharacteristicRing;
    let mut column = vec![Val::ZERO; 128];
    column[37] = Val::ONE;
    let mut builder = ScopedProgramBuilder::new(3).unwrap();
    builder.memory.limit = Some(1);
    let mut output = [[Wire(42); 3]];
    assert!(expressions::periodic_values_into(
        &mut builder,
        &[column],
        [Wire(0), Wire(1), Wire(2)],
        7,
        crate::block_v2::machine::compiler_constants::Constants::cpu(),
        &mut output,
    )
    .is_err());
    assert_eq!(output, [[Wire(42); 3]]);
    assert!(builder.resource_failure().is_some());
    assert!(builder.finish(None).is_err());
}

#[test]
fn progression_periodic_emission_obeys_scratch_and_operation_allowances() {
    use crate::block_v2::machine::{program::Val, verifier::expressions};
    use p3_field::PrimeCharacteristicRing;
    // The same2048-root progression as a full Mul32 indicator. Its two public
    // coefficient buffers alone need32784 bytes, exceeding the first quota.
    let mut column = vec![Val::ZERO; 65536];
    for i in 0..2048 {
        column[18 + 19 * i] = Val::ONE;
    }
    for reject_operations in [false, true] {
        let mut builder = ScopedProgramBuilder::new(3).unwrap();
        if reject_operations {
            builder.memory.wire_limit = 3;
        } else {
            builder.memory.limit = Some(32768);
        }
        let mut output = [[Wire(42); 3]];
        assert!(expressions::periodic_values_into(
            &mut builder,
            &[column.clone()],
            [Wire(0), Wire(1), Wire(2)],
            16,
            crate::block_v2::machine::compiler_constants::Constants::cpu(),
            &mut output,
        )
        .is_err());
        assert_eq!(output, [[Wire(42); 3]]);
        assert!(builder.resource_failure().is_some());
        if !reject_operations {
            assert!(builder.memory.peak <= 32768);
        }
        assert!(builder.finish(None).is_err());
    }
}

fn compiler_storage_rejection(
    constants: crate::block_v2::machine::compiler_constants::Constants<'_>,
) {
    use crate::block_v2::machine::{program::Val, programs, verifier::expressions};
    use p3_field::PrimeCharacteristicRing;
    let scalar = size_of::<Val>();
    for (operation, limit) in [
        (0, 4 * scalar - 1),
        (0, 4 * (scalar + size_of::<Wire>()) - 1),
        (1, 4 * scalar - 1),
        (2, (4 + 4 * 4) * scalar - 1),
        (3, 4 * scalar - 1),
        (3, 8 * scalar - 1),
    ] {
        let mut b = ScopedProgramBuilder::with_constants(3, constants).unwrap();
        b.memory.limit = Some(limit);
        let result = match operation {
            0 => programs::selectors::<4>(&mut b, Wire(0), 0, 3, constants).map(|_| ()),
            1 => {
                let mut output = [[Wire(42); 3]; 1];
                let result = expressions::periodic_values_into(
                    &mut b,
                    &[vec![
                        Val::ONE,
                        Val::from_u64(2),
                        Val::from_u64(3),
                        Val::from_u64(4),
                    ]],
                    [Wire(0), Wire(1), Wire(2)],
                    2,
                    constants,
                    &mut output,
                );
                assert_eq!(output, [[Wire(42); 3]; 1]);
                result
            }
            2 => expressions::quotient_with_constants(
                &mut b,
                &vec![vec![[Wire(0); 3]; 3]; 4],
                [Wire(0), Wire(1), Wire(2)],
                2,
                constants,
            )
            .map(|_| ()),
            _ => {
                use crate::block_v2::machine::verifier::periodic::{self, Source};
                struct Column(std::cell::Cell<usize>);
                impl Source for Column {
                    fn count(&self) -> usize {
                        1
                    }
                    fn len(&self, i: usize) -> Option<usize> {
                        (i == 0).then_some(4)
                    }
                    fn fill(&self, _: usize, output: &mut [Val]) -> Result<(), CompileError> {
                        self.0.set(self.0.get() + 1);
                        for (index, value) in output.iter_mut().enumerate() {
                            *value = Val::from_usize(index + 1);
                        }
                        Ok(())
                    }
                }
                let source = Column(std::cell::Cell::new(0));
                let mut output = [[Wire(42); 3]; 1];
                let result =
                    periodic::values_into(&mut b, &source, [Wire(0); 3], 2, constants, &mut output);
                assert_eq!(source.0.get(), usize::from(limit >= 4 * scalar));
                assert_eq!(output, [[Wire(42); 3]; 1]);
                result
            }
        };
        assert!(matches!(
            result,
            Err(CompileError::Shape("compiler scratch allowance"))
        ));
        assert_eq!(b.memory.live, 0);
        assert!(b.memory.peak <= limit);
        assert_eq!(b.finish(None).unwrap_err(), ExecutionError::TooLarge);
    }
}

#[test]
fn periodic_source_error_and_unwind_free_storage_before_quota_reuse() {
    use crate::block_v2::machine::{
        compiler_constants::Constants,
        program::Val,
        verifier::periodic::{self, Source},
    };
    struct FailingSource(bool);
    impl Source for FailingSource {
        fn count(&self) -> usize {
            1
        }
        fn len(&self, i: usize) -> Option<usize> {
            (i == 0).then_some(8)
        }
        fn fill(&self, _: usize, _: &mut [Val]) -> Result<(), CompileError> {
            if self.0 {
                panic!("periodic source unwind");
            }
            Err(CompileError::Shape("periodic source error"))
        }
    }
    for unwind in [false, true] {
        let mut b = ScopedProgramBuilder::new(0).unwrap();
        let bytes = 8 * size_of::<Val>();
        b.memory.limit = Some(bytes);
        let mut output = [[Wire(42); 3]; 1];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            periodic::values_into(
                &mut b,
                &FailingSource(unwind),
                [Wire(0); 3],
                3,
                Constants::cpu(),
                &mut output,
            )
        }));
        assert_eq!(result.is_err(), unwind);
        if let Ok(result) = result {
            assert!(result.is_err());
        }
        assert_eq!(output, [[Wire(42); 3]; 1]);
        assert_eq!(b.memory.live, 0);
        assert_eq!(b.memory.peak, bytes);
        assert!(b.resource_failure().is_none());
        b.with_compiler_scratch("reused-periodic-source", 8, 0u64, |_, _| Ok(()))
            .unwrap();
        assert_eq!(b.memory.live, 0);
        assert_eq!(b.memory.peak, bytes);
    }
}

#[test]
fn compiler_constant_consumers_reject_quota_before_cpu_arithmetic() {
    use crate::{
        block_v2::{machine::compiler_constants::Constants, profile},
        proving::{Request, Run, Stage},
    };
    let run = Run::new(
        "compiler storage rejection",
        Request::compatible(),
        profile::public_scope_capabilities(Stage::Preprocessing),
    )
    .unwrap();
    compiler_storage_rejection(Constants::cpu_reported(&run));
    assert!(run.finish(false).unwrap().observations.is_empty());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_compiler_constant_consumers_reject_quota_before_backend_work() {
    use crate::{
        block_v2::{gpu_hash, machine::compiler_constants::Constants, profile, quotient_pcs},
        proving::{Request, Run, Stage},
    };
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(quotient_pcs::gpu_witness_enabled());
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let run = Run::new(
        "compiler storage rejection",
        Request::compatible(),
        profile::public_scope_capabilities(Stage::Preprocessing),
    )
    .unwrap();
    let session = gpu_hash::device::DeviceSession::new().unwrap();
    let baseline = gpu_hash::report("compiler storage baseline").unwrap();
    compiler_storage_rejection(Constants::device(&session, &run));
    let after = gpu_hash::report("compiler storage rejected").unwrap();
    assert_eq!(baseline.allocations, after.allocations);
    assert_eq!(baseline.uploaded_bytes, after.uploaded_bytes);
    assert_eq!(baseline.downloaded_bytes, after.downloaded_bytes);
    assert!(run.finish(false).unwrap().observations.is_empty());
}
