//! A compilation-local arithmetic backend. Only public constants cross the
//! device boundary; neither this backend nor its cache enters a finished program.
use super::{CompileError, Constants, Val};
use crate::block_v2::profile::Challenge;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum FoldOperation {
    Add,
    Mul,
    Inverse,
    CubicMul,
    CubicInverse,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    operation: FoldOperation,
    operands: [u64; 6],
}

impl Key {
    fn slot(self) -> usize {
        // Integer metadata hashing only, never field arithmetic. Full-key
        // equality makes collisions safe; replacement keeps memory bounded.
        self.operands.iter().fold(self.operation as u64, |h, n| {
            h.rotate_left(11).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ n
        }) as usize
            % CACHE_ENTRIES
    }
}

#[derive(Clone, Copy)]
struct Entry {
    key: Key,
    value: Option<[Val; 3]>,
}

const CACHE_ENTRIES: usize = 64;
type Cache = [Option<Entry>; CACHE_ENTRIES];
// Fits alongside periodic staging in the existing 64 KiB public-hash host
// reservation. CPU builders do not allocate this cache.
const _: () = assert!(core::mem::size_of::<Cache>() <= 8192);

pub(crate) struct Folding<'a> {
    constants: Constants<'a>,
    cache: Option<Box<Cache>>,
    failure: Option<CompileError>,
}

impl<'a> Folding<'a> {
    pub(crate) fn new(constants: Constants<'a>) -> Self {
        let cache = match constants {
            Constants::Cpu(_) => None,
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Constants::Device(..) => Some(Box::new([None; CACHE_ENTRIES])),
        };
        Self {
            constants,
            cache,
            failure: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&CompileError> {
        self.failure.as_ref()
    }

    pub(crate) fn fold(
        &mut self,
        operation: FoldOperation,
        a: [Val; 3],
        b: [Val; 3],
    ) -> Option<[Val; 3]> {
        if self.failure.is_some() {
            // Infallible builder calls may continue, but finish rejects before
            // constructing a program. No cache lookup or arithmetic may resume.
            return Some([Val::ZERO; 3]);
        }
        let key = Key {
            operation,
            operands: [a[0], a[1], a[2], b[0], b[1], b[2]].map(|v| v.as_canonical_u64()),
        };
        if let Some(entry) = self.cache.as_ref().and_then(|cache| cache[key.slot()]) {
            if entry.key == key {
                return entry.value;
            }
        }
        match self.constants.fold(operation, a, b) {
            Ok(value) => {
                if let Some(cache) = &mut self.cache {
                    cache[key.slot()] = Some(Entry { key, value });
                }
                value
            }
            Err(error) => {
                self.failure = Some(error);
                Some([Val::ZERO; 3])
            }
        }
    }
}

impl Constants<'_> {
    fn fold(
        self,
        operation: FoldOperation,
        a: [Val; 3],
        b: [Val; 3],
    ) -> Result<Option<[Val; 3]>, CompileError> {
        match self {
            Self::Cpu(run) => Self::cpu_work(run, || {
                let base = |v| Some([v, Val::ZERO, Val::ZERO]);
                let cubic = |v| Challenge::from_basis_coefficients_slice(v).unwrap();
                let coefficients =
                    |v: Challenge| v.as_basis_coefficients_slice().try_into().unwrap();
                match operation {
                    FoldOperation::Add => base(a[0] + b[0]),
                    FoldOperation::Mul => base(a[0] * b[0]),
                    FoldOperation::Inverse => a[0].try_inverse().and_then(base),
                    FoldOperation::CubicMul => Some(coefficients(cubic(&a) * cubic(&b))),
                    FoldOperation::CubicInverse => cubic(&a).try_inverse().map(coefficients),
                }
            }),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Self::Device(session, run) => session
                .compiler_fold(
                    [a[0], a[1], a[2], b[0], b[1], b[2]].map(|v| v.as_canonical_u64()),
                    operation as u32,
                    run,
                )
                .map_err(CompileError::Backend),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::{Backend, Capabilities, Policy, Profile, Request, Run, Stage};

    #[test]
    fn cache_collisions_replace_entries_and_cache_noninvertibility() {
        let run = Run::new(
            "fold_cache_reference",
            Request::compatible(),
            Capabilities::cpu(Profile::BlockV2Cubic, true, true),
        )
        .unwrap();
        let mut folding = Folding::new(Constants::cpu_reported(&run));
        assert!(folding.cache.is_none());
        // Exercise the bounded cache deterministically using the CPU oracle.
        folding.cache = Some(Box::new([None; CACHE_ENTRIES]));
        let first = Key {
            operation: FoldOperation::Add,
            operands: [1, 0, 0, 1, 0, 0],
        };
        let second = (2..10000)
            .map(|v| Key {
                operands: [v, 0, 0, 1, 0, 0],
                ..first
            })
            .find(|key| key.slot() == first.slot())
            .unwrap();
        for key in [first, first, second, second, first] {
            let a = [Val::new(key.operands[0]), Val::ZERO, Val::ZERO];
            let b = [Val::ONE, Val::ZERO, Val::ZERO];
            assert_eq!(
                folding.fold(key.operation, a, b),
                Some([a[0] + Val::ONE, Val::ZERO, Val::ZERO])
            );
        }
        for _ in 0..2 {
            assert_eq!(
                folding.fold(FoldOperation::CubicInverse, [Val::ZERO; 3], [Val::ZERO; 3]),
                None
            );
        }
        let report = run.finish(true).unwrap();
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].completed_calls, 4);
    }

    #[test]
    fn latched_failure_precedes_cache_hits_and_any_new_backend_work() {
        let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
        for stage in Stage::ARITHMETIC {
            capabilities.set(stage, Backend::OpenCl);
        }
        let reject = Run::new(
            "fold_reject",
            Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            },
            capabilities,
        )
        .unwrap();
        let allow = Run::new(
            "fold_allow",
            Request::compatible(),
            Capabilities::cpu(Profile::BlockV2Cubic, true, true),
        )
        .unwrap();
        let mut folding = Folding::new(Constants::cpu_reported(&reject));
        let a = [Val::ONE, Val::ZERO, Val::ZERO];
        folding.fold(FoldOperation::Add, a, a);
        let cause = folding.failure().unwrap().clone();
        // Even if a backend would now succeed and the cache already contains a
        // valid answer, a failed builder cannot resume arithmetic.
        folding.constants = Constants::cpu_reported(&allow);
        let key = Key {
            operation: FoldOperation::Add,
            operands: [1, 0, 0, 1, 0, 0],
        };
        let mut cache = [None; CACHE_ENTRIES];
        cache[key.slot()] = Some(Entry {
            key,
            value: Some([Val::TWO, Val::ZERO, Val::ZERO]),
        });
        folding.cache = Some(Box::new(cache));
        assert_eq!(folding.fold(FoldOperation::Add, a, a), Some([Val::ZERO; 3]));
        folding.fold(FoldOperation::Inverse, a, a);
        assert_eq!(folding.failure(), Some(&cause));
        assert!(allow.finish(false).unwrap().observations.is_empty());
        assert!(reject.finish(false).unwrap().observations.is_empty());
    }
}
