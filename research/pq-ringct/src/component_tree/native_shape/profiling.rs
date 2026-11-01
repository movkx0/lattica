//! CPU metadata timings only. No transaction generation, proving or admission.
use super::CompileError;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub(crate) struct Statistics {
    pub preflight_ns: u128,
    pub key_ns: u128,
    pub lookup_ns: u128,
    pub periodic_ns: u128,
    pub symbolic_ns: u128,
    pub lowering_ns: u128,
    pub finalization_ns: u128,
}
pub(super) enum Phase {
    Preflight,
    Key,
    Lookup,
    Periodic,
    Symbolic,
}
#[derive(Clone, Copy, Default)]
struct State {
    totals: Statistics,
    detail: lattica_prover_p3::block_v2::machine::verifier::uni::shape::NativeLoweringTimings,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
pub(crate) struct Scope {
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub(crate) fn begin() -> Result<Self, CompileError> {
        STATE.with(|s| {
            let mut state = s.borrow_mut();
            if state.is_some() {
                return Err(CompileError::ResourceAdmission(
                    "native profiling scope busy",
                ));
            }
            *state = Some(State::default());
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    pub(crate) fn lowering(
        &self,
    ) -> lattica_prover_p3::block_v2::machine::verifier::uni::shape::NativeLoweringTimings {
        STATE.with(|s| s.borrow().unwrap().detail)
    }
    pub(crate) fn statistics(&self) -> Statistics {
        STATE.with(|s| s.borrow().unwrap().totals)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        STATE.with(|s| *s.borrow_mut() = None);
    }
}
pub(super) fn enabled() -> bool {
    STATE.with(|s| s.borrow().is_some())
}
pub(super) fn start() -> Option<Instant> {
    enabled().then(Instant::now)
}
pub(super) fn finish(phase: Phase, started: Option<Instant>) {
    if let Some(started) = started {
        let elapsed = started.elapsed().as_nanos();
        STATE.with(|s| {
            if let Some(s) = s.borrow_mut().as_mut() {
                let s = &mut s.totals;
                let field = match phase {
                    Phase::Preflight => &mut s.preflight_ns,
                    Phase::Key => &mut s.key_ns,
                    Phase::Lookup => &mut s.lookup_ns,
                    Phase::Periodic => &mut s.periodic_ns,
                    Phase::Symbolic => &mut s.symbolic_ns,
                };
                *field = field
                    .checked_add(elapsed)
                    .expect("bounded native profile duration");
            }
        });
    }
}
pub(super) fn measured<T>(phase: Phase, f: impl FnOnce() -> T) -> T {
    let start = start();
    let result = f();
    finish(phase, start);
    result
}
pub(super) fn compiler(
    t: lattica_prover_p3::block_v2::machine::verifier::uni::shape::NativeMetadataTimings,
) {
    STATE.with(|s| {
        if let Some(s) = s.borrow_mut().as_mut() {
            macro_rules! add { ($($f:ident),+) => { $(s.detail.$f += t.detail.$f;)+ }; }
            add!(
                setup_ns,
                pcs_ns,
                pcs_setup_ns,
                pcs_query_ns,
                pcs_opening_ns,
                pcs_reduction_ns,
                pcs_folding_ns,
                selectors_ns,
                periodic_ns,
                periodic_specialization_ns,
                periodic_interpolation_ns,
                periodic_emission_ns,
                quotient_ns,
                constraints_ns
            );
            let s = &mut s.totals;
            s.symbolic_ns += t.symbolic_ns;
            s.lowering_ns += t.lowering_ns;
            s.finalization_ns += t.finalization_ns;
        }
    });
}
// The profiler is opened only by the bounded CPU qualification; no extra
// retained graph, descriptor or production cache owner is introduced.
const _: () = assert!(8 * core::mem::size_of::<State>() <= 4096);
#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
