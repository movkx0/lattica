//! Retained fixed-budget recorder scope for the closed research AIR caller.
//! No callback or caller-supplied allowance enters this module.
use super::*;

pub(in crate::block_v2::machine::symbolic) struct RetainedScope {
    // The original Scope owns exactly the same TLS state and failure cleanup.
    _scope: Scope,
    _thread: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl RetainedScope {
    pub(in crate::block_v2::machine::symbolic) fn begin() -> Result<Self, CompileError> {
        if STATE.with(|state| state.borrow().is_some()) {
            reject();
            return Err(error());
        }
        STATE.with(|state| {
            *state.borrow_mut() = Some(State {
                limit: HOST_BYTES,
                bytes: 0,
                allocations: 0,
                arc_nodes: 0,
                depth: 0,
                failed: false,
            })
        });
        Ok(Self {
            _scope: Scope { report: true },
            _thread: core::marker::PhantomData,
        })
    }

    pub(in crate::block_v2::machine::symbolic) fn check(&self) -> Result<(), CompileError> {
        check()
    }
}
