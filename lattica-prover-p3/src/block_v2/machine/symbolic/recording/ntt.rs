//! Read-only source accounting for the concrete ntt recorder.
//! No caller allowance, reservation, AIR callback or reset enters this module.
use super::*;

pub(in crate::block_v2::machine::symbolic) struct SourceRecordingCensus {
    pub requested_host_bytes: usize,
    pub constraint_limit: usize,
}

pub(in crate::block_v2::machine::symbolic) fn capture() -> Result<SourceRecordingCensus, CompileError> {
    check()?;
    STATE.with(|state| {
        let state = state.borrow();
        let state = state.as_ref().ok_or_else(error)?;
        if state.failed || state.limit != HOST_BYTES || state.bytes == 0
            || state.bytes > HOST_BYTES || state.depth > MAX_DEPTH
        { return Err(error()); }
        Ok(SourceRecordingCensus { requested_host_bytes: state.bytes, constraint_limit: MAX_NODES })
    })
}
