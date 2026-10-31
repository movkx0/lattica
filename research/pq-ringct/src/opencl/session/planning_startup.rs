//! Consuming cleanup for the original-owned source planning context.
use super::*;
use crate::execution::generation_terminal::GenerationError;

impl Session {
    pub(crate) fn retire_original_planning_context(mut self) -> Result<(), GenerationError> {
        if self.runtime_lifetime.is_some() { return Err(GenerationError::Authority); }
        // close() recognizes an actually retired source Session and cannot
        // drain or shut down a later owned native/outer runtime in that case.
        self.close().map_err(|_| GenerationError::Shutdown)?;
        if !self.closed { return Err(GenerationError::Shutdown); }
        Ok(())
    }
}
