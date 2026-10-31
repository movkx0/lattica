//! Read-only confirmation of the already destroyed original source epoch.
use super::*;
use crate::execution::generation_terminal::GenerationError;

impl Session {
    pub(crate) fn confirm_retired_original_planning_context(&self) -> Result<(), GenerationError> {
        if self.runtime_lifetime.is_some() || !self.workflow_transition.retired() {
            return Err(GenerationError::Authority);
        }
        // Only RetiringSourceSession::retire sets this private state after
        // actual drain and shutdown. The later consuming close() takes the
        // inert retired branch and cannot touch any other runtime epoch.
        Ok(())
    }
}
