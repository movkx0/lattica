//! Concrete, separately declared ownership layers for the complete driver.
//! These aliases fix actual Vec/slot/result backing for the source inventory.
//! They issue no reservation, producer binding, or proof execution authority.
use super::fresh_generation::case_lifetime::CaseOwnerTable;
use crate::execution::{retained_resources::Reservation as Original,
    workflow_resources::{PhaseFailure, Retained, RetainedNative, RetainedOriginal,
        WorkflowError, OuterOwnedError}};
use core::result::Result as Outcome;
use std::cell::RefCell;

/// The complete producer/preissue Result is installed before it is inspected.
/// Consuming its Some value never moves or releases the enclosing slot/table.
pub(crate) type RuntimeTable<'case, T> = CaseOwnerTable<'case, RefCell<Option<T>>>;
pub(crate) mod native;
pub(crate) mod algebra;
pub(crate) mod graph;
pub(crate) mod crypto;
pub(crate) mod final_aggregation;
