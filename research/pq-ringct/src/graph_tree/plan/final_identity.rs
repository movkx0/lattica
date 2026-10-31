//! Exact immutable source-plan comparison for the owned aggregate consumer.
use super::*;
impl Plan {
    pub(in crate::graph_tree) fn matches_final_inner(&self, inner: &Arc<PlanInner>) -> bool {
        Arc::ptr_eq(&self.0, inner)
    }
}
