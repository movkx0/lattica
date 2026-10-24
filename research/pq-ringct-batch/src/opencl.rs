//! Serial OpenCL execution of the existing ordered recursive batch relation.
//!
//! Complete source-registered graph keys remain a caller prerequisite. GPU
//! acceleration changes execution only: both child verifiers and all ordered
//! coverage constraints are still emitted by `compile_merge`. A session owns
//! an explicitly bounded engine and must never overlap another GPU prover.
use crate::{require, BatchNode, Child, Error, Plan, Result};
use lattica_pq_ringct_research::{
    opencl::{Limits, Session},
    recursive_aggregation::LeafStatement,
};
use serde_json::{json, Value};
use std::time::Instant;

pub const SCHEMA: &str = "lattica-pq-opencl-recursive-aggregation-v1";

pub struct Aggregator {
    session: Session,
    reports: Vec<Value>,
}

impl Aggregator {
    /// Initialize only after trusted child preparation and external exclusive
    /// host/GPU admission. There is no compatible or CPU fallback mode.
    pub fn start(limits: Limits) -> Result<Self> {
        Ok(Self {
            session: Session::start(limits).map_err(Error)?,
            reports: Vec::new(),
        })
    }

    /// One real parent proof. Owned aggregate children are released during
    /// compilation; registered proving state is consumed before returning.
    pub fn merge(&mut self, children: [Child<'_>; 2]) -> Result<BatchNode> {
        let spans = children.each_ref().map(Child::span);
        let aggregate_children = children
            .iter()
            .filter(|child| matches!(child, Child::Batch(_)))
            .count();
        let started = Instant::now();
        let compiled =
            crate::tree::compile_merge_on_gpu(children, self.session.limits().host_bytes as usize)?;
        let geometry = compiled.geometry()?;
        self.session
            .check_rows(geometry.padded_rows)
            .map_err(Error)?;
        // retained_lde_bytes describes the CPU representation. It is not a
        // claim about GPU peak residency. The bounded engine independently
        // admits every allocation and may reject the actual working set.
        let node = compiled
            .prepare_opencl(&self.session)?
            .prove_opencl(&self.session)?;
        node.key().verify(node.proof())?;
        self.reports.push(json!({
            "child_spans": spans,
            "aggregate_children": aggregate_children,
            "span": node.key().span(),
            "level": node.key().level(),
            "active_rows": geometry.active_rows,
            "padded_rows": geometry.padded_rows,
            "cpu_retained_lde_bytes": geometry.retained_lde_bytes,
            "seconds": started.elapsed().as_secs_f64(),
            "strict_gpu_request": true,
            "native_parent_verification": true,
            "prepared_proving_state_dropped": true,
        }));
        Ok(node)
    }

    /// Pair adjacent children left-to-right and carry each odd tail unchanged.
    /// Validate the whole expected scope before any new proof is attempted.
    pub fn aggregate<'a>(
        &mut self,
        plan: &Plan,
        mut children: Vec<Child<'a>>,
        statements: &[LeafStatement],
    ) -> Result<Child<'a>> {
        plan.validate_expected(statements)?;
        require(
            children.len() == statements.len(),
            "initial graph count differs from expected statement count",
        )?;
        for (index, child) in children.iter().enumerate() {
            require(
                matches!(child, Child::Graph(_))
                    && child.span() == (index as u32, 1)
                    && child.matches_scope(plan),
                "initial children must be complete graphs in consecutive order",
            )?;
        }
        while children.len() > 1 {
            let mut next = Vec::with_capacity(children.len().div_ceil(2));
            let mut current = children.into_iter();
            while let Some(left) = current.next() {
                next.push(match current.next() {
                    Some(right) => Child::Batch(self.merge([left, right])?),
                    None => left,
                });
            }
            children = next;
        }
        let root = children.pop().ok_or_else(|| Error("empty batch".into()))?;
        plan.verify_expected(&root, statements)?;
        Ok(root)
    }

    /// Finish queue work and return observed engine counters. A singleton can
    /// be verified without a merge, but cannot claim GPU aggregation success.
    pub fn finish(self) -> Result<Value> {
        let Self { session, reports } = self;
        let observation = session.finish().map_err(Error)?;
        require(!reports.is_empty(), "no recursive GPU merge was performed")?;
        Ok(json!({
            "schema": SCHEMA,
            "passed": true,
            "merge_count": reports.len(),
            "merges": reports,
            "session": observation,
            "strict_stage_reports_required": true,
            "complete_ledger_transaction_qualified": false,
            "relation_kind": "ordered complete standalone MatRiCT relations",
            "claims": "Execution qualification only; no ledger, transaction-size, total-compute, throughput or cross-vendor performance claim"
        }))
    }
}

/// Ordered aggregation using the caller's explicit CPU or strict OpenCL
/// context. Every merge produces a fresh proof; this API has no proof cache.
pub fn aggregate_with_context<'a>(
    execution: &lattica_pq_ringct_research::execution::ProvingContext,
    plan: &Plan,
    children: Vec<Child<'a>>,
    statements: &[LeafStatement],
) -> Result<(Child<'a>, Vec<Value>)> {
    aggregate_context_impl(execution, plan, children, statements, None)
}

/// Correctness-run variant that checks every aggregate child's altered opening
/// is rejected by its parent's emitted verifier before proving that parent.
/// The budget covers the principal evaluation buffers, not complete process RSS.
pub fn aggregate_with_context_and_witness_checks<'a>(
    execution: &lattica_pq_ringct_research::execution::ProvingContext,
    plan: &Plan,
    children: Vec<Child<'a>>,
    statements: &[LeafStatement],
    evaluation_budget: u64,
) -> Result<(Child<'a>, Vec<Value>)> {
    require(
        evaluation_budget != 0,
        "zero recursive witness evaluation budget",
    )?;
    aggregate_context_impl(
        execution,
        plan,
        children,
        statements,
        Some(evaluation_budget),
    )
}

fn aggregate_context_impl<'a>(
    execution: &lattica_pq_ringct_research::execution::ProvingContext,
    plan: &Plan,
    mut children: Vec<Child<'a>>,
    statements: &[LeafStatement],
    evaluation_budget: Option<u64>,
) -> Result<(Child<'a>, Vec<Value>)> {
    plan.validate_expected(statements)?;
    require(
        children.len() == statements.len(),
        "initial graph count differs from expected statement count",
    )?;
    for (index, child) in children.iter().enumerate() {
        require(
            matches!(child, Child::Graph(_))
                && child.span() == (index as u32, 1)
                && child.matches_scope(plan),
            "initial children must be complete graphs in consecutive order",
        )?;
    }
    let mut reports = Vec::new();
    while children.len() > 1 {
        let mut next = Vec::with_capacity(children.len().div_ceil(2));
        let mut current = children.into_iter();
        while let Some(left) = current.next() {
            let Some(right) = current.next() else {
                next.push(left);
                break;
            };
            let spans = [left.span(), right.span()];
            let aggregate_children = usize::from(matches!(&left, Child::Batch(_)))
                + usize::from(matches!(&right, Child::Batch(_)));
            let started = Instant::now();
            // Reclaim a previous registration before compiling the next large
            // verifier. The context still retains bounded public metadata.
            execution.release_prepared().map_err(Error)?;
            let mut compiled = crate::tree::compile_merge_with_context([left, right], execution)
                .map_err(|error| Error(format!("batch children={spans:?} compilation: {error}")))?;
            let geometry = compiled.geometry()?;
            let mut witness_checks = Vec::new();
            if let Some(budget) = evaluation_budget.filter(|_| aggregate_children > 0) {
                for check in
                    compiled
                        .evaluate_recursive_witness_checks(budget)
                        .map_err(|error| {
                            Error(format!("batch children={spans:?} witness checks: {error}"))
                        })?
                {
                    witness_checks.push(json!({
                        "child_index": check.child_index,
                        "child_first": check.child_first,
                        "child_count": check.child_count,
                        "principal_buffer_bound_bytes": check.principal_buffer_bound_bytes,
                        "evaluation_seconds": check.evaluation_seconds,
                        "altered_opening_rejected": true,
                    }));
                }
            }
            let node = compiled.prove_with_context(execution)?;
            node.key().verify(node.proof())?;
            let strict_gpu = execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired;
            reports.push(json!({
                "child_spans": spans,
                "aggregate_children": aggregate_children,
                "span": node.key().span(),
                "level": node.key().level(),
                "active_rows": geometry.active_rows,
                "padded_rows": geometry.padded_rows,
                "cpu_retained_lde_bytes": geometry.retained_lde_bytes,
                "seconds": started.elapsed().as_secs_f64(),
                "backend": if strict_gpu { "opencl" } else { "cpu" },
                "request_policy": format!("{:?}", execution.policy()),
                "strict_gpu_request": strict_gpu,
                "native_parent_verification": true,
                "cache_policy": "fresh_only",
                "proof_cache_hit": false,
                "prepared_registration_retained_in_context": true,
                "recursive_witness_checks": witness_checks,
            }));
            next.push(Child::Batch(node));
        }
        children = next;
    }
    let root = children.pop().ok_or_else(|| Error("empty batch".into()))?;
    plan.verify_expected(&root, statements)?;
    Ok((root, reports))
}
