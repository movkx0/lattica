use crate::{err, require, Error, Result};
use lattica_pq_ringct_research::recursive_aggregation::LeafStatement;
use lattica_prover_p3::block_v2::{commitment, machine::program::Val};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

pub const PUBLIC_VALUES: usize = 25;
pub const CONTEXT: usize = 8;
pub const MODE: usize = 16;
pub const LEVEL: usize = 17;
pub const FIRST: usize = 18;
pub const COUNT: usize = 19;
pub const TOTAL: usize = 20;
pub const ROOT: usize = 21;
pub const BATCH_MODE: u64 = 0x4241_5443;
pub const LEAF_DOMAIN: u64 = 0x4c50_5142_4c46_0001;
pub const NODE_DOMAIN: u64 = 0x4c50_5142_4e44_0001;

struct PlanInner {
    graph_profile: [u8; 32],
    batch_profile: [u8; 32],
    context: [u8; 32],
    total: u32,
}

/// A caller-supplied trusted graph profile and one exact ordered batch scope.
/// Construction does not register a consensus profile or authenticate ledger
/// state. Clones share the same scope; separately created plans cannot mix keys.
#[derive(Clone)]
pub struct Plan(Arc<PlanInner>);
impl Plan {
    pub fn new(graph_profile: [u8; 32], context: [u8; 32], total: u32) -> Result<Self> {
        require(total != 0, "empty transaction batch")?;
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/ordered-batch/profile/v1");
        hash.update(graph_profile);
        hash.update((PUBLIC_VALUES as u32).to_le_bytes());
        hash.update(BATCH_MODE.to_le_bytes());
        hash.update(LEAF_DOMAIN.to_le_bytes());
        hash.update(NODE_DOMAIN.to_le_bytes());
        Ok(Self(Arc::new(PlanInner {
            graph_profile,
            batch_profile: hash.finalize().into(),
            context,
            total,
        })))
    }
    pub fn graph_profile(&self) -> [u8; 32] {
        self.0.graph_profile
    }
    pub fn batch_profile(&self) -> [u8; 32] {
        self.0.batch_profile
    }
    pub fn context(&self) -> [u8; 32] {
        self.0.context
    }
    pub fn total(&self) -> u32 {
        self.0.total
    }
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn validate_expected(&self, statements: &[LeafStatement]) -> Result<()> {
        require(
            usize::try_from(self.total()).ok() == Some(statements.len()),
            "expected original statement count differs from total",
        )?;
        for statement in statements {
            require(
                statement.profile == self.graph_profile(),
                "expected graph profile mismatch",
            )?;
            require(
                statement.context == self.context(),
                "expected transaction context mismatch",
            )?;
            // Check before any Val::from_u64 conversion: field reduction must
            // never let a noncanonical original digest alias a canonical one.
            require(
                statement.digest.iter().all(|v| *v < commitment::MODULUS),
                "noncanonical expected original statement digest",
            )?;
        }
        Ok(())
    }
    /// Canonical commitment to every original statement in its supplied order.
    /// This native computation is not proof verification.
    pub fn expected_root(&self, statements: &[LeafStatement]) -> Result<[u64; 4]> {
        self.validate_expected(statements)?;
        self.expected_subroot(statements, 0)
    }
    fn expected_subroot(&self, statements: &[LeafStatement], first: u32) -> Result<[u64; 4]> {
        let count = u32::try_from(statements.len()).map_err(err)?;
        let spec = Spec::new(self, first, count)?;
        if count == 1 {
            return leaf_root(&spec, statements[0].digest);
        }
        let split = canonical_left_count(count)?;
        let right_first = first
            .checked_add(split)
            .ok_or_else(|| Error("batch index overflow".into()))?;
        let (left, right) = statements.split_at(usize::try_from(split).map_err(err)?);
        let roots = [
            self.expected_subroot(left, first)?,
            self.expected_subroot(right, right_first)?,
        ];
        node_root(&spec, split, count - split, roots)
    }
    pub(crate) fn expected_public(
        &self,
        statements: &[LeafStatement],
    ) -> Result<[Val; PUBLIC_VALUES]> {
        let root = self.expected_root(statements)?;
        Spec::new(self, 0, self.total())?.public(root)
    }
}

/// Fixed metadata comes only from checked graph positions and canonical merges.
#[derive(Clone)]
pub(crate) struct Spec {
    pub(crate) plan: Plan,
    pub(crate) first: u32,
    pub(crate) count: u32,
}
impl Spec {
    pub(crate) fn new(plan: &Plan, first: u32, count: u32) -> Result<Self> {
        require(count != 0, "empty batch interval")?;
        let end = first
            .checked_add(count)
            .ok_or_else(|| Error("batch interval overflow".into()))?;
        require(end <= plan.total(), "batch interval exceeds total")?;
        Ok(Self {
            plan: plan.clone(),
            first,
            count,
        })
    }
    pub(crate) fn end(&self) -> Result<u32> {
        self.first
            .checked_add(self.count)
            .ok_or_else(|| Error("batch interval overflow".into()))
    }
    pub(crate) fn remaining(&self) -> Result<u32> {
        self.plan
            .total()
            .checked_sub(self.end()?)
            .ok_or_else(|| Error("batch interval exceeds total".into()))
    }
    pub(crate) fn level(&self) -> u32 {
        // count>=1; (count-1) avoids overflowing next_power_of_two at u32::MAX.
        u32::BITS - (self.count - 1).leading_zeros()
    }
    pub(crate) fn complete(&self) -> bool {
        self.first == 0 && self.count == self.plan.total()
    }
    pub(crate) fn merge(left: &Self, right: &Self) -> Result<Self> {
        require(
            left.plan.same_scope(&right.plan),
            "different registered batch scopes",
        )?;
        require(
            left.end()? == right.first,
            "missing, duplicate, overlapping or reordered batch interval",
        )?;
        let count = left
            .count
            .checked_add(right.count)
            .ok_or_else(|| Error("batch count overflow".into()))?;
        require(
            left.count == canonical_left_count(count)?,
            "noncanonical batch split; odd tails must be carried unchanged",
        )?;
        Self::new(&left.plan, left.first, count)
    }
    pub(crate) fn public(&self, root: [u64; 4]) -> Result<[Val; PUBLIC_VALUES]> {
        require(
            root.iter().all(|v| *v < commitment::MODULUS),
            "noncanonical batch root",
        )?;
        let mut public = [Val::ZERO; PUBLIC_VALUES];
        public[..8].copy_from_slice(&words(&self.plan.batch_profile()));
        public[CONTEXT..CONTEXT + 8].copy_from_slice(&words(&self.plan.context()));
        public[MODE] = Val::from_u64(BATCH_MODE);
        public[LEVEL] = Val::from_u32(self.level());
        public[FIRST] = Val::from_u32(self.first);
        public[COUNT] = Val::from_u32(self.count);
        public[TOTAL] = Val::from_u32(self.plan.total());
        public[ROOT..].copy_from_slice(&root.map(Val::from_u64));
        Ok(public)
    }
    pub(crate) fn validate_public(&self, public: &[Val; PUBLIC_VALUES]) -> Result<()> {
        // Compare every metadata field, including context and exact span.
        require(
            public[..ROOT] == self.public([0; 4])?[..ROOT],
            "batch public scope/header mismatch",
        )
    }
}

pub(crate) fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}
pub(crate) fn canonical_left_count(count: u32) -> Result<u32> {
    require(count >= 2, "a merge needs at least two original statements")?;
    Ok(1u32 << (u32::BITS - 1 - (count - 1).leading_zeros()))
}
/// Exact leaf input order: [first, total, statement_digest[0..4]].
/// Profile and context are separately authenticated in the parent public header.
pub(crate) fn leaf_fields(spec: &Spec, digest: [u64; 4]) -> Result<Vec<u64>> {
    require(
        spec.count == 1,
        "graph child must cover one original statement",
    )?;
    require(
        digest.iter().all(|v| *v < commitment::MODULUS),
        "noncanonical original statement digest",
    )?;
    let mut fields = vec![u64::from(spec.first), u64::from(spec.plan.total())];
    fields.extend(digest);
    Ok(fields)
}
pub(crate) fn leaf_root(spec: &Spec, digest: [u64; 4]) -> Result<[u64; 4]> {
    commitment::hash_fields(LEAF_DOMAIN, &leaf_fields(spec, digest)?).map_err(err)
}
/// Exact node metadata order precedes left_root[0..4], then right_root[0..4]:
/// [first, count, total, level, left_count, right_count].
pub(crate) fn node_metadata(spec: &Spec, left_count: u32, right_count: u32) -> Result<[u64; 6]> {
    require(
        left_count == canonical_left_count(spec.count)?
            && left_count.checked_add(right_count) == Some(spec.count),
        "noncanonical child counts",
    )?;
    Ok([
        u64::from(spec.first),
        u64::from(spec.count),
        u64::from(spec.plan.total()),
        u64::from(spec.level()),
        u64::from(left_count),
        u64::from(right_count),
    ])
}
pub(crate) fn node_root(
    spec: &Spec,
    left_count: u32,
    right_count: u32,
    roots: [[u64; 4]; 2],
) -> Result<[u64; 4]> {
    require(
        roots.iter().flatten().all(|v| *v < commitment::MODULUS),
        "noncanonical child batch root",
    )?;
    let mut fields = node_metadata(spec, left_count, right_count)?.to_vec();
    fields.extend(roots[0]);
    fields.extend(roots[1]);
    commitment::hash_fields(NODE_DOMAIN, &fields).map_err(err)
}
