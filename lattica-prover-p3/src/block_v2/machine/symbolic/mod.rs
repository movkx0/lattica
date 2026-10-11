//! Explicit-backend symbolic AIR construction. The upstream CPU builder remains
//! the reference implementation. No ambient backend or serialized device state.
// CPU proving retains native symbolic construction as the reference. Trusted-cap
// verification explicitly uses bounded CPU recording. Tests compare both paths.
#![cfg_attr(
    not(any(test, feature = "gpu", feature = "gpu-metal")),
    allow(dead_code)
)]

use super::{compiler_constants::Constants, program::Val, verifier::CompileError};
use crate::block_v2::profile::Challenge;
use p3_air::{
    symbolic::{AirLayout, ConstraintLayout, SymbolicExpression, SymbolicExpressionExt},
    Air, BaseAir,
};
use p3_lookup::{Kind, LogUpGadget, Lookup, LookupProtocol};

mod builder;
mod expression;
mod lookup;
mod normalize;
mod recording;
#[cfg(test)]
mod tests;
pub(crate) mod verifier;
pub use builder::Builder;
#[cfg(test)]
pub(crate) use tests::{conformance, reject_geometry};
type BaseExpr = SymbolicExpression<Val>;
type ExtExpr = SymbolicExpressionExt<Val, Challenge>;
const MAX_NODES: usize = 1 << 17;
/// Additional transient compiler graph/memo space, beyond the existing program
/// and public-hash buffers. Workers reserve it before starting GPU compilation.
pub(crate) const HOST_BYTES: u64 = 192 << 20;
/// Packed lookup backing arrays, names and shared expression Arcs retained by
/// each GPU-prepared AIR. Enforced by the packer's capacity/ownership census.
/// A cached output can overlap another symbolic workspace, so enclosing cache
/// admission must reserve this per entry in addition to `HOST_BYTES` once.
pub(crate) const LOOKUP_RETAINED_HOST_BYTES: u64 = lookup::RETAINED_BYTES as u64;
// Recorded and normalized graphs, retained lookups and root-vector capacity,
// Arc headers, memo/visit tables and traversal allowances. The recorder admits
// its own cumulative requested storage before allocation (64 MiB). A separate
// 64 MiB quota admits normalization scratch and output. Packing has its own
// 64 MiB cumulative quota and retained-output cap. Caller/AIR allocations and
// overlapping retained output lifetimes still need enclosing accounting.
// This is additional transient space, not the existing compiled-program budget.
const _: () = assert!(
    (MAX_NODES as u64) * (4 * (core::mem::size_of::<ExtExpr>() as u64 + 16) + 160) + (1 << 20)
        <= 64 << 20
);

pub(crate) struct Constraints<F: p3_field::ExtensionField<Val> = Challenge> {
    pub base: Vec<BaseExpr>,
    pub extension: Vec<SymbolicExpressionExt<Val, F>>,
    pub order: ConstraintLayout,
}
impl<F: p3_field::ExtensionField<Val>> Constraints<F> {
    /// Base-only AIRs have no extension coefficients to convert. Preserve their
    /// original constraint order while choosing the quotient challenge field.
    pub(crate) fn into_base_only<E: p3_field::ExtensionField<Val>>(
        self,
    ) -> Result<Constraints<E>, CompileError> {
        if !self.extension.is_empty() || !self.order.ext_indices.is_empty() {
            return Err(CompileError::Shape("single-AIR extension constraints"));
        }
        Ok(Constraints {
            base: self.base,
            extension: Vec::new(),
            order: self.order,
        })
    }

    pub fn max_degree(&self) -> usize {
        self.base
            .iter()
            .map(|e| e.degree_multiple())
            .chain(self.extension.iter().map(|e| e.degree_multiple()))
            .max()
            .unwrap_or(0)
    }
}
fn finish(builder: &Builder, constants: Constants<'_>) -> Result<Constraints, CompileError> {
    let storage = normalize::Storage::new(!matches!(constants, Constants::Cpu(None)));
    finish_with_storage(builder, constants, &storage)
}

fn finish_with_storage(
    builder: &Builder,
    constants: Constants<'_>,
    storage: &normalize::Storage,
) -> Result<Constraints, CompileError> {
    normalize::admit(builder, storage)?;
    let mut normalizer = normalize::Normalizer::new(constants, storage);
    Ok(Constraints {
        base: storage.vector(builder.base.len(), |i| normalizer.base(&builder.base[i], 0))?,
        extension: storage.vector(builder.extension.len(), |i| {
            normalizer.extension(&builder.extension[i], 0)
        })?,
        order: ConstraintLayout {
            base_indices: storage.vector(builder.order.base_indices.len(), |i| {
                Ok(builder.order.base_indices[i])
            })?,
            ext_indices: storage.vector(builder.order.ext_indices.len(), |i| {
                Ok(builder.order.ext_indices[i])
            })?,
        },
    })
}
pub(crate) fn uni<A: BaseAir<Val> + Air<Builder>>(
    air: &A,
    constants: Constants<'_>,
) -> Result<Constraints, CompileError> {
    let builder = recording::run(!matches!(constants, Constants::Cpu(None)), || {
        let mut builder = Builder::new(AirLayout::from_air::<Val>(air))?;
        air.eval(&mut builder);
        Ok(builder)
    })?;
    finish(&builder, constants)
}
pub(crate) fn batch<A: BaseAir<Val> + Air<Builder>>(
    air: &A,
    lookups: &[Lookup<Val>],
    constants: Constants<'_>,
) -> Result<Constraints, CompileError> {
    batch_with_layout(
        air,
        AirLayout::from_air::<Val>(air),
        lookups,
        &LogUpGadget::new(),
        constants,
    )
}

pub(crate) fn batch_layout<LG: LookupProtocol>(
    layout: AirLayout,
    lookups: &[Lookup<Val>],
    gadget: &LG,
) -> Result<AirLayout, CompileError> {
    Ok(AirLayout {
        permutation_width: if lookups.is_empty() {
            0
        } else {
            lookups
                .len()
                .checked_add(1)
                .ok_or(CompileError::Shape("symbolic lookup width"))?
        },
        num_permutation_values: usize::from(!lookups.is_empty()),
        num_permutation_challenges: lookups
            .len()
            .checked_mul(gadget.num_challenges())
            .ok_or(CompileError::Shape("symbolic challenge count"))?,
        ..layout
    })
}

pub(crate) fn batch_with_layout<A: BaseAir<Val> + Air<Builder>, LG: LookupProtocol>(
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<Val>],
    gadget: &LG,
    constants: Constants<'_>,
) -> Result<Constraints, CompileError> {
    let layout = batch_layout(layout, lookups, gadget)?;
    let builder = recording::run(!matches!(constants, Constants::Cpu(None)), || {
        let mut builder = Builder::new(layout)?;
        gadget.eval_air_and_lookups(air, &mut builder, lookups);
        Ok(builder)
    })?;
    finish(&builder, constants)
}

pub(crate) fn batch_log_chunks<A: BaseAir<Val>, LG: LookupProtocol>(
    air: &A,
    constraints: &Constraints,
    lookups: &[Lookup<Val>],
    gadget: &LG,
    is_zk: usize,
) -> Result<usize, CompileError> {
    if is_zk > 1 {
        return Err(CompileError::Shape("symbolic hiding degree"));
    }
    let actual = constraints.max_degree();
    let degree = match air.max_constraint_degree() {
        Some(hint) => {
            let hinted = hint.max(
                lookups
                    .iter()
                    .map(|l| gadget.constraint_degree(l))
                    .max()
                    .unwrap_or(0),
            );
            if hinted < actual {
                return Err(CompileError::Shape("symbolic degree hint"));
            }
            hinted
        }
        None => actual,
    };
    // ceil(log2(max(degree + is_zk, 2) - 1)), without overflowing degree+1.
    Ok(log_chunks(if is_zk == 1 {
        degree
    } else {
        degree.saturating_sub(1)
    }))
}
pub(crate) fn lookups<A: BaseAir<Val> + Air<Builder>>(
    air: &A,
    constants: Constants<'_>,
) -> Result<Vec<Lookup<Val>>, CompileError> {
    let builder = recording::run(!matches!(constants, Constants::Cpu(None)), || {
        let mut builder = Builder::new(AirLayout::from_air::<Val>(air))?;
        air.eval(&mut builder);
        Ok(builder)
    })?;
    let storage = normalize::Storage::new(!matches!(constants, Constants::Cpu(None)));
    lookups_from_builder(&builder, constants, &storage)
}

fn lookups_from_builder(
    builder: &Builder,
    constants: Constants<'_>,
    storage: &normalize::Storage,
) -> Result<Vec<Lookup<Val>>, CompileError> {
    normalize::admit(builder, storage)?;
    let mut normalizer = normalize::Normalizer::new(constants, storage);
    let count = builder
        .local
        .len()
        .checked_add(builder.global.len())
        .ok_or(CompileError::Shape("symbolic lookup count"))?;
    let mut result = storage.capacity(count)?;
    // Pinned upstream order: every local interaction precedes every global one.
    for local in &builder.local {
        let mut elements = storage.capacity(local.tuples.len())?;
        let mut multiplicities = storage.capacity(local.tuples.len())?;
        for (fields, count) in &local.tuples {
            elements.push(storage.vector(fields.len(), |i| normalizer.base(&fields[i], 0))?);
            multiplicities.push(normalizer.base(count, 0)?);
        }
        result.push(Lookup {
            kind: Kind::Local,
            elements,
            multiplicities,
            count_weight: 0,
            column: result.len(),
        });
    }
    for global in &builder.global {
        let fields = storage.vector(global.fields.len(), |i| {
            normalizer.base(&global.fields[i], 0)
        })?;
        let count = normalizer.base(&global.count, 0)?;
        result.push(Lookup {
            kind: Kind::Global(storage.string(&global.bus_name)?),
            elements: storage.single(fields)?,
            multiplicities: storage.single(count)?,
            count_weight: global.count_weight,
            column: result.len(),
        });
    }
    Ok(result)
}

#[cfg(test)]
fn pack(lookups: Vec<Lookup<Val>>, max_degree: usize) -> Vec<Lookup<Val>> {
    lookup::pack(lookups, max_degree, false)
        .expect("recorded interactions fit the packing allowance")
        .iter()
        .cloned()
        .collect()
}
pub(crate) fn log_chunks(degree: usize) -> usize {
    // Pinned hiding profile: is_zk=1, so max(degree+1,2)-1=max(degree,1).
    if degree <= 1 {
        0
    } else {
        (usize::BITS - (degree - 1).leading_zeros()) as usize
    }
}

pub(crate) struct Prepared {
    pub lookups: p3_lookup::Lookups<Val>,
    pub constraints: Constraints,
    pub log_chunks: usize,
}

/// Owned lookup metadata can enter the preprocessing cache independently of
/// the constraint graph used to compute its canonical program fingerprint.
pub(crate) struct LookupLayout {
    pub lookups: p3_lookup::Lookups<Val>,
    pub log_chunks: usize,
}
impl Prepared {
    pub(crate) fn into_parts(self) -> (LookupLayout, Constraints) {
        (
            LookupLayout {
                lookups: self.lookups,
                log_chunks: self.log_chunks,
            },
            self.constraints,
        )
    }
}

pub(crate) fn prepare_machine(
    air: &super::MachineAir,
    constants: Constants<'_>,
) -> Result<Prepared, CompileError> {
    match constants {
        Constants::Cpu(run) => Constants::cpu_work(run, || {
            let layout = AirLayout::from_air::<Val>(air);
            let gadget = LogUpGadget::new();
            let lookups = p3_lookup::Lookups::from_air::<Challenge, _>(air);
            let log_chunks =
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                    air, layout, &lookups, 1, &gadget,
                );
            if log_chunks > crate::block_v2::profile::LOG_BLOWUP {
                return Err(CompileError::Shape("symbolic quotient degree"));
            }
            let lookups = lookups.pack_same_bus(&gadget, 1 << log_chunks);
            let (base, extension) =
                p3_batch_stark::symbolic::get_symbolic_constraints::<Val, Challenge, _, _>(
                    air, layout, &lookups, &gadget,
                );
            let order = p3_batch_stark::symbolic::get_constraint_layout::<Val, Challenge, _, _>(
                air, layout, &lookups, &gadget,
            );
            Ok(Prepared {
                lookups,
                constraints: Constraints {
                    base,
                    extension,
                    order,
                },
                log_chunks,
            })
        })?,
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        Constants::Device(..) => {
            let unpacked = lookups(air, constants)?;
            let degree = batch(air, &unpacked, constants)?.max_degree();
            let degree = if let Some(hint) = air.max_constraint_degree() {
                let hinted = unpacked.iter().try_fold(hint, |degree, lookup| {
                    Ok::<_, CompileError>(degree.max(lookup::degree(lookup)?))
                })?;
                if hinted < degree {
                    return Err(CompileError::Shape("symbolic degree hint"));
                }
                hinted
            } else {
                degree
            };
            let log_chunks = log_chunks(degree);
            if log_chunks > crate::block_v2::profile::LOG_BLOWUP {
                return Err(CompileError::Shape("symbolic quotient degree"));
            }
            let lookups = lookup::pack(unpacked, 1 << log_chunks, true)?;
            let constraints = batch(air, &lookups, constants)?;
            Ok(Prepared {
                lookups,
                constraints,
                log_chunks,
            })
        }
    }
}

pub(crate) fn prepare_uni<A>(
    air: &A,
    constants: Constants<'_>,
) -> Result<(Vec<BaseExpr>, usize), CompileError>
where
    A: BaseAir<Val> + Air<Builder> + Air<p3_air::symbolic::SymbolicAirBuilder<Val>>,
{
    match constants {
        Constants::Cpu(run) => Constants::cpu_work(run, || native_uni(air)),
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        Constants::Device(..) => {
            let constraints = uni(air, constants)?;
            if !constraints.extension.is_empty() {
                return Err(CompileError::Unsupported("uni extension constraints"));
            }
            let actual = constraints.max_degree();
            let degree = air.max_constraint_degree().unwrap_or(actual);
            if degree < actual {
                return Err(CompileError::Shape("symbolic degree hint"));
            }
            Ok((constraints.base, log_chunks(degree)))
        }
    }
}
pub(crate) fn native_uni<A>(air: &A) -> (Vec<BaseExpr>, usize)
where
    A: BaseAir<Val> + Air<p3_air::symbolic::SymbolicAirBuilder<Val>>,
{
    let layout = AirLayout::from_air::<Val>(air);
    (
        p3_air::symbolic::get_symbolic_constraints::<Val, A>(air, layout),
        p3_uni_stark::get_log_num_quotient_chunks::<Val, A>(air, layout, 1),
    )
}
