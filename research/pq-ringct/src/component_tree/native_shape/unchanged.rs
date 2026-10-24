//! Closed planning of the native families unchanged by paired SHAKE.
//!
//! These are counts-only compiler prerequisites. Geometry and all owned AIR,
//! periodic-table and callback backing are bounded before any such allocation.
//! No proof, registration, receipt or dispatch authority escapes this module.

use super::{
    add, bytes, compile, mul, ClosedNativeAllocations, CompileError, ConstructionLimits,
    NativeCoreBound, NativeGeometry, NativePlanningStorage, Val,
};
use crate::{
    affine_air::{self, AffineAir},
    g_bound_air::{self, GBoundAir},
    graph_proofs::ComponentKind,
    linear_map_air::LinearMapAir,
    ntt_air::NttAir,
    permutation_air::{self, PermutationAir},
    poly_air::MulAir,
    proof_air::{self, ProofAir},
    statement_air::{self, StatementAir},
};
use core::mem::size_of;
use p3_air::BaseAir;

#[derive(Clone, Copy, Debug)]
pub enum OtherNativeDescriptor<'a> {
    Statement {
        setup_seed: [u8; 32],
    },
    PrivateProof,
    Algebra {
        kind: &'a ComponentKind,
        count: usize,
    },
}

fn count_at_most(count: usize, maximum: usize) -> Result<(), CompileError> {
    if count == 0 || count > maximum {
        return Err(CompileError::Shape("unchanged native selected batch limit"));
    }
    Ok(())
}

fn geometry<A: BaseAir<Val>>(
    air: &A,
    height: usize,
    publics: usize,
    periodic: usize,
    maximum_period: usize,
) -> Result<NativeGeometry, CompileError> {
    if air.num_public_values() != publics || air.num_periodic_columns() != periodic {
        return Err(CompileError::Shape("unchanged native AIR source drift"));
    }
    Ok(NativeGeometry {
        width: air.width(),
        height,
        public_values: publics,
        periodic_columns: periodic,
        maximum_period,
    })
}

impl OtherNativeDescriptor<'_> {
    /// Uses only fixed-size constructors, immutable descriptor inspection and
    /// checked arithmetic. In particular, this does not clone a linear map.
    pub fn geometry(self) -> Result<NativeGeometry, CompileError> {
        self.source().map(|(geometry, _)| geometry)
    }

    fn source(self) -> Result<(NativeGeometry, ClosedNativeAllocations), CompileError> {
        // Scalar default permutations own three constant Vecs. Statement
        // bundle initialization constructs one twice; Affine constructs one.
        // This is separate from the stack-only Poseidon AIR callback and the
        // common compiler's scalar folding helpers.
        let scalar_poseidon = add(bytes::<Val>(4 * 8 + 4 * 8 + 22)?, bytes::<Vec<Val>>(3)?)?;
        let (geometry, owned, extra, expressions, inline) = match self {
            Self::Statement { setup_seed } => (
                geometry(
                    &StatementAir { setup_seed },
                    statement_air::HEIGHT,
                    8,
                    2,
                    64,
                )?,
                0,
                mul(2, scalar_poseidon)?,
                4 * 32,
                size_of::<StatementAir>(),
            ),
            Self::PrivateProof => (
                geometry(&ProofAir, proof_air::HEIGHT, 4, 3, 64)?,
                0,
                0,
                8 + 4 * 32 + 60,
                size_of::<ProofAir>(),
            ),
            Self::Algebra { kind, count } => match kind {
                ComponentKind::Affine { kind, modulus } => {
                    count_at_most(count, 64)?;
                    let air = AffineAir::new(*kind, *modulus, count)
                        .map_err(|_| CompileError::Shape("unchanged native affine descriptor"))?;
                    (
                        geometry(&air, air.height(), 4, 9, affine_air::ROWS_PER_POLYNOMIAL)?,
                        0,
                        scalar_poseidon,
                        8 * 32,
                        size_of::<AffineAir>(),
                    )
                }
                ComponentKind::Ntt { modulus } => {
                    count_at_most(count, 32)?;
                    let air = NttAir::new(*modulus, count)
                        .map_err(|_| CompileError::Shape("unchanged native NTT descriptor"))?;
                    (
                        geometry(&air, air.height, 8 * count, 9 + 2 * count, air.height)?,
                        0,
                        // metadata holds 768 Step{usize,usize,u64,u64} values
                        // alongside its full periodic table on pinned x86_64.
                        mul(768, add(bytes::<usize>(2)?, bytes::<u64>(2)?)?)?,
                        4 * 4 + 6 * 32,
                        size_of::<NttAir>(),
                    )
                }
                ComponentKind::Mul { modulus } => {
                    count_at_most(count, 32)?;
                    let air = MulAir::new(*modulus, count)
                        .map_err(|_| CompileError::Shape("unchanged native multiply descriptor"))?;
                    (
                        geometry(&air, air.height, 12 * count, 21 + count, air.height)?,
                        0,
                        0,
                        5 * 32,
                        size_of::<MulAir>(),
                    )
                }
                ComponentKind::GBound { bound } => {
                    count_at_most(count, 1)?;
                    let air = GBoundAir::new(*bound)
                        .map_err(|_| CompileError::Shape("unchanged native G-bound descriptor"))?;
                    (
                        geometry(
                            &air,
                            g_bound_air::HEIGHT,
                            8,
                            39,
                            g_bound_air::SCHEDULE_PERIOD,
                        )?,
                        0,
                        0,
                        2 * 8 + 4 * 24,
                        size_of::<GBoundAir>(),
                    )
                }
                ComponentKind::Permutation { kind } => {
                    count_at_most(count, 1)?;
                    (
                        geometry(
                            &PermutationAir::new(*kind),
                            permutation_air::HEIGHT,
                            8,
                            134,
                            permutation_air::HEIGHT,
                        )?,
                        0,
                        0,
                        8 * 28,
                        size_of::<PermutationAir>(),
                    )
                }
                ComponentKind::LinearMap { descriptor } => {
                    count_at_most(count, 1)?;
                    let layout = descriptor.planning_layout().map_err(|_| {
                        CompileError::Shape("unchanged native linear-map descriptor")
                    })?;
                    if layout.periodic_columns > 104 || layout.height > 2048 {
                        return Err(CompileError::Shape(
                            "unchanged native linear-map source drift",
                        ));
                    }
                    (
                        NativeGeometry {
                            width: layout.width,
                            height: layout.height,
                            public_values: layout.public_values,
                            periodic_columns: layout.periodic_columns,
                            maximum_period: layout.height,
                        },
                        layout.clone_backing_bytes,
                        0,
                        8 * 32,
                        size_of::<LinearMapAir>(),
                    )
                }
                ComponentKind::External => {
                    return Err(CompileError::Unsupported(
                        "unchanged native external family",
                    ));
                }
            },
        };
        if !(1..=1024).contains(&geometry.width)
            || !(8..=1 << 24).contains(&geometry.height)
            || !geometry.height.is_power_of_two()
            || geometry.public_values > 384
            || geometry.periodic_columns > 134
            || !geometry.maximum_period.is_power_of_two()
            || geometry.maximum_period > 65536
            || geometry.maximum_period > geometry.height
        {
            return Err(CompileError::Shape("unchanged native closed geometry"));
        }
        Ok((
            geometry,
            ClosedNativeAllocations {
                owned_backing_bytes: owned,
                construction_extra_bytes: extra,
                // Conservative sums of the explicit callback Vec lengths.
                // Symbolic expression/Arc storage is separately recorder-bound.
                callback_expressions: expressions,
                callback_variables: add(geometry.public_values, geometry.periodic_columns)?,
                inline_air_bytes: inline,
            },
        ))
    }

    fn storage(
        self,
        construction: ConstructionLimits,
    ) -> Result<NativePlanningStorage, CompileError> {
        let (geometry, source) = self.source()?;
        NativePlanningStorage::for_closed_source(geometry, source, construction)
    }
}

/// Admit source-owned planning storage before constructing an owned AIR or
/// allocating periodic columns; compiler storage has its own enforced limit.
/// This never executes a proof or grants production dispatch permission.
pub fn other_native_core_bound(
    descriptor: OtherNativeDescriptor<'_>,
    construction: ConstructionLimits,
    auxiliary_allowance: usize,
) -> Result<NativeCoreBound, CompileError> {
    let storage = descriptor.storage(construction)?;
    if storage.auxiliary_peak_bytes > auxiliary_allowance {
        return Err(CompileError::ResourceAdmission(
            "unchanged native auxiliary allowance",
        ));
    }
    match descriptor {
        OtherNativeDescriptor::Statement { setup_seed } => {
            compile(&StatementAir { setup_seed }, storage, construction)
        }
        OtherNativeDescriptor::PrivateProof => compile(&ProofAir, storage, construction),
        OtherNativeDescriptor::Algebra { kind, count } => match kind {
            ComponentKind::Affine { kind, modulus } => {
                let air = AffineAir::new(*kind, *modulus, count)
                    .map_err(|_| CompileError::Shape("unchanged native affine construction"))?;
                compile(&air, storage, construction)
            }
            ComponentKind::Ntt { modulus } => {
                let air = NttAir::new(*modulus, count)
                    .map_err(|_| CompileError::Shape("unchanged native NTT construction"))?;
                compile(&air, storage, construction)
            }
            ComponentKind::Mul { modulus } => {
                let air = MulAir::new(*modulus, count)
                    .map_err(|_| CompileError::Shape("unchanged native multiply construction"))?;
                compile(&air, storage, construction)
            }
            ComponentKind::GBound { bound } => {
                let air = GBoundAir::new(*bound)
                    .map_err(|_| CompileError::Shape("unchanged native G-bound construction"))?;
                compile(&air, storage, construction)
            }
            ComponentKind::Permutation { kind } => {
                compile(&PermutationAir::new(*kind), storage, construction)
            }
            ComponentKind::LinearMap { descriptor } => {
                // Vec cloning is deliberately after the complete admission.
                let air = LinearMapAir::new(descriptor.clone());
                compile(&air, storage, construction)
            }
            ComponentKind::External => Err(CompileError::Unsupported(
                "unchanged native external family",
            )),
        },
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
