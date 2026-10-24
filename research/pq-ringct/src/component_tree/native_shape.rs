//! Closed, counts-only native compiler planning. No proof or registration
//! object escapes, and no production path is enabled by these measurements.
use crate::{
    aes_lane_air::{self, AesLaneAir},
    graph_crypto::NativeRetentionShape,
    shake_air::{
        self,
        lane::{
            self,
            batch::{BatchShakeAir, ShakeSegmentAir},
            LaneShakeAir,
        },
    },
    sparse_air::{self, SparseAir},
    transcript_air::{self, PartKind, TranscriptAir},
    uniform_air::{self, UniformAir},
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ConstructionLimits, Val, Wire, MAX_WIRES},
        verifier::{
            uni::{
                self, shape::NativeCoreCounts, BoundedSymbolicAllowance, BoundedSymbolicBuilder,
            },
            CompileError,
        },
    },
    profile,
};
use p3_air::{Air, AirBuilder, BaseAir};

pub mod framing;
pub mod unchanged;

/// Public descriptors of exactly the trusted implementations audited below.
/// In particular this is not an arbitrary AIR/callback interface.
#[derive(Clone, Copy, Debug)]
pub enum NativeDescriptor<'a> {
    Aes {
        descriptor: aes_lane_air::Descriptor,
        first: usize,
        count: usize,
    },
    Shake {
        descriptor: shake_air::Descriptor,
        first: usize,
        count: usize,
    },
    Transcript(&'a [PartKind]),
    Sparse(sparse_air::Kind),
    Uniform(uniform_air::Kind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeGeometry {
    pub width: usize,
    pub height: usize,
    pub public_values: usize,
    pub periodic_columns: usize,
    pub maximum_period: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePlanningStorage {
    pub geometry: NativeGeometry,
    pub symbolic_workspace_bytes: usize,
    pub symbolic_retained_bytes: usize,
    pub template_retained_bytes: usize,
    pub template_construction_bytes: usize,
    pub descriptor_and_periodic_bytes: usize,
    pub callback_and_helper_bytes: usize,
    pub input_backing_bytes: usize,
    pub returned_wire_bytes: usize,
    pub auxiliary_peak_bytes: usize,
    pub total_requested_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCoreBound {
    pub counts: NativeCoreCounts,
    pub storage: NativePlanningStorage,
}

/// Source-audited extra storage for closed native implementations in this
/// module and its children. This is not a caller-selected AIR allowance.
/// Values describe logical backing; the common preflight charges capacity
/// and growth overlap before any owned descriptor or callback is constructed.
struct ClosedNativeAllocations {
    owned_backing_bytes: usize,
    construction_extra_bytes: usize,
    callback_expressions: usize,
    callback_variables: usize,
    inline_air_bytes: usize,
}

fn add(a: usize, b: usize) -> Result<usize, CompileError> {
    a.checked_add(b).ok_or(CompileError::ResourceAdmission(
        "native planner size overflow",
    ))
}
fn mul(a: usize, b: usize) -> Result<usize, CompileError> {
    a.checked_mul(b).ok_or(CompileError::ResourceAdmission(
        "native planner size overflow",
    ))
}
fn bytes<T>(count: usize) -> Result<usize, CompileError> {
    mul(count, size_of::<T>())
}

impl NativeDescriptor<'_> {
    fn aes(self) -> Result<AesLaneAir, CompileError> {
        let Self::Aes {
            descriptor,
            first,
            count,
        } = self
        else {
            return Err(CompileError::Shape("native planner AES family"));
        };
        if count > 64 {
            return Err(CompileError::Shape(
                "native planner AES selected batch limit",
            ));
        }
        AesLaneAir::segment(descriptor, first, count)
            .map_err(|_| CompileError::Shape("native planner AES descriptor"))
    }

    fn shake(self) -> Result<ShakeSegmentAir, CompileError> {
        let Self::Shake {
            descriptor,
            first,
            count,
        } = self
        else {
            return Err(CompileError::Shape("native planner SHAKE family"));
        };
        // Both constructors are allocation-free and validate all descriptors
        // before arithmetic-derived bounds are used. This is phase selection,
        // never a retry after proof/compilation execution.
        if count == 1 {
            LaneShakeAir::new(descriptor, first)
                .map(ShakeSegmentAir::Single)
                .map_err(|_| CompileError::Shape("native planner SHAKE descriptor"))
        } else {
            BatchShakeAir::full_absorb(descriptor, first, count)
                .or_else(|_| BatchShakeAir::full_squeeze(descriptor, first, count))
                .map(ShakeSegmentAir::Batch)
                .map_err(|_| CompileError::Shape("native planner SHAKE descriptor"))
        }
    }

    /// Allocation-free geometry from closed source, before building any owned
    /// transcript parts/events, periodic columns, template or compiler.
    pub fn geometry(self) -> Result<NativeGeometry, CompileError> {
        let result = match self {
            Self::Aes { .. } => {
                let air = self.aes()?;
                NativeGeometry {
                    width: air.width(),
                    height: air.height,
                    public_values: aes_lane_air::PUBLIC_VALUES,
                    periodic_columns: aes_lane_air::PERIODIC_COLUMNS,
                    maximum_period: aes_lane_air::SCHEDULE_PERIOD,
                }
            }
            Self::Shake { .. } => {
                let air = self.shake()?;
                NativeGeometry {
                    width: air.width(),
                    height: air.height(),
                    public_values: shake_air::PUBLIC_VALUES,
                    periodic_columns: lane::PERIODIC_COLUMNS,
                    maximum_period: lane::SCHEDULE_PERIOD,
                }
            }
            Self::Transcript(parts) => {
                if parts.is_empty() || parts.len() > 256 {
                    return Err(CompileError::Shape("native planner transcript parts"));
                }
                // TranscriptAir's Event has three usize fields and each
                // transition contributes two columns. The final transition
                // to inactive class3 always exists. No witness is inspected.
                let events = 1 + parts.windows(2).filter(|p| p[0] != p[1]).count();
                NativeGeometry {
                    width: 101 + 2 * events + 3 * shake_air::POSEIDON_WIDTH,
                    height: parts.len().next_power_of_two() * transcript_air::ROWS_PER_PART,
                    public_values: transcript_air::PUBLIC_VALUES,
                    periodic_columns: 4,
                    maximum_period: transcript_air::ROWS_PER_PART,
                }
            }
            Self::Sparse(kind) => {
                let air = SparseAir::new(kind);
                NativeGeometry {
                    width: air.width(),
                    height: sparse_air::HEIGHT,
                    public_values: sparse_air::PUBLIC_VALUES,
                    periodic_columns: 4 + 6 + 8 + 64,
                    maximum_period: sparse_air::HEIGHT,
                }
            }
            Self::Uniform(kind) => {
                let air = UniformAir::new(kind);
                NativeGeometry {
                    width: air.width(),
                    height: air.height(),
                    public_values: 8,
                    periodic_columns: 2,
                    maximum_period: air.height(),
                }
            }
        };
        if !(1..=1024).contains(&result.width)
            || result.public_values > 216
            || !(8..=1 << 24).contains(&result.height)
            || !result.height.is_power_of_two()
            || result.periodic_columns > 128
            || result.maximum_period > 65536
            || result.maximum_period > result.height
        {
            return Err(CompileError::Shape("native planner closed geometry"));
        }
        Ok(result)
    }
}

impl NativePlanningStorage {
    pub fn for_descriptor(
        descriptor: NativeDescriptor<'_>,
        construction: ConstructionLimits,
    ) -> Result<Self, CompileError> {
        let geometry = descriptor.geometry()?;
        let parts = match descriptor {
            NativeDescriptor::Transcript(p) => p.len(),
            _ => 0,
        };
        let descriptor_buffers = mul(parts, add(size_of::<PartKind>(), 3 * size_of::<usize>())?)?;
        Self::for_closed_source(
            geometry,
            ClosedNativeAllocations {
                owned_backing_bytes: descriptor_buffers,
                construction_extra_bytes: 0,
                // SHAKE47, Sparse104, Transcript32, AES31+4 and Uniform2
                // expression Vec payloads; at most216 cloned public/periodic Vars.
                callback_expressions: 128,
                callback_variables: 216,
                inline_air_bytes: size_of::<TranscriptAir>()
                    + size_of::<ShakeSegmentAir>()
                    + size_of::<SparseAir>()
                    + size_of::<AesLaneAir>()
                    + size_of::<UniformAir>(),
            },
            construction,
        )
    }

    fn for_closed_source(
        geometry: NativeGeometry,
        source: ClosedNativeAllocations,
        construction: ConstructionLimits,
    ) -> Result<Self, CompileError> {
        if !(1..=1024).contains(&geometry.width)
            || geometry.public_values > 384
            || !(8..=1 << 24).contains(&geometry.height)
            || !geometry.height.is_power_of_two()
            || geometry.periodic_columns > 256
            || !geometry.maximum_period.is_power_of_two()
            || geometry.maximum_period > 65536
            || geometry.maximum_period > geometry.height
        {
            return Err(CompileError::Shape("native planner closed source geometry"));
        }
        if construction.max_requested_program_bytes == 0
            || construction.max_wires > MAX_WIRES
            || construction.max_input_values > construction.max_wires
        {
            return Err(CompileError::Shape("native planner construction geometry"));
        }
        if !(cfg!(all(not(debug_assertions), target_arch = "x86_64"))
            && size_of::<Val>() == 8
            && size_of::<usize>() == 8
            && profile::LOG_BLOWUP == 4
            && profile::CAP_HEIGHT == 6
            && profile::NUM_QUERIES == 128
            && profile::NUM_RANDOM_CODEWORDS == 4)
        {
            return Err(CompileError::Unsupported(
                "native planner pinned storage profile",
            ));
        }
        let retention = NativeRetentionShape::for_planner(geometry.width, geometry.height)
            .map_err(|_| CompileError::Shape("native planner retained geometry"))?;
        let template_retained_bytes = retention.retained_bytes();
        // The private core template constructor only uses exact iterators and
        // repeated vec initialization. Double its complete allowed backing to
        // cover source clones/growth overlap; widths[3] belongs to helpers.
        let template_construction_bytes = mul(2, template_retained_bytes)?;
        let symbolic = BoundedSymbolicAllowance::REQUIRED;
        let input_backing_bytes = bytes::<Val>(mul(2, construction.max_input_values)?)?;
        let returned_wire_bytes = bytes::<Wire>(construction.max_input_values)?;

        // Every schedule column is bounded by this period. Factor4 covers
        // capacity and growth overlap, including Sparse's appended columns and
        // Transcript's replacement two-entry even-period column.
        let periodic = add(
            bytes::<Val>(mul(geometry.periodic_columns, geometry.maximum_period)?)?,
            bytes::<Vec<Val>>(geometry.periodic_columns)?,
        )?;
        let descriptor_and_periodic_bytes = add(
            mul(
                4,
                add(
                    add(periodic, source.owned_backing_bytes)?,
                    source.construction_extra_bytes,
                )?,
            )?,
            source.inline_air_bytes,
        )?;

        type B = BoundedSymbolicBuilder;
        type E = <B as AirBuilder>::Expr;
        type V = <B as AirBuilder>::Var;
        // Symbolic Arc children/windows are already in the recorder quotas;
        // these are only the closed callback's own temporary Vec backings.
        let callbacks = mul(
            4,
            add(
                bytes::<E>(source.callback_expressions)?,
                bytes::<V>(source.callback_variables)?,
            )?,
        )?;
        // BaseAir's default main_next_row_columns returns width usize values.
        // Private template widths[3], quotient Vec headers, transcript/bit
        // vectors and scalar CPU folding constants are separate helpers.
        let helper = [
            bytes::<usize>(mul(4, add(geometry.width, 34)?)?)?,
            bytes::<Vec<[Wire; 3]>>(4 * 32)?,
            bytes::<Wire>(4 * (4 + 8 + 64))?,
            bytes::<Val>(4 * (4 * 8 + 4 * 8 + 22))?,
            bytes::<Vec<Val>>(4 * 3)?,
        ]
        .into_iter()
        .try_fold(callbacks, add)?;
        let auxiliary_peak_bytes = [
            symbolic.workspace_bytes,
            symbolic.retained_graph_bytes,
            template_construction_bytes,
            descriptor_and_periodic_bytes,
            helper,
            input_backing_bytes,
            returned_wire_bytes,
        ]
        .into_iter()
        .try_fold(0, add)?;
        Ok(Self {
            geometry,
            symbolic_workspace_bytes: symbolic.workspace_bytes,
            symbolic_retained_bytes: symbolic.retained_graph_bytes,
            template_retained_bytes,
            template_construction_bytes,
            descriptor_and_periodic_bytes,
            callback_and_helper_bytes: helper,
            input_backing_bytes,
            returned_wire_bytes,
            auxiliary_peak_bytes,
            total_requested_bytes: add(
                construction.max_requested_program_bytes,
                auxiliary_peak_bytes,
            )?,
        })
    }
}

fn compile<A>(
    air: &A,
    storage: NativePlanningStorage,
    construction: ConstructionLimits,
) -> Result<NativeCoreBound, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    let g = storage.geometry;
    if air.width() != g.width
        || air.num_public_values() != g.public_values
        || air.num_periodic_columns() != g.periodic_columns
    {
        return Err(CompileError::Shape("native planner AIR source drift"));
    }
    let columns = air.periodic_columns();
    if columns.len() != g.periodic_columns
        || columns
            .iter()
            .any(|c| !c.len().is_power_of_two() || c.len() > g.maximum_period)
    {
        return Err(CompileError::Shape("native planner periodic source drift"));
    }
    let counts = uni::shape::verifier_core_counts(
        air,
        g.height,
        &columns,
        construction,
        BoundedSymbolicAllowance::REQUIRED,
    )?;
    Ok(NativeCoreBound { counts, storage })
}

/// Complete allocation-free public preflight precedes all planner-owned AIR,
/// periodic/template/symbolic/compiler allocations. No real proof is executed.
pub fn native_core_bound(
    descriptor: NativeDescriptor<'_>,
    construction: ConstructionLimits,
    auxiliary_host_allowance: usize,
) -> Result<NativeCoreBound, CompileError> {
    let storage = NativePlanningStorage::for_descriptor(descriptor, construction)?;
    if storage.auxiliary_peak_bytes > auxiliary_host_allowance {
        return Err(CompileError::ResourceAdmission(
            "native planner auxiliary allowance",
        ));
    }
    match descriptor {
        NativeDescriptor::Aes { .. } => compile(&descriptor.aes()?, storage, construction),
        NativeDescriptor::Shake { .. } => compile(&descriptor.shake()?, storage, construction),
        NativeDescriptor::Transcript(parts) => {
            let air = TranscriptAir::new(parts.to_vec())
                .map_err(|_| CompileError::Shape("native planner transcript construction"))?;
            compile(&air, storage, construction)
        }
        NativeDescriptor::Sparse(kind) => compile(&SparseAir::new(kind), storage, construction),
        NativeDescriptor::Uniform(kind) => compile(&UniformAir::new(kind), storage, construction),
    }
}

#[cfg(test)]
mod tests;
