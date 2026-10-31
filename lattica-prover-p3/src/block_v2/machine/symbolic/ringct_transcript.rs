//! Source-fixed recorder bridge. No AIR callback, dispatch, numeric allowance
//! or detached recording constructor is public. The closed research caller
//! evaluates its concrete AIR; the recorder constructs the fixed public columns.
use super::{recorded, recording, Builder, RecordedUni};
use crate::{
    block_v2::{gpu_quotient_prover::uni, native_gpu::transcript_preparation::TranscriptPreparationPlan},
    config::Val,
    ringct_research_quota::{Bytes, Category, Ledger, Reservation},
};
use core::mem::size_of;
use p3_air::symbolic::AirLayout;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    Shape,
    Allocation,
    Recording,
    Preparation,
}

/// Cumulative requested backing for replaying this exact accepted recording
/// with p3's default symbolic builder during CPU verification. The concrete
/// research caller must bind this census to the same immutable source AIR.
/// It is not a generic bound for a supplied AIR or a runtime admission token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptSymbolicReplay {
    geometry: crate::block_v2::native_gpu::transcript_preparation::TranscriptGeometry,
    required_host_bytes: usize,
}

impl TranscriptSymbolicReplay {
    fn from_recording(census: TranscriptPreparationPlan, recorded: &RecordedUni)
        -> Result<Self, Error>
    {
        use p3_air::symbolic::{SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};
        let source = recording::transcript::capture().map_err(|_| Error::Recording)?;
        let constraints = recorded.constraints();
        if constraints == 0 || constraints > source.constraint_limit { return Err(Error::Shape); }
        let geometry = census.geometry();
        // The recorder emits each arithmetic Arc without constant folding and
        // charges its full allocation, including discarded nodes and growth.
        // The upstream expression operators can only fold those operations
        // away. Add upstream layout/main clones and returned root/type arrays
        // without subtracting the recorder's corresponding original buffers.
        // A source AIR callback's own Vec allocations are outside recording.
        let variables = geometry.width().checked_mul(2)
            .and_then(|n| n.checked_add(geometry.public_values()))
            .and_then(|n| n.checked_add(geometry.periodic_columns())).ok_or(Error::Shape)?;
        let arrays = variables.checked_mul(16)
            .and_then(|n| n.checked_mul(size_of::<SymbolicVariable<Val>>())).ok_or(Error::Shape)?;
        let roots = constraints.checked_mul(4)
            .and_then(|n| n.checked_mul(size_of::<SymbolicExpression<Val>>() + size_of::<usize>()))
            .ok_or(Error::Shape)?;
        let frames = 8 * (size_of::<SymbolicAirBuilder<Val>>() + size_of::<AirLayout>()
            + size_of::<Self>() + size_of::<Result<Self, Error>>() + size_of::<[usize; 8]>());
        let required_host_bytes = source.requested_host_bytes.checked_add(arrays)
            .and_then(|n| n.checked_add(roots))
            .and_then(|n| n.checked_add(census.host().air_callback_heap_bytes))
            .and_then(|n| n.checked_add(frames)).ok_or(Error::Shape)?;
        Ok(Self { geometry, required_host_bytes })
    }

    pub fn geometry(self) -> crate::block_v2::native_gpu::transcript_preparation::TranscriptGeometry {
        self.geometry
    }
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
}

fn layout(census: TranscriptPreparationPlan) -> AirLayout {
    AirLayout {
        main_width: census.geometry().width(),
        num_public_values: census.geometry().public_values(),
        num_periodic_columns: census.geometry().periodic_columns(),
        ..AirLayout::default()
    }
}

/// Explicit bridge owners, in addition to the source preparation census.
/// This pure source census neither reserves memory nor authorizes execution.
pub fn additional_host_bytes() -> usize {
    8 * (size_of::<TranscriptRecorder<'static>>()
        + size_of::<PreparedTranscript<'static>>()
        + size_of::<Result<TranscriptRecorder<'static>, Error>>()
        + size_of::<Result<PreparedTranscript<'static>, Error>>()
        + size_of::<recording::ringct::RetainedScope>()
        + size_of::<RecordedUni>()
        + size_of::<AirLayout>()
        + size_of::<TranscriptPreparationPlan>()
        + size_of::<[usize; 8]>())
}

fn authority(
    census: TranscriptPreparationPlan,
    reservation: &Reservation,
    ledger: &Ledger,
) -> Result<(), Error> {
    let allowance = ledger.snapshot().allowance;
    let request = reservation.requirements();
    let symbolic = census
        .host()
        .prepared_partition_bytes()
        .map_err(|_| Error::Shape)?;
    let other = census
        .host()
        .required_host_bytes
        .checked_sub(symbolic)
        .and_then(|n| n.checked_add(additional_host_bytes()))
        .ok_or(Error::Shape)?;
    if !reservation.belongs_to(ledger)
        || allowance.host > 32u64 << 30
        || allowance.device > 8u64 << 30
        || request.get(Category::SymbolicCompiler)
            != (Bytes {
                host: symbolic as u64,
                device: 0,
            })
        || request.get(Category::PhaseScratch).device != 0
        || request.get(Category::PhaseScratch).host < other as u64
        || request.total().map_err(|_| Error::Authority)?.device != 0
        || Category::ALL.into_iter().any(|category| {
            !matches!(
                category,
                Category::SymbolicCompiler | Category::PhaseScratch
            ) && request.get(category) != Bytes::ZERO
        })
    {
        return Err(Error::Authority);
    }
    if census.geometry().periodic_values() != 386 { return Err(Error::Shape); }
    Ok(())
}

/// The retained TLS scope is thread-bound and follows every builder borrow.
/// Dynamic builder/column fields drop before the scope; the original token
/// remains exclusively borrowed throughout errors, unwinding and successful
/// handoff. A second retained recording cannot share this original claim.
pub struct TranscriptRecorder<'claim> {
    builder: Option<Builder>,
    columns: Vec<Vec<Val>>,
    census: TranscriptPreparationPlan,
    scope: recording::ringct::RetainedScope,
    reservation: &'claim mut Reservation,
    ledger: &'claim Ledger,
}

impl<'claim> TranscriptRecorder<'claim> {
    pub fn begin(
        census: TranscriptPreparationPlan,
        reservation: &'claim mut Reservation,
        ledger: &'claim Ledger,
    ) -> Result<Self, Error> {
        authority(census, reservation, ledger)?;
        let scope = recording::ringct::RetainedScope::begin().map_err(|_| Error::Recording)?;
        let builder = Builder::new(layout(census)).map_err(|_| Error::Recording)?;
        let count = census.geometry().periodic_columns();
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if columns.capacity() != count {
            return Err(Error::Allocation);
        }
        for index in 0..count {
            let period = census.geometry().periodic_length(index).map_err(|_| Error::Shape)?;
            let mut column = Vec::new();
            column
                .try_reserve_exact(period)
                .map_err(|_| Error::Allocation)?;
            if column.capacity() != period {
                return Err(Error::Allocation);
            }
            for row in 0..period {
                column.push(census.geometry().periodic_value(index, row).map_err(|_| Error::Shape)?);
            }
            columns.push(column);
        }
        Ok(Self {
            builder: Some(builder),
            columns,
            census,
            scope,
            reservation,
            ledger,
        })
    }

    pub fn builder_mut(&mut self) -> &mut Builder {
        self.builder.as_mut().expect("live fixed recorder")
    }

    pub fn finish(mut self) -> Result<PreparedTranscript<'claim>, Error> {
        authority(self.census, self.reservation, self.ledger)?;
        self.scope.check().map_err(|_| Error::Recording)?;
        let recorded = recorded::ringct::finish(
            self.builder.take().ok_or(Error::Recording)?,
            layout(self.census),
        )
        .map_err(|_| Error::Recording)?;
        self.scope.check().map_err(|_| Error::Recording)?;
        let replay = TranscriptSymbolicReplay::from_recording(self.census, &recorded)?;
        drop(self.scope);
        Ok(PreparedTranscript {
            recorded,
            columns: self.columns,
            census: self.census,
            replay,
            reservation: self.reservation,
            ledger: self.ledger,
        })
    }
}

/// Opaque data already produced by closed source evaluation. It is not a proof
/// or dispatch permit. The original preparation token remains exclusively
/// borrowed through its entire lifetime; the core consumer must preserve that
/// borrow through PCS.
pub struct PreparedTranscript<'claim> {
    recorded: RecordedUni,
    columns: Vec<Vec<Val>>,
    census: TranscriptPreparationPlan,
    replay: TranscriptSymbolicReplay,
    reservation: &'claim mut Reservation,
    ledger: &'claim Ledger,
}

impl<'claim> PreparedTranscript<'claim> {
    pub fn symbolic_replay_census(&self) -> TranscriptSymbolicReplay { self.replay }
    pub fn census(&self) -> TranscriptPreparationPlan {
        self.census
    }
    pub fn reservation(&self) -> &Reservation {
        self.reservation
    }
    pub fn ledger(&self) -> &'claim Ledger {
        self.ledger
    }
    pub fn constraints(&self) -> usize {
        self.recorded.constraints()
    }
    pub fn node_bound(&self) -> usize {
        self.recorded.node_bound()
    }

    /// Only the fixed core consumer supplies its independently admitted PCS
    /// operation allowance. There is no public numeric preparation constructor.
    /// It must retain the returned original exclusive claim until every dynamic
    /// preparation owner, including compiled program/PCS state, is destroyed.
    pub(crate) fn into_prepared(
        self,
        operation_host_budget: usize,
    ) -> Result<(uni::Prepared, &'claim mut Reservation), Error> {
        authority(self.census, self.reservation, self.ledger)?;
        let prepared = uni::prepared_from_closed_transcript(
            self.recorded,
            self.columns,
            self.census,
            operation_host_budget,
        )
        .map_err(|_| Error::Preparation)?;
        Ok((prepared, self.reservation))
    }
}
