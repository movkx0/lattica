//! Source-fixed recorder bridge. No AIR callback, dispatch, numeric allowance
//! or detached recording constructor is public. The closed research caller
//! evaluates its concrete AIR and fills its concrete public periodic columns.
use super::{recorded, recording, Builder, RecordedUni};
use crate::{
    block_v2::{gpu_quotient_prover::uni, native_gpu::aes_preparation::AesPreparationPlan},
    config::Val,
    ringct_research_quota::{Bytes, Category, Ledger, Reservation},
};
use core::mem::size_of;
use p3_air::symbolic::AirLayout;
use p3_field::PrimeCharacteristicRing;

const COLUMNS: usize = 31;
const PERIOD: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    Shape,
    Allocation,
    Recording,
    Preparation,
}

fn layout(census: AesPreparationPlan) -> AirLayout {
    AirLayout {
        main_width: census.geometry().width(),
        num_public_values: census.geometry().public_values(),
        num_periodic_columns: COLUMNS,
        ..AirLayout::default()
    }
}

/// Additional explicit bridge owners, outside A016's pre-existing owners.
/// This pure source census neither reserves memory nor authorizes execution.
pub fn additional_host_bytes() -> usize {
    size_of::<AesRecorder<'static>>()
        + size_of::<PreparedAes<'static>>()
        + size_of::<recording::ringct::RetainedScope>()
        + size_of::<AirLayout>()
}

fn authority(
    census: AesPreparationPlan,
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
        .required_host_bytes()
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
    if census.geometry().periodic_columns() != COLUMNS
        || census.geometry().periodic_length() != PERIOD
        || census.geometry().public_values() != 12
    {
        return Err(Error::Shape);
    }
    Ok(())
}

/// The retained TLS scope is thread-bound and follows every builder borrow.
/// Dynamic builder/column fields drop before the scope; the original token
/// remains exclusively borrowed throughout errors, unwinding and successful
/// handoff. A second retained recording cannot share this original claim.
pub struct AesRecorder<'claim> {
    builder: Option<Builder>,
    columns: Vec<Vec<Val>>,
    filled: [bool; COLUMNS],
    census: AesPreparationPlan,
    scope: recording::ringct::RetainedScope,
    reservation: &'claim mut Reservation,
    ledger: &'claim Ledger,
}

impl<'claim> AesRecorder<'claim> {
    pub fn begin(
        census: AesPreparationPlan,
        reservation: &'claim mut Reservation,
        ledger: &'claim Ledger,
    ) -> Result<Self, Error> {
        authority(census, reservation, ledger)?;
        let scope = recording::ringct::RetainedScope::begin().map_err(|_| Error::Recording)?;
        let builder = Builder::new(layout(census)).map_err(|_| Error::Recording)?;
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(COLUMNS)
            .map_err(|_| Error::Allocation)?;
        if columns.capacity() != COLUMNS {
            return Err(Error::Allocation);
        }
        for _ in 0..COLUMNS {
            let mut column = Vec::new();
            column
                .try_reserve_exact(PERIOD)
                .map_err(|_| Error::Allocation)?;
            if column.capacity() != PERIOD {
                return Err(Error::Allocation);
            }
            column.resize(PERIOD, Val::ZERO);
            columns.push(column);
        }
        Ok(Self {
            builder: Some(builder),
            columns,
            filled: [false; COLUMNS],
            census,
            scope,
            reservation,
            ledger,
        })
    }

    pub fn builder_mut(&mut self) -> &mut Builder {
        self.builder.as_mut().expect("live fixed recorder")
    }

    pub fn periodic_column_mut(&mut self, index: usize) -> Result<&mut [Val], Error> {
        if index >= COLUMNS || self.filled[index] {
            recording::reject();
            return Err(Error::Shape);
        }
        self.filled[index] = true;
        Ok(&mut self.columns[index])
    }

    pub fn finish(mut self) -> Result<PreparedAes<'claim>, Error> {
        authority(self.census, self.reservation, self.ledger)?;
        self.scope.check().map_err(|_| Error::Recording)?;
        if self.filled.iter().any(|filled| !filled)
            || self
                .columns
                .iter()
                .flatten()
                .any(|value| *value != Val::ZERO && *value != Val::ONE)
        {
            return Err(Error::Shape);
        }
        let recorded = recorded::ringct::finish(
            self.builder.take().ok_or(Error::Recording)?,
            layout(self.census),
        )
        .map_err(|_| Error::Recording)?;
        self.scope.check().map_err(|_| Error::Recording)?;
        drop(self.scope);
        Ok(PreparedAes {
            recorded,
            columns: self.columns,
            census: self.census,
            reservation: self.reservation,
            ledger: self.ledger,
        })
    }
}

/// Opaque data already produced by closed source evaluation. It is not a proof
/// or dispatch permit. The original preparation token remains exclusively
/// borrowed through its entire lifetime; the core consumer must preserve that
/// borrow through PCS.
pub struct PreparedAes<'claim> {
    recorded: RecordedUni,
    columns: Vec<Vec<Val>>,
    census: AesPreparationPlan,
    reservation: &'claim mut Reservation,
    ledger: &'claim Ledger,
}

impl<'claim> PreparedAes<'claim> {
    pub fn census(&self) -> AesPreparationPlan {
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
        let prepared = uni::prepared_from_closed_aes(
            self.recorded,
            self.columns,
            self.census,
            operation_host_budget,
        )
        .map_err(|_| Error::Preparation)?;
        Ok((prepared, self.reservation))
    }
}

#[cfg(test)]
mod tests;
