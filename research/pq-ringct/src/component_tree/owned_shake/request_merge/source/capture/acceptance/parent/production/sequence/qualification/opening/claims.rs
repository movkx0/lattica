//! Complete additive caller census for the reviewed private opening driver.
//! The terminal harness census is deliberately not a worker admission request.
use super::*;
use core::mem::{size_of, size_of_val};
use crate::execution::retained_resources::{CategoryCounters, CATEGORY_COUNT};

#[cfg(test)]
mod tests;

const FRAME_COPIES: usize = 8;
const FORMAT_ARGUMENTS: usize = 32;
const OBSERVER_OUTPUT_BYTES: usize = 4096;
const OBSERVER_FIXED_HOST_LIMIT: u64 = 1 << 20;

// Infer the complete private plan-report layout from its maintained method,
// without exporting its module or constructing a plan/owner to measure it.
fn report_layout<A, B, T: 'static, E>(
    _: fn(A, B) -> core::result::Result<T, E>,
) -> [usize; 7] {
    [
        size_of::<T>(),
        size_of::<Option<T>>(),
        size_of::<&T>(),
        size_of::<Option<&T>>(),
        size_of::<core::result::Result<T, E>>(),
        size_of::<DriverResult<T>>(),
        size_of::<DriverResult<&T>>(),
    ]
}

fn repeated_layout(parts: &[usize]) -> DriverResult<u64> {
    // Include the complete input array plus arithmetic/iteration/error frames;
    // no optimizer, tail-call, ownership-move or stack-slot reuse discount.
    let controls = size_of_val(parts)
        .checked_add(size_of::<&[usize]>())
        .and_then(|n| n.checked_add(size_of::<std::slice::Iter<'static, usize>>()))
        .and_then(|n| n.checked_add(size_of::<[usize; 16]>()))
        .and_then(|n| n.checked_add(size_of::<Option<usize>>()))
        .and_then(|n| n.checked_add(size_of::<DriverResult<usize>>()))
        .and_then(|n| n.checked_add(size_of::<DriverResult<u64>>()))
        .ok_or("root-opening caller census overflow")?;
    let bytes = parts.iter().try_fold(controls, |sum, part| {
        sum.checked_add(*part)
            .ok_or("root-opening caller census overflow")
    })?;
    let bytes = bytes
        .checked_mul(FRAME_COPIES)
        .ok_or("root-opening caller census overflow")?;
    u64::try_from(bytes).map_err(|_| "root-opening caller census overflow")
}

fn added_driver_host_bytes() -> DriverResult<u64> {
    let planned = report_layout(PreissuedRootOpening::plan_report);
    let parts = [
        size_of::<OpeningMode>(),
        size_of::<(super::super::Mode, &'static str)>(),
        size_of::<PreissuedRootOpening<'static, 'static, 'static>>(),
        size_of::<Option<PreissuedRootOpening<'static, 'static, 'static>>>(),
        size_of::<&PreissuedRootOpening<'static, 'static, 'static>>(),
        size_of::<Option<&PreissuedRootOpening<'static, 'static, 'static>>>(),
        size_of::<core::result::Result<
            PreissuedRootOpening<'static, 'static, 'static>, ParentCompileError,
        >>(),
        size_of::<DriverResult<PreissuedRootOpening<'static, 'static, 'static>>>(),
        size_of::<DriverResult<&PreissuedRootOpening<'static, 'static, 'static>>>(),
        size_of::<RetainedRootOpeningReport<'static, 'static, 'static>>(),
        size_of::<&RetainedRootOpeningReport<'static, 'static, 'static>>(),
        size_of::<core::result::Result<
            RetainedRootOpeningReport<'static, 'static, 'static>, ParentCompileError,
        >>(),
        size_of::<DriverResult<RetainedRootOpeningReport<'static, 'static, 'static>>>(),
        size_of::<RootOpeningMeasurements>(),
        size_of::<&RootOpeningMeasurements>(),
        size_of::<core::result::Result<&RootOpeningMeasurements, ParentCompileError>>(),
        size_of::<DriverResult<&RootOpeningMeasurements>>(),
        planned[0], planned[1], planned[2], planned[3], planned[4], planned[5], planned[6],
        size_of_val(&planned),
        // Both the baseline caller and this additive census retain complete
        // component/source/attempt/error forwarding frames independently.
        size_of::<Component<'static, 'static, 'static>>(),
        size_of::<&Component<'static, 'static, 'static>>(),
        size_of::<core::result::Result<Component<'static, 'static, 'static>, Failure>>(),
        size_of::<Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<&mut Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<&mut Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<&mut Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<ParentSourceBound<'static, 'static>>(),
        size_of::<&ParentSourceBound<'static, 'static>>(),
        size_of::<&ReservedShakeRequest>(),
        size_of::<Failure>(),
        size_of::<&Failure>(),
        size_of::<Cause>(),
        size_of::<&Cause>(),
        size_of::<bank::Failure>(),
        size_of::<ParentCompileError>(),
        size_of::<Requirements>(),
        size_of::<DriverResult<Requirements>>(),
        size_of::<Reservation>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<core::result::Result<(), crate::execution::retained_resources::Error>>(),
        size_of::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>(),
        size_of::<Bytes>(),
        size_of::<Ledger>(),
        size_of::<&Ledger>(),
        size_of::<Snapshot>(),
        size_of::<DriverResult<()>>(),
        size_of::<DriverResult<u64>>(),
        size_of::<DriverResult<usize>>(),
        // The probe caller+verifier sum and driver+probe sum each use the
        // complete checked u64 option/result frames; timing uses u128.
        size_of::<Option<u64>>(),
        size_of::<Option<usize>>(),
        size_of::<Option<u128>>(),
        size_of::<[usize; 64]>(),
        size_of::<[u64; 32]>(),
        size_of::<[u128; 32]>(),
        size_of::<[bool; 32]>(),
        size_of::<&str>(),
        size_of::<String>(),
        size_of::<std::env::VarError>(),
        size_of::<core::result::Result<String, std::env::VarError>>(),
        size_of::<core::result::Result<&str, &std::env::VarError>>(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<[[usize; 3]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 39]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 20]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 5]; FORMAT_ARGUMENTS]>(),
        // Independently additive bounded guard-value, formatting, drop, byte
        // forwarding and error helpers; exact external environment is pinned.
        32 << 10,
    ];
    repeated_layout(&parts)
}

pub(super) fn driver_requirement() -> DriverResult<Requirements> {
    // Preserve every existing caller category and byte. The new original is
    // admitted once, before guards/source/preissue/Attempt in exercise().
    let mut complete = super::super::claims::driver_requirement()?;
    complete.add(Category::PhaseScratch, Bytes {
        host: added_driver_host_bytes()?,
        device: 0,
    }).map_err(|_| "root-opening complete caller census overflow")?;
    Ok(complete)
}

pub(super) fn terminal_observer_bytes() -> DriverResult<u64> {
    // A source-only census of the separately bounded bootstrap/terminal
    // harness. This function takes no Ledger and creates no Requirements or
    // Reservation. Its reported bytes confer no worker/source-storage credit.
    let parts = [
        size_of::<TerminalObservation>(),
        size_of::<OpeningMode>(),
        size_of::<DriverResult<()>>(),
        size_of::<DriverResult<u64>>(),
        size_of::<Snapshot>(),
        size_of::<Ledger>(),
        size_of::<WorkerAllowance>(),
        size_of::<Bytes>(),
        size_of::<CategoryCounters>(),
        size_of::<[CategoryCounters; CATEGORY_COUNT]>(),
        size_of::<std::slice::Iter<'static, CategoryCounters>>(),
        size_of::<std::time::Instant>(),
        size_of::<std::time::Duration>(),
        size_of::<[u128; 8]>(),
        size_of::<[u64; 16]>(),
        size_of::<[usize; 16]>(),
        size_of::<[bool; 16]>(),
        size_of::<&str>(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<[[usize; 3]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 39]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 20]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 5]; FORMAT_ARGUMENTS]>(),
        OBSERVER_OUTPUT_BYTES,
        // Fixed bootstrap, scalar formatting, timing and ordinary destruction
        // helpers belong only to the externally guarded harness process.
        32 << 10,
    ];
    let bytes = repeated_layout(&parts)?;
    if bytes == 0 || bytes > OBSERVER_FIXED_HOST_LIMIT {
        return Err("root-opening terminal observer census bound");
    }
    Ok(bytes)
}
