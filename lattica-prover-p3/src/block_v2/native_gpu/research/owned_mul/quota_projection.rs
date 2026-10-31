//! Pure projection of existing original startup/PCS requirements. No quota
//! reservation, runtime creation, environment read or dispatch occurs here.
use super::*;
pub(super) fn pcs_request(startup_device: usize, operation_host: usize) -> Result<Bytes> {
    if operation_host == 0 || operation_host > NATIVE_HOST { return Err(Error::Admission); }
    Ok(Bytes { host: u64::try_from(operation_host).map_err(|_| Error::Admission)?,
        device: MANAGED_DEVICE.checked_sub(u64::try_from(startup_device)
            .map_err(|_| Error::Admission)?).ok_or(Error::Admission)? })
}
pub(super) const fn additional_host_bytes() -> usize {
    8 * (size_of::<Reservation>() + size_of::<Result<Reservation>>()
        + size_of::<Bytes>() + size_of::<Result<Bytes>>() + size_of::<Requirements>()
        + size_of::<StartupPlan>() + size_of::<Result<StartupPlan>>()
        + size_of::<TreeProfile>() + size_of::<&Reservation>() + size_of::<&Ledger>()
        + 4 * size_of::<usize>() + 4 * size_of::<u64>()) + 4096
}
