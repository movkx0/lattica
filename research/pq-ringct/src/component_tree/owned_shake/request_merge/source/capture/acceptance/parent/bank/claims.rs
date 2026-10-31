//! Category-preserving bank arithmetic and complete added caller storage.

use super::*;
use crate::execution::{
    phase_report::Error as ReportError, retained_resources::Error as QuotaError,
};

pub(super) fn maximum(left: Requirements, right: Requirements) -> Result<Requirements> {
    let mut maximum = Requirements::default();
    for category in Category::ALL {
        let left = left.get(category);
        let right = right.get(category);
        maximum
            .add(
                category,
                Bytes {
                    host: left.host.max(right.host),
                    device: left.device.max(right.device),
                },
            )
            .map_err(|_| Error::Overflow)?;
    }
    Ok(maximum)
}

pub(super) fn sum(mut left: Requirements, right: Requirements) -> Result<Requirements> {
    for category in Category::ALL {
        left.add(category, right.get(category))
            .map_err(|_| Error::Overflow)?;
    }
    Ok(left)
}

/// No admission, release, category conversion or observer accounting occurs.
/// Failure destroys both untouched originals as terminal cleanup only.
pub(super) fn reunite(left: Reservation, right: Reservation) -> Result<Reservation> {
    left.reunite(right).map_err(|_| Error::Authority)
}

pub(super) fn caller_requirement() -> Result<Requirements> {
    let parts = [
        frames::<CompilerBank<'static, 'static, 'static, 'static>>(8)?,
        frames::<Result<CompilerBank<'static, 'static, 'static, 'static>>>(8)?,
        frames::<BankedLeaf<'static, 'static, 'static, 'static>>(8)?,
        frames::<BankResult<BankedLeaf<'static, 'static, 'static, 'static>>>(8)?,
        frames::<BankedParent<'static, 'static, 'static, 'static>>(8)?,
        frames::<Result<BankedParent<'static, 'static, 'static, 'static>>>(8)?,
        frames::<BankAdmission<'static>>(8)?,
        frames::<Failure>(8)?,
        frames::<CompilationFailure>(8)?,
        frames::<OwnedCompiledShake<'static>>(8)?,
        frames::<Option<OwnedCompiledShake<'static>>>(8)?,
        frames::<LeafPayload<'static>>(8)?,
        frames::<&LeafPayload<'static>>(8)?,
        frames::<&mut CompiledNode>(8)?,
        frames::<CompiledNode>(8)?,
        frames::<Summary>(8)?,
        frames::<GroupCompilePlan<'static>>(8)?,
        frames::<Storage>(8)?,
        frames::<Result<Storage>>(8)?,
        frames::<[&GroupCompilePlan<'static>; LEAF_COUNT]>(8)?,
        frames::<[Option<ReservedNativeChild<'static>>; 2]>(8)?,
        frames::<[Option<Reservation>; 2]>(8)?,
        frames::<Option<Reservation>>(8)?,
        frames::<Reservation>(48)?,
        frames::<core::result::Result<Reservation, (QuotaError, Reservation, Reservation)>>(8)?,
        frames::<(QuotaError, Reservation, Reservation)>(8)?,
        frames::<core::result::Result<Reservation, (ReportError, PhaseReportOwner)>>(8)?,
        frames::<(ReportError, PhaseReportOwner)>(8)?,
        frames::<core::result::Result<(VerificationReceipt, Reservation), VerificationFailure>>(8)?,
        frames::<core::result::Result<(), VerificationFailure>>(8)?,
        frames::<VerificationReceipt>(8)?,
        frames::<VerificationFailure>(8)?,
        frames::<PhaseReportOwner>(8)?,
        frames::<PhaseIdentity>(8)?,
        frames::<Result<PhaseIdentity>>(8)?,
        frames::<Requirements>(48)?,
        frames::<Result<Requirements>>(16)?,
        frames::<Bytes>(24)?,
        frames::<crate::execution::retained_resources::Snapshot>(8)?,
        frames::<Result<()>>(16)?,
        frames::<&Source<'static, 'static>>(8)?,
        frames::<&GroupCompilePlan<'static>>(16)?,
        frames::<&Ledger>(16)?,
        frames::<&Reservation>(16)?,
        frames::<&OwnedCompiledShake<'static>>(8)?,
        frames::<&CompiledLeafParent<'static, 'static, 'static>>(8)?,
        frames::<&Arc<Program>>(16)?,
        frames::<usize>(16)?,
        frames::<usize>(64)?,
        frames::<bool>(16)?,
        frames::<Option<Error>>(8)?,
        frames::<std::slice::Iter<'static, &'static GroupCompilePlan<'static>>>(8)?,
        frames::<
            std::iter::Enumerate<std::slice::Iter<'static, &'static GroupCompilePlan<'static>>>,
        >(8)?,
        frames::<std::array::IntoIter<Option<Reservation>, 2>>(8)?,
        frames::<std::iter::Flatten<std::array::IntoIter<Option<Reservation>, 2>>>(8)?,
        frames::<std::slice::IterMut<'static, Val>>(8)?,
        // The parent storage arithmetic is called before its compiler chunk
        // can be split. Preserve its complete existing caller census here.
        super::super::caller_bytes()?,
        PhaseReportOwner::reclamation_caller_host_bytes(),
    ];
    let helper = frames::<usize>(8 * parts.len())?;
    let bytes = parts
        .into_iter()
        .try_fold(helper, super::super::super::super::super::add)?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}
