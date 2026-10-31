//! Requested backing and complete fixed caller/codec forwarding frames.
use super::*;
use crate::execution::retained_resources::Snapshot;
use core::mem::size_of_val;

fn frames<T>() -> R<usize> { product(size_of::<T>(), 16) }

fn request(bytes: usize) -> R<Requirements> {
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| Error::Overflow)?, device: 0,
    }))
}

/// All reachable concrete schema values and returned Results. Add the complete
/// set at each forwarding level; take no union, inlining or move-elision credit.
fn schema_frame() -> R<usize> {
    let parts = [
        size_of::<Proof>(), size_of::<R<Proof>>(),
        size_of::<Cap>(), size_of::<R<Cap>>(),
        size_of::<BatchCommitments<Cap>>(), size_of::<R<BatchCommitments<Cap>>>(),
        size_of::<BatchOpenedValues<Challenge>>(), size_of::<R<BatchOpenedValues<Challenge>>>(),
        size_of::<LookupValues>(), size_of::<R<LookupValues>>(),
        size_of::<Values>(), size_of::<R<Values>>(),
        size_of::<Opening>(), size_of::<R<Opening>>(),
        size_of::<Fri>(), size_of::<R<Fri>>(),
        size_of::<Query>(), size_of::<R<Query>>(),
        size_of::<Step>(), size_of::<R<Step>>(),
        size_of::<Challenge>(), size_of::<Val>(),
        size_of::<[Val; 4]>(), size_of::<[u8; 8]>(),
        size_of::<Vec<Vec<Vec<Vec<Challenge>>>>>(),
        size_of::<(Vec<Vec<Val>>, Vec<[Val; 4]>)>(),
        size_of::<R<(Vec<Vec<Val>>, Vec<[Val; 4]>)>>(),
        size_of::<Option<Vec<Challenge>>>(),
        element_size(|p| &p.lookup_terminals),
        size_of::<postcard::Error>(), size_of::<std::collections::TryReserveError>(),
        // Source-fixed control: Storage/Attempt; Guard/Visit/Seed/Access;
        // Postcard Slice serializer/deserializer/SeqAccess; fixed-u64 wrappers;
        // derived schema visitors; iterator/count/length state and closure
        // captures. Their named source fields fit 128 machine words per level.
        size_of::<[usize; 128]>(),
    ];
    parts.into_iter().try_fold(size_of_val(&parts), sum)
}

pub(super) fn phase() -> R<Requirements> {
    // At most 32 codec compounds. Sixteen additive forwarding frames per
    // level cover caller -> API -> Storage/seed -> Guard -> Postcard access ->
    // Visit -> concrete visitor -> Access -> Seed -> child, plus serializer
    // wrappers/derived forwarding. Fixture/census nesting is smaller. See BOUNDS.
    let codec = product(product(model::MAX_DEPTH, 16)?, schema_frame()?)?;
    let parts = [
        product(2, DECODE_LIMIT)?, // Original fixture AND cumulative decoder.
        product(2, INNER_LIMIT)?, // Both full packets, including spare capacity.
        codec,
        frames::<fixture::Storage>()?, frames::<Backing>()?, frames::<R<Backing>>()?,
        frames::<HeightShape>()?, frames::<Case>()?, frames::<R<Case>>()?,
        frames::<Reservation>()?, frames::<Requirements>()?, frames::<R<Requirements>>()?,
        frames::<Ledger>()?, frames::<&Ledger>()?, frames::<&Reservation>()?,
        frames::<Bytes>()?, frames::<Snapshot>()?, frames::<Error>()?,
        frames::<R<()>>()?, frames::<R<usize>>()?, frames::<R<Vec<u8>>>()?,
        frames::<Instant>()?, frames::<u128>()?, frames::<[usize; 32]>()?,
        frames::<std::ops::Range<usize>>()?,
        frames::<core::result::Result<Proof, postcard::Error>>()?,
        frames::<core::result::Result<&'static mut [u8], postcard::Error>>()?,
        frames::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>()?,
        // Fixed bounded core decoder diagnostic / formatting and byte helpers.
        64 << 10,
    ];
    request(parts.into_iter().try_fold(product(size_of_val(&parts), 16)?, sum)?)
}

pub(super) fn driver() -> R<Requirements> {
    let parts = [
        frames::<TransportEnvelope>()?, frames::<core::result::Result<TransportEnvelope, Refusal>>()?,
        frames::<[HeightShape; HEIGHTS]>()?, frames::<HeightShape>()?,
        frames::<std::array::IntoIter<HeightShape, HEIGHTS>>()?,
        frames::<std::array::IntoIter<HeightShape, 2>>()?,
        frames::<Case>()?, frames::<R<Case>>()?, frames::<Backing>()?,
        frames::<Ledger>()?, frames::<WorkerAllowance>()?, frames::<Snapshot>()?,
        frames::<Reservation>()?, frames::<Requirements>()?, frames::<R<Requirements>>()?,
        frames::<Bytes>()?, frames::<Error>()?, frames::<R<()>>()?,
        frames::<Val>()?, frames::<Instant>()?, frames::<u128>()?,
        frames::<&Ledger>()?, frames::<&Reservation>()?,
        frames::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>()?,
        frames::<std::fmt::Arguments<'static>>()?, frames::<[usize; 256]>()?,
        64 << 10,
    ];
    request(parts.into_iter().try_fold(product(size_of_val(&parts), 16)?, sum)?)
}
