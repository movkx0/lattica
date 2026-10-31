//! Requested Rust fixture/translation storage, derived in its private owner.
//! Native C state/callbacks and OpenCL generation have separate claims.
use super::*;
use core::mem::size_of;

pub(crate) fn requested_host_bytes() -> Result<usize, &'static str> {
    // The encoded fixture remains live while the public ring/recipients and
    // secret spending/commitment key vectors are decoded into the GPU request.
    // Both ranges derive from the same constants consumed by the translator.
    let words = WORDS.checked_add(SERIALS.checked_sub(RING)
        .ok_or("fixture translation geometry underflow")?)
        .and_then(|count| count.checked_mul(size_of::<u64>()))
        .ok_or("fixture translation backing overflow")?;
    let frames = [
        size_of::<NativeSpendFixture>(), size_of::<DecodedWitness>(),
        size_of::<PublicSpendInputs>(), size_of::<PrivateSpendWitness>(),
        size_of::<PrivateSpendRequest>(), size_of::<FixtureAmounts>(),
        size_of::<Result<NativeSpendFixture, NativeError>>(),
        size_of::<Result<PrivateSpendRequest, NativeError>>(),
        size_of::<[u8; 32]>(), size_of::<Option<[u8; 32]>>(),
        size_of::<[i64; DEGREE]>(), size_of::<[u64; DEGREE]>(),
        16 * size_of::<usize>(),
    ].into_iter().try_fold(0usize, |sum, value| sum.checked_add(value)
        .ok_or("fixture caller frame overflow"))?
        .checked_mul(4).ok_or("fixture caller transport overflow")?;
    words.checked_add(frames).ok_or("fixture requested storage overflow")
}
