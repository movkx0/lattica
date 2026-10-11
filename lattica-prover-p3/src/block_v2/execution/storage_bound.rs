//! Requested backing bounds for the pinned Rust 1.96 collections.
//!
//! These are conservative allocation-layout bounds, not allocator/RSS bounds.
//! Requalify against alloc/collections/btree/node.rs when changing toolchains.
use crate::block_v2::recursive::Error;
use core::mem::{align_of, size_of};

pub(super) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or_else(|| "execution storage overflow".into())
}

pub(super) fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b)
        .ok_or_else(|| "execution storage overflow".into())
}

pub(super) fn vector<T>(capacity: usize) -> Result<usize, Error> {
    mul(capacity, size_of::<T>())
}

/// ArcInner<T> is repr(C): two atomic usize counters followed by aligned T.
/// Weak references keep this allocation after the last strong owner is gone.
pub(super) fn arc<T>() -> Result<usize, Error> {
    arc_slice::<T>(1)
}

/// ArcInner<[T]> has the same aligned header, followed by len inline elements.
pub(super) fn arc_slice<T>(len: usize) -> Result<usize, Error> {
    let align = align_of::<T>().max(align_of::<usize>());
    let round = |n| -> Result<usize, Error> { Ok(add(n, align - 1)? / align * align) };
    round(add(round(2 * size_of::<usize>())?, vector::<T>(len)?)?)
}

/// Vec growth from an empty Vec by push/filtered collect, without reserve calls.
pub(super) fn growing_vector<T>(len: usize) -> Result<usize, Error> {
    if len == 0 {
        return Ok(0);
    }
    // All users are non-ZST metadata types. Rust's initial allocation is at
    // most eight elements; doubling then keeps capacity below twice the len.
    vector::<T>(mul(2, len)?.max(8))
}

/// A BTreeMap/BTreeSet has no spare-node cache. Charge a full internal node
/// per entry plus one for an empty retained root or an insertion in progress.
/// Real nodes contain up to 11 entries and 12 child pointers. Rounding *each*
/// field to the largest alignment also bounds any Rust-layout field ordering
/// and both the leaf and enclosing internal-node tail padding.
pub(super) fn btree<K, V>(entries: usize) -> Result<usize, Error> {
    let align = align_of::<K>()
        .max(align_of::<V>())
        .max(align_of::<usize>());
    let round =
        |bytes: usize| -> Result<usize, Error> { Ok(add(bytes, align - 1)? / align * align) };
    let fields = [
        size_of::<usize>(), // Option<NonNull<InternalNode>> parent
        size_of::<u16>(),   // parent_idx
        size_of::<u16>(),   // len
        vector::<K>(11)?,
        vector::<V>(11)?,
        vector::<usize>(12)?, // internal edges; also charged for every leaf
    ];
    let node = fields
        .into_iter()
        .try_fold(0, |sum, field| add(sum, round(field)?))?;
    mul(add(entries, 1)?, node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_layout_bounds_handle_empty_overflow_and_alignment() {
        #[repr(align(256))]
        struct Aligned([u8; 256]);
        // Exercise an over-aligned key, including padding around tiny values.
        let key = Aligned([0; 256]);
        assert_eq!(key.0.len(), 256);
        assert!(btree::<Aligned, u8>(0).unwrap() >= 11 * 256 + 11 + 12 * size_of::<usize>());
        assert!(btree::<u64, ()>(0).unwrap() > 0); // a removed last entry can leave a root
        assert!(btree::<u64, u64>(usize::MAX).is_err());
        assert!(vector::<u64>(usize::MAX).is_err());
        assert!(growing_vector::<u64>(usize::MAX).is_err());
        assert_eq!(growing_vector::<u64>(0).unwrap(), 0);
        for len in 1..1024 {
            let mut v = Vec::new();
            v.extend((0..len).filter(|_| true).map(|n| n as u64));
            assert!(vector::<u64>(v.capacity()).unwrap() <= growing_vector::<u64>(len).unwrap());
        }
    }
}
