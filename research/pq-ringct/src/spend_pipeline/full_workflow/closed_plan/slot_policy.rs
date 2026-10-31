//! Pure reservation-slot selection. These numbers grant no phase authority.
use super::{Bytes, Category, Requirements, SlotSpec};
use core::mem::size_of;

// Explicit additional live helper/caller storage before selection begins.
// The enclosing metadata/inspection census applies its existing x8 forwarding
// multiplier. No inlining, optimizer slot reuse, or dead temporaries are assumed.
//
// first_compatible: two slices, one output, one index and its Option result.
// same_category_support: two arguments, the category array/index/current value,
// two getter results and a boolean result. Forwarding: the record caller's
// slices/output/result, two support-call arguments, two Requirements::get
// receiver copies and their Bytes results, comparison/control temporaries.
// Compiler compatibility adds both exact requirement operands, per-category
// host/device checks, mandatory-support values and both helper call frames.
pub(super) const SELECTION_FRAME_BYTES: usize =
    size_of::<&[SlotSpec]>() + size_of::<&[bool]>()
    + size_of::<Requirements>() + size_of::<usize>() + size_of::<Option<usize>>()
    + size_of::<[Requirements; 2]>() + size_of::<[Category; Category::ALL.len()]>()
    + size_of::<usize>() + size_of::<Category>() + size_of::<[Bytes; 2]>() + size_of::<bool>()
    + size_of::<&[SlotSpec]>() + size_of::<&[bool]>()
    + size_of::<[Requirements; 5]>() + size_of::<Option<usize>>()
    + size_of::<[Bytes; 2]>() + size_of::<[bool; 8]>() + size_of::<[usize; 4]>()
    + size_of::<[Requirements; 6]>() + size_of::<[Category; Category::ALL.len()]>()
    + size_of::<[Bytes; 6]>() + size_of::<[bool; 8]>() + size_of::<[usize; 4]>();

/// The support of a slot's category-wise maximum stays constant when it is
/// reused only by this predicate. In particular, a compiler reservation cannot
/// migrate into a retained proof. Magnitudes still grow via the original max.
fn same_category_support(previous: Requirements, requested: Requirements) -> bool {
    let categories = Category::ALL;
    let mut category_index = 0;
    while category_index < categories.len() {
        let category = categories[category_index];
        let old = previous.get(category);
        let new = requested.get(category);
        if (old.host == 0) != (new.host == 0)
            || (old.device == 0) != (new.device == 0)
        { return false; }
        category_index += 1;
    }
    true
}

/// The two maintained compiled-program owner shapes differ only in whether
/// their inline typed-owner backing is a separate RegisteredMetadata claim.
/// Both keep positive compiler/input host backing. Every byte of the optional
/// metadata remains in the slot's category-wise historical maximum, even when
/// a later compiled owner does not request that category. No proof, failure,
/// phase scratch or device backing can enter this compiler-only compatibility.
fn compiler_category_support(requirements: Requirements) -> bool {
    if requirements.get(Category::SymbolicCompiler).host == 0
        || requirements.get(Category::CompilerInputs).host == 0
    { return false; }
    for category in Category::ALL {
        let value = requirements.get(category);
        if value.device != 0 || (value.host != 0 && !matches!(category,
            Category::SymbolicCompiler | Category::CompilerInputs | Category::RegisteredMetadata))
        { return false; }
    }
    true
}

fn compatible(previous: Requirements, requested: Requirements) -> bool {
    same_category_support(previous, requested)
        || (compiler_category_support(previous) && compiler_category_support(requested))
}

/// The schedule owns equally sized slot/live vectors. Slot zero is the
/// dedicated failure reservation. Every input is still live when called.
pub(super) fn first_compatible(slots: &[SlotSpec], live: &[bool], output: Requirements) -> Option<usize> {
    let mut index = 1;
    while index < live.len() {
        if !live[index] && compatible(slots[index].requirements, output) {
            return Some(index);
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests;
