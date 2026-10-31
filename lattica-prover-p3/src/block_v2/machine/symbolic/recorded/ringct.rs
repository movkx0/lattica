//! Seal an already evaluated fixed-source builder without another AIR callback.
use super::*;

pub(in crate::block_v2::machine::symbolic) fn finish(
    builder: Builder,
    layout: AirLayout,
) -> Result<RecordedUni, CompileError> {
    if layout.preprocessed_width != 0
        || layout.permutation_width != 0
        || layout.num_permutation_challenges != 0
        || layout.num_permutation_values != 0
    {
        return Err(CompileError::Shape("closed SHAKE recording layout"));
    }
    let nodes = normalize::admit(&builder, &normalize::Storage::new(false))?;
    if !builder.extension.is_empty()
        || !builder.order.ext_indices.is_empty()
        || !builder.global.is_empty()
        || !builder.local.is_empty()
        || builder.base.is_empty()
        || builder
            .order
            .base_indices
            .iter()
            .copied()
            .ne(0..builder.base.len())
    {
        return Err(CompileError::Shape("closed SHAKE recording constraints"));
    }
    Ok(RecordedUni {
        builder,
        layout,
        nodes,
    })
}
