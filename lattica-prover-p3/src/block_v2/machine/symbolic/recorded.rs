//! Single-AIR recording retained across device admission. Raw degree fields
//! are deliberately unused; only explicit-backend normalization supplies degree.
use super::*;

pub(crate) struct RecordedUni {
    builder: Builder,
    layout: AirLayout,
    nodes: usize,
}

impl RecordedUni {
    pub(crate) fn new<A: Air<Builder>>(air: &A) -> Result<Self, CompileError> {
        let layout = AirLayout::from_air::<Val>(air);
        if layout.preprocessed_width != 0
            || layout.permutation_width != 0
            || layout.num_permutation_challenges != 0
            || layout.num_permutation_values != 0
        {
            return Err(CompileError::Shape("owned uni recording layout"));
        }
        let builder = recording::run(true, || {
            let mut builder = Builder::new(layout)?;
            // Match the runtime's empty-lookup path and emission order.
            LogUpGadget::new().eval_air_and_lookups(air, &mut builder, &[]);
            Ok(builder)
        })?;
        let nodes = normalize::admit(&builder, &normalize::Storage::new(false))?;
        if !builder.extension.is_empty()
            || !builder.order.ext_indices.is_empty()
            || builder.base.is_empty()
            || builder
                .order
                .base_indices
                .iter()
                .copied()
                .ne(0..builder.base.len())
            || air
                .num_constraints()
                .is_some_and(|n| n != builder.base.len())
        {
            return Err(CompileError::Shape("owned uni recording constraints"));
        }
        Ok(Self {
            builder,
            layout,
            nodes,
        })
    }

    pub(crate) fn layout(&self) -> AirLayout {
        self.layout
    }
    pub(crate) fn matches_layout(&self, layout: AirLayout) -> bool {
        let key = |l: AirLayout| {
            [
                l.main_width,
                l.preprocessed_width,
                l.num_public_values,
                l.permutation_width,
                l.num_permutation_challenges,
                l.num_permutation_values,
                l.num_periodic_columns,
            ]
        };
        key(self.layout) == key(layout)
    }
    pub(crate) fn node_bound(&self) -> usize {
        self.nodes
    }
    pub(crate) fn constraints(&self) -> usize {
        self.builder.base.len()
    }

    /// Consume this exact recording once. No second AIR evaluation can change
    /// the graph whose storage was admitted before witness generation.
    pub(crate) fn normalize(self, constants: Constants<'_>) -> Result<Constraints, CompileError> {
        finish(&self.builder, constants)
    }
}
