//! Shared batch geometry and peak admission for native wallet transports.
use super::{staging_words, Plan};
use crate::batch_common::{DeviceBatchGeometry, MAX_BATCH_TILES};
use crate::gpu_matrix::{Extension, MatrixSpec, RowOrder};
pub(crate) struct BatchPlan<'a> {
    pub(crate) trace: MatrixSpec,
    pub(crate) public: MatrixSpec,
    pub(crate) geometry: MatrixSpec,
    pub(crate) layout: DeviceBatchGeometry<'a>,
    pub(crate) peak: [MatrixSpec; 8],
    pub(crate) tiles: usize,
    pub(crate) height: usize,
}

impl<'a> BatchPlan<'a> {
    pub(crate) fn new(
        layout: DeviceBatchGeometry<'a>,
        count: usize,
        single: Plan,
        host_allowance: usize,
    ) -> Result<Self, String> {
        if count > MAX_BATCH_TILES {
            return Err("batch exceeds MAX_BATCH_TILES".into());
        }
        let tiles = count.max(1).next_power_of_two();
        let height = layout.height;
        let rows = height.checked_mul(tiles).ok_or("batch height overflow")?;
        if !height.is_power_of_two()
            || height < 32
            || layout.wallet_width < 8
            || rows > u32::MAX as usize
            || layout.wallet_width.checked_add(layout.public_width) != Some(layout.root_column)
            || layout.root_column.checked_add(4) != Some(layout.batch_width)
            || layout.fold_base.checked_add(layout.chunks.len()) != Some(layout.root_block)
            || layout.root_block >= height / 32
            || layout
                .root_block
                .checked_mul(32)
                .and_then(|r| r.checked_add(31))
                != Some(layout.root_output_row)
            || layout.chunks.is_empty()
            || layout
                .chunks
                .iter()
                .flatten()
                .flatten()
                .any(|&col| col < layout.wallet_width || col >= layout.root_column)
        {
            return Err("unsupported batch trace geometry".into());
        }
        if single.trace
            != MatrixSpec::new(
                height.ilog2(),
                layout.wallet_width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?
            || single.public
                != MatrixSpec::new(
                    0,
                    layout.public_width,
                    Extension::Base,
                    RowOrder::Natural,
                    1,
                )?
        {
            return Err("batch and wallet geometry differ".into());
        }
        let trace = MatrixSpec::new(
            rows.ilog2(),
            layout.batch_width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let public = MatrixSpec::new(0, 4, Extension::Base, RowOrder::Natural, 1)?;
        let geometry_words = layout
            .chunks
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(11))
            .ok_or("batch geometry size overflow")?;
        let single_bytes = single.staging_bytes()?;
        let host_bytes = geometry_words
            .checked_mul(8)
            .and_then(|n| n.checked_add(single_bytes))
            .ok_or("batch host staging overflow")?;
        if host_bytes > host_allowance {
            return Err("batch input staging exceeds host allowance".into());
        }
        let geometry = MatrixSpec::new(0, geometry_words, Extension::Base, RowOrder::Natural, 1)?;
        let [a, b, c, d, e] = single.specs()?;
        Ok(Self {
            trace,
            public,
            geometry,
            layout,
            peak: [trace, public, geometry, a, b, c, d, e],
            tiles,
            height,
        })
    }

    // Materialize only after host staging and aggregate device storage pass.
    pub(crate) fn words(&self) -> Result<Vec<u64>, String> {
        let layout = self.layout;
        let mut words = staging_words(self.geometry.words())?;
        words.extend([
            self.height as u64,
            layout.batch_width as u64,
            layout.wallet_width as u64,
            layout.public_width as u64,
            layout.fold_base as u64,
            layout.root_block as u64,
            layout.root_column as u64,
            layout.root_output_row as u64,
            self.tiles as u64,
            layout.chunks.len() as u64,
            crate::domains::DOM_TXROOT,
        ]);
        words.extend(
            layout
                .chunks
                .iter()
                .flatten()
                .map(|col| col.map_or(u64::MAX, |c| c as u64)),
        );
        debug_assert_eq!(words.len(), self.geometry.words());
        Ok(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_shapes_bound_padding_and_shared_staging_before_allocation() {
        const HOST: usize = 512 << 20;
        for count in [0usize, 1, 3, 8, MAX_BATCH_TILES] {
            for (layout, single) in [
                (
                    crate::batch_joinsplit_air::device_batch_geometry(),
                    Plan::new(HOST).unwrap(),
                ),
                (
                    crate::batch_htlc_air::device_batch_geometry(),
                    crate::gpu_wallet::htlc::plan(HOST).unwrap(),
                ),
            ] {
                let host = (11 + layout.chunks.len() * 4) * 8 + single.staging_bytes().unwrap();
                assert!(BatchPlan::new(layout, count, single, host - 1).is_err());
                let plan = BatchPlan::new(layout, count, single, host).unwrap();
                assert_eq!(plan.tiles, count.max(1).next_power_of_two());
                assert_eq!(
                    plan.trace.words(),
                    plan.tiles * layout.height * layout.batch_width
                );
                let words = plan.words().unwrap();
                assert_eq!(words.len(), plan.geometry.words());
                assert_eq!(words.capacity(), words.len());
                assert_eq!(plan.peak[3..], single.specs().unwrap());
            }
        }
        let single = Plan::new(HOST).unwrap();
        let layout = crate::batch_joinsplit_air::device_batch_geometry();
        for count in [MAX_BATCH_TILES + 1, usize::MAX] {
            assert!(BatchPlan::new(layout, count, single, HOST).is_err());
        }
        assert!(BatchPlan::new(
            layout,
            1,
            crate::gpu_wallet::htlc::plan(HOST).unwrap(),
            HOST
        )
        .is_err());
        let mut bad = layout;
        bad.root_output_row += 1;
        assert!(BatchPlan::new(bad, 1, single, HOST).is_err());
        let mut chunks = layout.chunks.to_vec();
        chunks[0][0] = Some(layout.batch_width);
        bad = layout;
        bad.chunks = &chunks;
        assert!(BatchPlan::new(bad, 1, single, HOST).is_err());
    }
}
