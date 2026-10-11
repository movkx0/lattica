//! Initial PCS query assembly using device prefixes and retained Merkle trees.
//! Host LDE values and the legacy compact reconstruction/cache are never read.
//! Device salts return only queried rows; host reference storage remains supported.
use super::*;
use device::{DeviceSession, Extension, RowOrder};
use p3_field::Field;

const HOST_METADATA: usize = 1 << 20;

#[cfg(test)]
mod tests;

impl CandidateMmcs {
    pub(crate) fn owned_query_host_bytes<M>(
        &self,
        data: &ProverData<M>,
        queries: usize,
    ) -> Result<usize, String> {
        let dimensions = data.owned_dimensions()?;
        if !self.gpu
            || queries == 0
            || queries > 256
            || dimensions.is_empty()
            || dimensions.len() > 256
        {
            return Err("owned PCS query requires bounded GPU commitment geometry".into());
        }
        let height = dimensions[0].height;
        if !height.is_power_of_two() || height > 1 << 25 {
            return Err("owned PCS query height exceeds its bound".into());
        }
        let mut fields = 0usize;
        for d in dimensions {
            if d.height != height || d.width == 0 || d.width > 4096 {
                return Err("owned PCS query requires equal heights and bounded columns".into());
            }
            fields += d.width + 4; // data and the four unchanged MMCS salts
        }
        let path_bytes = (height.ilog2() as usize).saturating_sub(self.cap_height) * 32;
        // At most one matrix's raw result and gather tile coexist with earlier
        // result rows. Include row/path/salt copies during final proof assembly.
        Ok(2 * queries * (fields * 8 + path_bytes) + HOST_METADATA)
    }

    pub(crate) fn open_owned_queries<M>(
        &self,
        session: &DeviceSession,
        data: &ProverData<M>,
        indices: &[usize],
        host_allowance: usize,
    ) -> Result<Vec<BatchOpening<Val, Self>>, String> {
        let host_peak = self.owned_query_host_bytes(data, indices.len())?;
        if host_peak > host_allowance {
            return Err("owned PCS queries exceed host proof allowance".into());
        }
        let dimensions = data.owned_dimensions()?;
        let height = dimensions[0].height;
        if indices.iter().any(|i| *i >= height) {
            return Err("owned PCS query outside commitment".into());
        }
        let (salts, tree) = match data {
            ProverData::GpuRetained { salts, tree, .. } => {
                (super::salt_data::SaltView::Host(salts), tree)
            }
            ProverData::DeviceOnly { salts, tree, .. } => (salts.view(), tree),
            ProverData::Compact(d) => (super::salt_data::SaltView::Host(&d.salts), &d.tree),
            _ => return Err("owned PCS query requires retained salts and tree".into()),
        };
        salts.validate(session, height, dimensions.len())?;
        // Validate every owner/layout before reconstructing any matrix. Public
        // preprocessing imports are aliases; private inputs cannot cross jobs.
        let prefixes: Vec<_> = (0..dimensions.len())
            .map(|i| data.owned_matrix(session, i))
            .collect::<Result<_, _>>()?;
        for (prefix, d) in prefixes.iter().zip(dimensions) {
            let s = prefix.spec();
            if s.rows() != height >> super::super::profile::LOG_BLOWUP
                || s.columns() != d.width
                || s.extension() != Extension::Base
                || s.order() != RowOrder::BitReversed
                || s.shift() != Val::GENERATOR.as_canonical_u64()
            {
                return Err("owned PCS query prefix does not match commitment".into());
            }
        }
        let mut values: Vec<Vec<Vec<Val>>> = (0..indices.len())
            .map(|_| Vec::with_capacity(dimensions.len()))
            .collect();
        let mut retained_value_bytes = 0;
        for prefix in &prefixes {
            let width = prefix.spec().columns();
            let rows = session.query_rows(
                prefix,
                height.ilog2(),
                indices,
                host_peak - retained_value_bytes - HOST_METADATA / 2,
            )?;
            for (query, row) in rows.chunks_exact(width).enumerate() {
                values[query].push(row.iter().map(|v| Val::new(*v)).collect());
            }
            retained_value_bytes += indices.len() * width * 8;
        }
        let salt_rows = salts.gather(session, indices, host_peak - retained_value_bytes)?;
        indices
            .iter()
            .zip(values)
            .zip(salt_rows)
            .map(|((&index, values), salt_rows)| {
                let path = tree.open(index, self.cap_height)?;
                Ok(BatchOpening::new(values, (salt_rows, path)))
            })
            .collect()
    }
}
