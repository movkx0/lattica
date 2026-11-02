use super::*;
use lattica_prover_p3::block_v2::native_gpu::{NodeCommitment, operations_batch::COMMITMENT_BATCH_SIZE as MAX};

// The input references, index mapping and two result representations coexist.
// Packing/readback and GPU buffers are covered independently by the core API.
pub(in crate::rust_verify::committed_backend) const FRAME_BYTES: usize = 8 * (
    MAX * (core::mem::size_of::<NodeCommitment<'static>>() + core::mem::size_of::<usize>()
        + 2 * core::mem::size_of::<[Val; 4]>()) + 1024);

impl CommittedBackend<'_> {
    pub(in crate::rust_verify::committed_backend) fn finish_device_commitments(&mut self) -> Result<(), String> {
        if self.failure.is_some() { return Err("failed graph cannot finalize commitments".into()); }
        if !self.pending_commitments { return Ok(()); }
        let device = self.device.ok_or("pending commitments require GPU device")?;
        for group in 0..4 {
            let total = if group == 3 { self.graph.bytes.len() } else { self.graph.polynomials.len() };
            let mut next = 0;
            while next < total {
                let mut inputs = [NodeCommitment::Bytes(&[0; 32]); MAX];
                let mut indices = [0usize; MAX];
                let mut count = 0;
                while next < total && count < MAX {
                    let index = next; next += 1;
                    let input = if group == 3 { Some(NodeCommitment::Bytes(&self.graph.bytes[index].values)) }
                    else {
                        let node = &self.graph.polynomials[index];
                        match (&node.values, node.kind, group) {
                            (PolynomialValues::Canonical(values), PolynomialKind::Canonical { modulus: Q }, 0) => Some(NodeCommitment::Canonical { values, modulus: Q }),
                            (PolynomialValues::Canonical(values), PolynomialKind::Canonical { modulus: QHAT }, 1) => Some(NodeCommitment::Canonical { values, modulus: QHAT }),
                            (PolynomialValues::Signed(values), PolynomialKind::Signed { .. }, 2) => Some(NodeCommitment::Signed(values)),
                            _ => None,
                        }
                    };
                    if let Some(input) = input { inputs[count] = input; indices[count] = index; count += 1; }
                }
                if count == 0 { continue; }
                let roots = match device.commit_nodes(&inputs[..count]) {
                    Ok(roots) if roots.len() == count => roots,
                    Ok(_) => { self.failure = Some("GPU batch root count mismatch".into()); return Err("graph commitment finalization failed".into()); }
                    Err(error) => { self.failure = Some(error); return Err("graph commitment finalization failed".into()); }
                };
                for (index, root) in indices[..count].iter().copied().zip(roots) {
                    if group == 3 { self.graph.bytes[index].commitment = root; }
                    else { self.graph.polynomials[index].commitment = root; }
                }
            }
        }
        self.pending_commitments = false;
        Ok(())
    }
}
