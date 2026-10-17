//! Explicit device-only PCS output and pre-RNG admission of remaining host
//! random/salt staging. Legacy full/prefix modes preserve their prior layout.
use super::*;
use engine::lde_plan::LdeRetention;

impl CandidateMmcs {
    pub(crate) fn uses_device_storage(&self) -> bool {
        self.device_only
    }

    pub(super) fn lde_retention(&self, bits: usize) -> LdeRetention {
        if self.device_only {
            LdeRetention::DeviceOnly
        } else {
            LdeRetention::HostPrefix(bits)
        }
    }

    pub(super) fn plan_resident_storage(
        &self,
        inputs: &[LdeInputShape],
        host_budget: usize,
        bits: usize,
        capture: Option<usize>,
        extra_allocations: &[usize],
    ) -> Result<LdeCommitPlan, String> {
        if !self.gpu {
            return Err("resident PCS requires GPU commitments".into());
        }
        let plan = engine::plan_lde_commit_storage(
            inputs,
            self.cap_height,
            host_budget,
            self.lde_retention(bits),
            capture,
            extra_allocations,
        )?;
        if self.device_only {
            // Device output needs no host LDE allocation, but CPU-generated
            // hiding/mask/salt material is still bounded before drawing RNGs.
            // Count two input-sized buffers conservatively even for inputs
            // already on GPU, plus all pending sample/auxiliary allocations.
            let host_staging = extra_allocations.iter().try_fold(
                plan.projected_input_upload_bytes
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(plan.projected_salt_upload_bytes))
                    .ok_or("device PCS host staging size overflow")?,
                |total, bytes| {
                    total
                        .checked_add(*bytes)
                        .ok_or("device PCS host staging size overflow")
                },
            )?;
            if host_staging > host_budget {
                return Err("device PCS random/salt staging exceeds host allowance".into());
            }
            eprintln!(
                "bounded_device_pcs_host_staging planned_bytes={host_staging} allowance_bytes={host_budget} lde_output_bytes=0"
            );
        }
        Ok(plan)
    }

    pub(super) fn finish_lde_commit(
        &self,
        output: engine::lde_execute::LdeCommitOutput,
        salts: Vec<RowMajorMatrix<Val>>,
        preprocessing: bool,
    ) -> Result<
        (
            <Self as Mmcs<Val>>::Commitment,
            ProverData<RowMajorMatrix<Val>>,
        ),
        String,
    > {
        self.finish_lde_commit_with_salts(output, salts, preprocessing, Vec::new())
    }

    pub(super) fn finish_lde_commit_with_salts(
        &self,
        output: engine::lde_execute::LdeCommitOutput,
        salts: Vec<RowMajorMatrix<Val>>,
        preprocessing: bool,
        checkpoints: Vec<compact_salts::Checkpoints>,
    ) -> Result<(<Self as Mmcs<Val>>::Commitment, ProverData<RowMajorMatrix<Val>>), String> {
        let cap = <Self as Mmcs<Val>>::Commitment::new(output.cap().to_vec());
        let owned = (!output.device_matrices.is_empty()).then(|| {
            OwnedInputs::new(
                output.device_matrices,
                preprocessing,
                output.plan.output_height(),
            )
        });
        let data = match output.plan.retention {
            LdeRetention::DeviceOnly => {
                if !output.matrices.is_empty() || output.plan.host_output_bytes != 0 {
                    return Err("device-only commitment unexpectedly produced host LDEs".into());
                }
                ProverData::DeviceOnly {
                    owned: owned.ok_or("device-only commitment lost its owned prefixes")?,
                    salts: SaltStore::Host(salts),
                    tree: output.tree,
                }
            }
            LdeRetention::HostPrefix(0) => ProverData::GpuRetained {
                matrices: output.matrices,
                salts,
                tree: output.tree,
                owned,
            },
            LdeRetention::HostPrefix(_) => {
                let mut data = compact_data::CompactData::new(
                    output.prefixes,
                    output.plan.output_height(),
                    compact_salts::retain(salts, checkpoints),
                    output.tree,
                );
                data.owned = owned;
                ProverData::Compact(data)
            }
        };
        Ok((cap, data))
    }
}
