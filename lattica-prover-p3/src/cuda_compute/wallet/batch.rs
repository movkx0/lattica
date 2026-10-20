//! Serial device assembly uses one temporary wallet frame for every tile.
//! Padding, statement folding and all trace columns stay on the device.
use super::*;
use crate::gpu_wallet::batch::BatchPlan;

impl Wallets {
    pub(crate) fn joinsplit_batch(
        &self,
        witnesses: &[crate::joinsplit_air::Witness],
        host_bytes: usize,
        run: &Run,
    ) -> Result<NativeWalletTrace> {
        let plan = BatchPlan::new(
            crate::batch_joinsplit_air::device_batch_geometry(),
            witnesses.len(),
            Plan::new(host_bytes)?,
            host_bytes,
        )?;
        self.generate_batch(
            plan,
            witnesses,
            crate::batch_joinsplit_air::dummy_witness,
            |w| self.joinsplit(w, host_bytes, run),
            run,
        )
    }

    pub(crate) fn htlc_batch(
        &self,
        witnesses: &[crate::htlc_air::Witness],
        host_bytes: usize,
        run: &Run,
    ) -> Result<NativeWalletTrace> {
        let plan = BatchPlan::new(
            crate::batch_htlc_air::device_batch_geometry(),
            witnesses.len(),
            gpu_wallet::htlc::plan(host_bytes)?,
            host_bytes,
        )?;
        self.generate_batch(
            plan,
            witnesses,
            crate::batch_htlc_air::dummy_witness,
            |w| self.htlc(w, host_bytes, run),
            run,
        )
    }

    fn generate_batch<W>(
        &self,
        plan: BatchPlan<'_>,
        witnesses: &[W],
        dummy: impl FnOnce() -> W,
        generate: impl Fn(&W) -> Result<NativeWalletTrace>,
        run: &Run,
    ) -> Result<NativeWalletTrace> {
        // Include the complete temporary frame before packing any private input.
        self.admit(&plan.peak, run)?;
        let words = plan.words()?;
        let trace = Matrix {
            spec: plan.trace,
            buffer: self.runtime.allocate(plan.trace.words())?,
        };
        let public = self.runtime.allocate(plan.public.words())?;
        let geometry = self.runtime.allocate(plan.geometry.words())?;
        geometry.write(0, &words)?;
        let copy = |tile: usize, frame: &NativeWalletTrace| -> Result<()> {
            // Shapes, tile bounds and both buffer owners are checked before launch.
            // Frames are constructed locally using this runtime's wallet generator.
            record(run, Stage::WitnessTrace, unsafe {
                self.batch[0].launch(
                    super::super::transform::linear_launch(plan.height)?,
                    &[
                        Argument::Buffer(&frame.trace.buffer),
                        Argument::Buffer(&frame.public),
                        Argument::Buffer(&geometry),
                        Argument::Buffer(&trace.buffer),
                        Argument::U32(tile as u32),
                    ],
                )
            })
        };
        for (tile, witness) in witnesses.iter().enumerate() {
            copy(tile, &generate(witness)?)?;
        }
        if witnesses.len() < plan.tiles {
            // The canonical dummy contains raw fields only. Its derived statement
            // and witness trace are generated once on CUDA and reused for padding.
            let frame = generate(&dummy())?;
            for tile in witnesses.len()..plan.tiles {
                copy(tile, &frame)?;
            }
        }
        record(run, Stage::WitnessTrace, unsafe {
            self.batch[1].launch(
                Launch {
                    blocks: 1,
                    threads: 1,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&geometry),
                    Argument::Buffer(&trace.buffer),
                    Argument::Buffer(&self.constants[0]),
                    Argument::Buffer(&self.constants[1]),
                    Argument::Buffer(&self.constants[2]),
                    Argument::Buffer(&self.constants[3]),
                ],
            )
        })?;
        record(run, Stage::PublicValues, unsafe {
            self.batch[2].launch(
                Launch {
                    blocks: 1,
                    threads: 4,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&trace.buffer),
                    Argument::Buffer(&geometry),
                    Argument::Buffer(&public),
                ],
            )
        })?;
        Ok(NativeWalletTrace { trace, public })
    }
}
