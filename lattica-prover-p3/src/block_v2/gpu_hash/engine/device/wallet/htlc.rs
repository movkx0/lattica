//! HTLC raw witness encoding and AIR-owned layout. The shared wallet runner
//! bounds memory, scrubs private staging and records every completed kernel.
use super::*;
use crate::htlc_air as htlc;

pub(super) use crate::gpu_wallet::htlc::{input_words, plan, GEOMETRY_WORDS, INPUT_WORDS};

impl DeviceSession {
    pub(crate) fn htlc_witness(
        &self,
        witness: &htlc::Witness,
        host_allowance: usize,
        run: &crate::proving::Run,
    ) -> Result<WalletTrace, String> {
        self.generate_wallet(
            plan(host_allowance)?,
            &htlc::device_trace_geometry(),
            || input_words(witness),
            [
                "device_htlc_regions",
                "device_htlc_columns",
                "device_htlc_public",
            ],
            run,
        )
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests;
