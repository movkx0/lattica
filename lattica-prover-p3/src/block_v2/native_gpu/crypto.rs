//! Raw-byte inputs for device-owned crypto AIR traces. No host trace adapter.
use super::{GeneratedTrace, TraceContext};

#[derive(Clone, Copy, Debug)]
pub struct AesTraceSpec {
    pub domain: u64,
    pub start_counter: u32,
    pub output_len: usize,
    pub first_block: usize,
    pub blocks: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct ShakeTraceSpec {
    pub input_len: usize,
    pub output_len: usize,
    pub first_permutation: usize,
    pub permutations: usize,
}

impl TraceContext<'_> {
    pub fn aes_lane_trace(
        &self,
        key: &[u8; 32],
        spec: AesTraceSpec,
    ) -> Result<GeneratedTrace, String> {
        self.session.crypto_trace(
            0,
            key,
            spec.domain,
            spec.start_counter,
            32,
            spec.output_len,
            spec.first_block,
            spec.blocks,
            self.host_allowance,
            self.run,
        )
    }
    pub fn aes_wide_trace(
        &self,
        key: &[u8; 32],
        spec: AesTraceSpec,
    ) -> Result<GeneratedTrace, String> {
        self.session.crypto_trace(
            1,
            key,
            spec.domain,
            spec.start_counter,
            32,
            spec.output_len,
            spec.first_block,
            spec.blocks,
            self.host_allowance,
            self.run,
        )
    }
    pub fn shake_lane_trace(
        &self,
        input: &[u8],
        spec: ShakeTraceSpec,
    ) -> Result<GeneratedTrace, String> {
        self.session.crypto_trace(
            2,
            input,
            0,
            0,
            spec.input_len,
            spec.output_len,
            spec.first_permutation,
            spec.permutations,
            self.host_allowance,
            self.run,
        )
    }
    pub fn shake_lane_batch_trace(
        &self,
        input: &[u8],
        spec: ShakeTraceSpec,
    ) -> Result<GeneratedTrace, String> {
        self.session.crypto_trace(
            3,
            input,
            0,
            0,
            spec.input_len,
            spec.output_len,
            spec.first_permutation,
            spec.permutations,
            self.host_allowance,
            self.run,
        )
    }
    pub fn shake_wide_trace(
        &self,
        input: &[u8],
        spec: ShakeTraceSpec,
    ) -> Result<GeneratedTrace, String> {
        self.session.crypto_trace(
            4,
            input,
            0,
            0,
            spec.input_len,
            spec.output_len,
            spec.first_permutation,
            spec.permutations,
            self.host_allowance,
            self.run,
        )
    }
}
