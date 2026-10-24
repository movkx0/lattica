//! Fixed native rejection samplers. Only the raw AES/SHAKE output bytes cross
//! the host boundary; decisions, coefficients, trace and endpoint hashes are GPU work.
use super::{GeneratedTrace, TraceContext};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniformKind {
    SampleG4,
    ExpandAlpha2,
}
impl UniformKind {
    pub fn input_bytes(self) -> usize {
        match self {
            Self::SampleG4 => 1197 * 4,
            Self::ExpandAlpha2 => 643 * 4,
        }
    }
    pub fn rows(self) -> usize {
        match self {
            Self::SampleG4 => 2048,
            Self::ExpandAlpha2 => 1024,
        }
    }
    pub fn width(self) -> usize {
        445
    }
    pub(crate) fn code(self) -> u32 {
        match self {
            Self::SampleG4 => 0,
            Self::ExpandAlpha2 => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparseKind {
    AlphaPrime39,
    ChallengeX44,
}
impl SparseKind {
    pub fn input_bytes(self) -> usize {
        match self {
            Self::AlphaPrime39 => 127,
            Self::ChallengeX44 => 137,
        }
    }
    pub fn rows(self) -> usize {
        256
    }
    pub fn width(self) -> usize {
        506
    }
    pub(crate) fn code(self) -> u32 {
        match self {
            Self::AlphaPrime39 => 2,
            Self::ChallengeX44 => 3,
        }
    }
}

impl TraceContext<'_> {
    pub fn uniform_trace(&self, kind: UniformKind, bytes: &[u8]) -> Result<GeneratedTrace, String> {
        self.sampling_trace(
            kind.code(),
            kind.rows(),
            kind.width(),
            kind.input_bytes(),
            bytes,
        )
    }
    pub fn sparse_trace(&self, kind: SparseKind, bytes: &[u8]) -> Result<GeneratedTrace, String> {
        self.sampling_trace(
            kind.code(),
            kind.rows(),
            kind.width(),
            kind.input_bytes(),
            bytes,
        )
    }
    fn sampling_trace(
        &self,
        code: u32,
        rows: usize,
        width: usize,
        input: usize,
        bytes: &[u8],
    ) -> Result<GeneratedTrace, String> {
        if self.rows != rows
            || self.width != width
            || self.public_count != 8
            || bytes.len() != input
        {
            return Err("native sampler input/AIR geometry mismatch".into());
        }
        let (trace, public) =
            self.session
                .pq_sampling_trace(code, bytes, self.host_allowance, self.run)?;
        Ok(GeneratedTrace { trace, public })
    }
}
