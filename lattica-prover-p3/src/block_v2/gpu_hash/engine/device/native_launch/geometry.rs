use super::*;

const Q: u64 = 167_770_241;
const QHAT: u64 = 3_489_661_057;
const MAX_WORDS: usize = 128 * 256;

pub(super) struct ArithmeticShape {
    pub(super) words: [usize; 4],
    pub(super) work_items: usize,
}
impl ArithmeticShape {
    pub(super) fn check(spec: &ArithmeticOperationSpec) -> Result<Self, Failure> {
        let fail = || Failure::shape(Kernel::Arithmetic);
        let m = &spec.metadata;
        if m.len() < 4 {
            return Err(fail());
        }
        let count = usize::try_from(m[2]).map_err(|_| fail())?;
        if count == 0 || count > MAX_WORDS {
            return Err(fail());
        }
        let q = m[1];
        let canonical = matches!(q, Q | QHAT);
        let (input, output, work, metadata) = match m[0] {
            1..=3 if canonical => (2 * count, count, count, 4),
            4 if canonical => (count, count, count, 4),
            5 if q == 0 => (count, count, count, 4),
            6 if q == 0 => (2 * count, count, count, 4),
            7 if canonical && count <= 128 => (256 * count, 256 * count, count, 3140),
            8 if canonical && count <= 128 => (512 * count, 256 * count, 64 * count, 2052),
            9 if q == Q && count == 1 => (256, 256, 256, 516),
            10 if q == 0 && count == 1 => (256, 256, 256, 516),
            _ => return Err(fail()),
        };
        if m.len() != metadata
            || m[3] != output as u64
            || (spec.input_words, spec.output_words, spec.work_items) != (input, output, work)
        {
            return Err(fail());
        }
        match m[0] {
            7 => {
                for step in m[4..3076].chunks_exact(4) {
                    if step[0] >= 256
                        || step[1] >= 256
                        || step[0] == step[1]
                        || step[2] >= q
                        || step[3] >= q
                    {
                        return Err(fail());
                    }
                }
                if !permutation(&m[3076..], 64) {
                    return Err(fail());
                }
            }
            8 => {
                if m[4..]
                    .chunks_exact(2)
                    .any(|term| term[0] >= q || term[1] > 1)
                {
                    return Err(fail());
                }
            }
            9 | 10 => {
                let limit = if m[0] == 9 { Q } else { 2 };
                if !permutation(&m[4..260], 256) || m[260..].iter().any(|&v| v >= limit) {
                    return Err(fail());
                }
            }
            _ => {}
        }
        Ok(Self {
            words: [input, metadata, output, work],
            work_items: work,
        })
    }
}

fn permutation(values: &[u64], count: usize) -> bool {
    let mut seen = [false; 256];
    if values.len() != count {
        return false;
    }
    for &value in values {
        if value >= count as u64 || seen[value as usize] {
            return false;
        }
        seen[value as usize] = true;
    }
    true
}

#[derive(Clone, Copy, Debug)]
pub(in crate::block_v2::gpu_hash::engine::device) enum CryptoKind {
    Aes { domain: u64, counter: u32 },
    Shake,
    UniformQ,
    UniformQhat,
    SparseAlpha,
    SparseX,
}
pub(super) struct CryptoShape {
    pub(super) words: [usize; 4],
    pub(super) geometry: [u64; 5],
    pub(super) launches: [(Kernel, usize); 2],
    pub(super) launch_count: usize,
}
impl CryptoShape {
    pub(super) fn new(kind: CryptoKind, input: usize, output: usize) -> Result<Self, Failure> {
        let (tag, domain, counter, kernel) = match kind {
            CryptoKind::Aes { domain, counter } => (0, domain, counter, Kernel::AesSboxes),
            CryptoKind::Shake => (1, 0, 0, Kernel::Shake),
            CryptoKind::UniformQ => (2, 0, 0, Kernel::Uniform),
            CryptoKind::UniformQhat => (3, 0, 0, Kernel::Uniform),
            CryptoKind::SparseAlpha => (4, 0, 0, Kernel::Sparse),
            CryptoKind::SparseX => (5, 0, 0, Kernel::Sparse),
        };
        let fail = || Failure::shape(kernel);
        if input > u32::MAX as usize
            || output > u32::MAX as usize
            || (tag == 0 && input != 32)
            || (tag == 4 && (input != 127 || output != 256))
            || (tag == 5 && (input != 137 || output != 256))
        {
            return Err(fail());
        }
        let blocks = output.div_ceil(16);
        if tag == 0 && blocks != 0 && counter.checked_add((blocks - 1) as u32).is_none() {
            return Err(fail());
        }
        Ok(Self {
            words: [
                input.max(1),
                5,
                if tag == 0 { 256 * 66 } else { 1 },
                output + 1,
            ],
            geometry: [tag, input as u64, output as u64, domain, counter as u64],
            launches: if tag == 0 {
                [(Kernel::AesSboxes, 256), (Kernel::Aes, blocks.max(1))]
            } else {
                [(kernel, 1), (kernel, 1)]
            },
            launch_count: if tag == 0 { 2 } else { 1 },
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(in crate::block_v2::gpu_hash::engine::device) enum NodeKind {
    CanonicalQ,
    CanonicalQhat,
    Signed,
    Bytes32,
}
impl NodeKind {
    pub(super) fn fields(self) -> (u32, u64, usize) {
        match self {
            Self::CanonicalQ => (0, Q, 256),
            Self::CanonicalQhat => (0, QHAT, 256),
            Self::Signed => (1, 0, 256),
            Self::Bytes32 => (2, 0, 32),
        }
    }
}
