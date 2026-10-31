//! Bounded device trace descriptors for the unchanged MatRiCT arithmetic AIRs.
//! Descriptors contain public schedules only. Raw witness words are uploaded by
//! approved generators; this API cannot construct a trace from host trace rows.
use super::{GeneratedTrace, TraceContext};

pub const POSEIDON_COLUMNS: usize = 94;
const HEADER: usize = 32;
const MAX_COUNT: usize = 128;
const POLY_DOMAIN: u64 = 0x504f_4c59_5f50_5131;
const SIGNED_DOMAIN: u64 = 0x5349_474e_5051_3031;
const BUNDLE_DOMAIN: u64 = 0x4146_4649_4e45_3031;
const Q: u64 = 167_770_241;
const QHAT: u64 = 3_489_661_057;

#[derive(Clone, Debug)]
pub struct ArithmeticSpec {
    pub(crate) geometry: Vec<u64>,
    pub(crate) input_words: usize,
    pub(crate) public_words: usize,
}
impl ArithmeticSpec {
    fn new(
        family: u64,
        rows: usize,
        pose: usize,
        count: usize,
        input_words: usize,
        public_words: usize,
    ) -> Result<Self, String> {
        if !rows.is_power_of_two()
            || rows > 262_144
            || count == 0
            || count > MAX_COUNT
            || public_words == 0
            || public_words > 4096
        {
            return Err("invalid arithmetic trace shape".into());
        }
        let width = pose
            .checked_add(POSEIDON_COLUMNS)
            .ok_or("arithmetic width overflow")?;
        if width > 4096
            || rows
                .checked_mul(width)
                .and_then(|v| v.checked_mul(8))
                .is_none()
        {
            return Err("arithmetic trace size overflow".into());
        }
        let mut geometry = vec![0; HEADER];
        geometry[..5].copy_from_slice(&[
            family,
            rows as u64,
            width as u64,
            pose as u64,
            count as u64,
        ]);
        geometry[16] = POLY_DOMAIN;
        geometry[17] = SIGNED_DOMAIN;
        geometry[18] = BUNDLE_DOMAIN;
        Ok(Self {
            geometry,
            input_words,
            public_words,
        })
    }
    fn bits(modulus: u64) -> Result<usize, String> {
        match modulus {
            Q => Ok(28),
            QHAT => Ok(32),
            _ => Err("unsupported MatRiCT modulus".into()),
        }
    }
    fn range_width(bits: usize) -> usize {
        1 + bits + bits / 4
    }
    pub fn rows(&self) -> usize {
        self.geometry[1] as usize
    }
    pub fn width(&self) -> usize {
        self.geometry[2] as usize
    }
    pub fn public_values(&self) -> usize {
        self.public_words
    }
    pub fn raw_input_words(&self) -> usize {
        self.input_words
    }
    pub(crate) fn family(&self) -> u64 {
        self.geometry[0]
    }

    /// kind: 1 add, 2 subtract, 3 signed-to-canonical. Signed inputs are encoded
    /// as their original i64 two's-complement words, not precomputed field values.
    pub fn affine(modulus: u64, count: usize, kind: u64, bound: u32) -> Result<Self, String> {
        let bits = Self::bits(modulus)?;
        if !count.is_power_of_two()
            || count > MAX_COUNT
            || !(1..=3).contains(&kind)
            || (kind != 3 && bound != 0)
            || (kind == 3 && (bound == 0 || bound > i32::MAX as u32 || u64::from(bound) >= modulus))
        {
            return Err("invalid affine device descriptor".into());
        }
        let rw = Self::range_width(bits);
        let mbits = ((32 - (bound + 1).leading_zeros()) as usize)
            .max(1)
            .div_ceil(4)
            * 4;
        let mrw = Self::range_width(mbits);
        let magnitude = 32 + 4 * rw;
        let pose = magnitude + if kind == 3 { 4 * mrw } else { 0 };
        let mut s = Self::new(
            1,
            count * 512,
            pose,
            count,
            count * 256 * if kind == 3 { 1 } else { 2 },
            4,
        )?;
        let g = &mut s.geometry;
        g[5] = modulus;
        g[6] = bits as u64;
        g[7] = 32;
        g[8] = rw as u64;
        g[9] = 16;
        g[10] = 12;
        g[11] = kind;
        g[12] = bound as u64;
        g[13] = mbits as u64;
        g[14] = magnitude as u64;
        g[15] = mrw as u64;
        Ok(s)
    }
    /// Each immutable step is [address_a,address_b,factor_u,factor_v].
    pub fn ntt(
        modulus: u64,
        count: usize,
        steps: &[[u64; 4]],
        permutation: &[u64],
    ) -> Result<Self, String> {
        let bits = Self::bits(modulus)?;
        if count == 0
            || count > MAX_COUNT
            || steps.len() != 768
            || permutation.len() != 64
            || steps
                .iter()
                .any(|s| s[0] >= 256 || s[1] >= 256 || s[2] >= modulus || s[3] >= modulus)
            || permutation.iter().any(|&v| v >= 64)
        {
            return Err("invalid NTT device schedule".into());
        }
        let rw = Self::range_width(bits);
        let carry = 340 + 6 * rw;
        let acc = carry + 2;
        let mut s = Self::new(
            2,
            (count * 896).next_power_of_two(),
            acc + 4,
            count,
            count * 256,
            count * 8,
        )?;
        let g = &mut s.geometry;
        g[5] = modulus;
        g[6] = bits as u64;
        g[7] = 340;
        g[8] = rw as u64;
        g[9] = acc as u64;
        g[10] = carry as u64;
        g.extend(steps.iter().flatten().copied());
        g.extend_from_slice(permutation);
        Ok(s)
    }
    /// Immutable multiplication terms are [factor,negative] in block/i/j order.
    pub fn mul(modulus: u64, count: usize, terms: &[[u64; 2]]) -> Result<Self, String> {
        let bits = Self::bits(modulus)?;
        if count == 0
            || count > MAX_COUNT
            || terms.len() != 64 * 16
            || terms.iter().any(|t| t[0] >= modulus || t[1] > 1)
        {
            return Err("invalid multiplication device schedule".into());
        }
        let rw = Self::range_width(bits);
        let carry = 15 + 5 * rw;
        let acc = carry + 1;
        let mut s = Self::new(
            3,
            (count * 1216).next_power_of_two(),
            acc + 12,
            count,
            count * 512,
            count * 12,
        )?;
        let g = &mut s.geometry;
        g[5] = modulus;
        g[6] = bits as u64;
        g[7] = 15;
        g[8] = rw as u64;
        g[9] = acc as u64;
        g[10] = carry as u64;
        g.extend(terms.iter().flatten().copied());
        Ok(s)
    }
    /// kind: 1 canonical automorphism, 2 signed inverse challenge.
    pub fn permutation(kind: u64, sources: &[u64], factors: &[u64]) -> Result<Self, String> {
        if !(1..=2).contains(&kind)
            || sources.len() != 256
            || factors.len() != 256
            || sources.iter().any(|&v| v >= 256)
            || factors.iter().any(|&v| {
                if kind == 1 {
                    v >= Q
                } else {
                    v != 1 && v != 0xffff_ffff_0000_0000
                }
            })
        {
            return Err("invalid permutation device descriptor".into());
        }
        let bits = if kind == 1 { 28 } else { 4 };
        let rw = Self::range_width(bits);
        let quotient = 272 + 4 * rw;
        let mut s = Self::new(
            4,
            256,
            quotient + if kind == 1 { 4 * rw } else { 0 },
            1,
            256,
            8,
        )?;
        let g = &mut s.geometry;
        g[5] = if kind == 1 { Q } else { 2 };
        g[6] = bits as u64;
        g[7] = 272;
        g[8] = rw as u64;
        g[9] = 264;
        g[11] = kind;
        g[14] = quotient as u64;
        g.extend_from_slice(sources);
        g.extend_from_slice(factors);
        Ok(s)
    }
    /// Public schedule has 39 columns of period 128; psi powers are public
    /// transform constants. Raw signed inputs are f[256] followed by x[256].
    pub fn g_bound(
        f_bound: u32,
        g_bound: u32,
        schedule: &[u64],
        psi_128: u64,
        inv_psi_128: u64,
    ) -> Result<Self, String> {
        if !matches!((f_bound, g_bound), (5086, 6_825_771) | (565, 1_137_628))
            || schedule.len() != 39 * 128
            || schedule.iter().any(|&v| v >= 0xffff_ffff_0000_0001)
            || schedule
                .get(..16 * 128)
                .is_none_or(|addresses| addresses.iter().any(|&v| v >= 256))
            || psi_128 >= 0xffff_ffff_0000_0001
            || inv_psi_128 >= 0xffff_ffff_0000_0001
        {
            return Err("invalid GBound device schedule".into());
        }
        let mut s = Self::new(5, 4096, 756, 1, 512, 8)?;
        let g = &mut s.geometry;
        g[6] = 24;
        g[7] = 596;
        g[8] = 31;
        g[9] = 752;
        g[12] = f_bound as u64;
        g[13] = g_bound as u64;
        g[20] = psi_128;
        g[21] = inv_psi_128;
        g.extend_from_slice(schedule);
        Ok(s)
    }
    /// Immutable input/output kinds are [modulus_or_zero,signed_bound]. Public
    /// coefficients/constant are serialized original i64 words, never products.
    pub fn linear_map(
        kinds: &[[u64; 2]],
        coefficients: &[[i64; 256]],
        constant: &[i64; 256],
        bits: usize,
        quotient_bound: u64,
    ) -> Result<Self, String> {
        let inputs = coefficients.len();
        if inputs == 0
            || inputs > 16
            || kinds.len() != inputs + 1
            || bits == 0
            || bits > 32
            || bits % 4 != 0
            || quotient_bound > i32::MAX as u64
        {
            return Err("invalid linear-map device descriptor".into());
        }
        let canonical = kinds[inputs][0] != 0;
        for kind in kinds {
            if canonical {
                Self::bits(kind[0])?;
                if *kind != kinds[inputs] {
                    return Err("mixed linear-map kinds".into());
                }
            } else if kind[0] != 0 || kind[1] == 0 || kind[1] > i32::MAX as u64 {
                return Err("invalid signed linear-map kind".into());
            }
        }
        // Mirror the immutable descriptor's integer embedding bound before
        // device ulong products/positive-negative accumulation are admitted.
        const FIELD: u128 = 0xffff_ffff_0000_0001;
        for lane in 0..256 {
            let mut maximum = constant[lane].unsigned_abs() as u128;
            for (row, kind) in coefficients.iter().zip(kinds) {
                let bound = if canonical { kind[0] - 1 } else { kind[1] };
                maximum = maximum
                    .checked_add((row[lane].unsigned_abs() as u128) * (bound as u128))
                    .ok_or("linear-map integer bound overflow")?;
            }
            if canonical {
                let q = kinds[inputs][0] as u128;
                if 2 * maximum + 2 * q >= FIELD
                    || maximum + (q - 1) + (quotient_bound as u128) * q >= FIELD
                    || maximum.div_ceil(q) + 1 > quotient_bound as u128
                {
                    return Err("canonical linear-map integer embedding overflow".into());
                }
            } else if maximum + (kinds[inputs][1] as u128) >= FIELD {
                return Err("signed linear-map integer embedding overflow".into());
            }
        }
        let qbits = (64 - (2 * quotient_bound + 1).leading_zeros() as usize)
            .max(1)
            .div_ceil(4)
            * 4;
        let rw = Self::range_width(bits);
        let qrw = Self::range_width(qbits);
        let acc = 4 * inputs;
        let ranges = acc + 4 * (inputs + 1);
        let quo = ranges + 4 * rw;
        let pose = quo + if canonical { 4 * qrw } else { 0 };
        let stride = (inputs + 1).next_power_of_two();
        let mut s = Self::new(6, 64 * stride, pose, 1, inputs * 256, 4 * (inputs + 1))?;
        let g = &mut s.geometry;
        g[5] = kinds[inputs][0];
        g[6] = bits as u64;
        g[7] = ranges as u64;
        g[8] = rw as u64;
        g[9] = acc as u64;
        g[11] = if canonical { 1 } else { 2 };
        g[12] = quotient_bound;
        g[13] = qbits as u64;
        g[14] = quo as u64;
        g[15] = qrw as u64;
        g[20] = inputs as u64;
        g[21] = stride as u64;
        g.extend(kinds.iter().flatten().copied());
        g.extend(coefficients.iter().flatten().map(|&v| v as u64));
        g.extend(constant.iter().map(|&v| v as u64));
        Ok(s)
    }
}
impl TraceContext<'_> {
    /// Admit the bounded raw serialization before the research caller creates
    /// its temporary word vector. Device allocations are admitted together by
    /// the generator immediately before enqueueing work.
    pub fn admit_arithmetic_raw(&self, spec: &ArithmeticSpec) -> Result<(), String> {
        if spec.rows() != self.rows
            || spec.width() != self.width
            || spec.public_words != self.public_count
        {
            return Err("arithmetic generator differs from admitted AIR shape".into());
        }
        let words = spec
            .input_words
            .checked_add(spec.geometry.len())
            .and_then(|v| v.checked_add(spec.geometry[4] as usize))
            .ok_or("arithmetic staging overflow")?;
        if words
            .checked_mul(8)
            .is_none_or(|v| v > self.host_allowance || v > 64 << 20)
        {
            return Err("arithmetic raw input/metadata exceeds host admission".into());
        }
        Ok(())
    }
    pub fn arithmetic_trace(
        &self,
        spec: &ArithmeticSpec,
        input: &[u64],
    ) -> Result<GeneratedTrace, String> {
        if spec.rows() != self.rows
            || spec.width() != self.width
            || spec.public_words != self.public_count
            || input.len() != spec.input_words
        {
            return Err("arithmetic generator differs from admitted AIR shape".into());
        }
        self.session
            .research_arithmetic_trace(spec, input, self.host_allowance, self.run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_rejects_unsafe_schedules_and_integer_embeddings() {
        assert!(ArithmeticSpec::affine(Q, 3, 1, 0).is_err());
        assert!(ArithmeticSpec::affine(Q, 1, 3, Q as u32).is_err());
        assert!(ArithmeticSpec::ntt(Q, 1, &[[256, 0, 1, 1]; 768], &[0; 64]).is_err());
        assert!(ArithmeticSpec::mul(QHAT, 1, &[[QHAT, 0]; 1024]).is_err());
        assert!(ArithmeticSpec::permutation(1, &[0; 256], &[Q; 256]).is_err());
        assert!(ArithmeticSpec::permutation(2, &[0; 256], &[2; 256]).is_err());
        let mut schedule = vec![0; 39 * 128];
        schedule[15 * 128 + 127] = 256;
        assert!(ArithmeticSpec::g_bound(565, 1_137_628, &schedule, 1, 1).is_err());
        schedule[15 * 128 + 127] = 0;
        assert!(ArithmeticSpec::g_bound(565, 6_825_771, &schedule, 1, 1).is_err());
        assert!(ArithmeticSpec::linear_map(
            &[[0, 1], [0, 1]],
            &[[i64::MAX; 256]],
            &[i64::MAX; 256],
            4,
            0
        )
        .is_err());
        assert!(ArithmeticSpec::linear_map(
            &[[Q, 0], [Q, 0]],
            &[[i64::MAX; 256]],
            &[0; 256],
            28,
            1
        )
        .is_err());
    }
}
