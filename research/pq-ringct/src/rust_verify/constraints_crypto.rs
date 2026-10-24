//! Cryptographic transcript and exact bounded samplers for the arithmetic
//! MatRiCT component. SHAKE and AES requests are explicit proof obligations.
//! Merely constructing this component does not prove those requests or yield a
//! complete MatRiCT leaf. A joining verifier must prove every request and bind
//! its exact input/output commitments before accepting the arithmetic component.

use super::{
    constraints::{ByteValue, ConstraintContext, ResidueValue, SignedValue},
    generic::{GParameters, GStatement, Polynomial},
    primitives, VerifyError, D, Q,
};
use lattica_prover_p3::block_v2::machine::{
    pq_bytes::{self, Byte},
    pq_modular as modular,
    program::{ScopedProgramBuilder, Val, Wire},
};
use p3_field::PrimeCharacteristicRing;

/// A request, not a verified digest. Lengths and request order are part of the
/// trusted arithmetic program shape and must be fixed by its registration.
#[derive(Clone, Debug)]
pub struct PendingShake {
    pub input: Vec<ByteValue>,
    pub output: Vec<ByteValue>,
    pub input_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}

/// The author's fixed AES-256 counter stream. A partial final block discards
/// its unused bytes. The next request has an explicitly fixed start counter.
#[derive(Clone, Debug)]
pub struct PendingAes {
    pub key: [ByteValue; 32],
    pub domain: u64,
    pub start_counter: u32,
    pub output: Vec<ByteValue>,
    pub input_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}

pub const AES_INPUT_DOMAIN: u64 = 0x4145_535f_4354_5249;
pub const AES_OUTPUT_DOMAIN: u64 = 0x4145_535f_4354_524f;

/// There is deliberately no conversion from these obligations to a verified
/// leaf. Host execution of SHAKE/AES supplies witness hints only.
pub struct CryptoObligations {
    pub fixed_setup_seed: [u8; 32],
    pub shake: Vec<PendingShake>,
    pub aes: Vec<PendingAes>,
    pub ntt: Vec<super::constraints_ntt::PendingNtt>,
    pub mul: Vec<super::constraints_poly::PendingMul>,
    pub(crate) polynomial_commitments: std::collections::BTreeMap<(u64, [Wire; 256]), [Wire; 4]>,
}
impl CryptoObligations {
    pub fn new(fixed_setup_seed: [u8; 32]) -> Self {
        Self {
            fixed_setup_seed,
            shake: Vec::new(),
            aes: Vec::new(),
            ntt: Vec::new(),
            mul: Vec::new(),
            polynomial_commitments: std::collections::BTreeMap::new(),
        }
    }
}

fn commit(b: &mut ScopedProgramBuilder<'_>, domain: u64, bytes: &[ByteValue]) -> [Wire; 4] {
    pq_bytes::poseidon_commit_bytes(
        b,
        domain,
        &bytes.iter().map(|x| x.constrained).collect::<Vec<_>>(),
    )
}

fn request_shake(
    c: &mut ConstraintContext<'_, '_>,
    input: Vec<ByteValue>,
    len: usize,
) -> Vec<ByteValue> {
    let native = primitives::shake(&input.iter().map(|x| x.value).collect::<Vec<_>>(), len);
    let output: Vec<_> = native.into_iter().map(|x| c.byte(x)).collect();
    let input_commitment = commit(c.builder, pq_bytes::SHAKE_INPUT_DOMAIN, &input);
    let output_commitment = commit(c.builder, pq_bytes::SHAKE_OUTPUT_DOMAIN, &output);
    c.crypto.shake.push(PendingShake {
        input,
        output: output.clone(),
        input_commitment,
        output_commitment,
    });
    output
}

fn request_aes(
    c: &mut ConstraintContext<'_, '_>,
    key: &[ByteValue; 32],
    domain: u64,
    start_counter: u32,
    len: usize,
) -> Vec<ByteValue> {
    let mut native = primitives::AesStream::new(&key.map(|x| x.value), domain);
    // This is witness generation only; the fixed start counter is committed.
    if start_counter != 0 {
        let _ = native.bytes(start_counter as usize * 16);
    }
    let output: Vec<_> = native.bytes(len).into_iter().map(|x| c.byte(x)).collect();
    let mut input = key.to_vec();
    input.extend(domain.to_le_bytes().map(|x| c.constant_byte(x)));
    input.extend(start_counter.to_le_bytes().map(|x| c.constant_byte(x)));
    input.extend((len as u64).to_le_bytes().map(|x| c.constant_byte(x)));
    let input_commitment = commit(c.builder, AES_INPUT_DOMAIN, &input);
    let output_commitment = commit(c.builder, AES_OUTPUT_DOMAIN, &output);
    c.crypto.aes.push(PendingAes {
        key: *key,
        domain,
        start_counter,
        output: output.clone(),
        input_commitment,
        output_commitment,
    });
    output
}

/// A sound, potentially expensive option for discharging one AES obligation
/// inside the same program. Segmented proof adapters must instead bind both
/// commitments, including key/domain/start counter/output byte count.
pub fn constrain_aes_inline(b: &mut ScopedProgramBuilder<'_>, request: &PendingAes) {
    let key = pq_bytes::Aes256Key::expand(b, &request.key.map(|x| x.constrained));
    let result = key.ctr(
        b,
        request.domain,
        request.start_counter,
        request.output.len(),
    );
    for (actual, expected) in result.into_iter().zip(&request.output) {
        let actual = actual.to_wire(b);
        let expected = expected.constrained.to_wire(b);
        b.assert_equal(actual, expected);
    }
}

fn bits(b: &mut ScopedProgramBuilder<'_>, value: Wire, count: usize) -> Vec<Wire> {
    modular::bounded_bits(b, value, count as u32).expect("fixed bounded bit width")
}

/// Exact comparison on already Boolean little-endian bits. No host branch
/// depends on the candidate; only public bound bits select the program shape.
fn less_than(b: &mut ScopedProgramBuilder<'_>, little: &[Wire], bound: u64) -> Wire {
    assert!(little.len() < 63 && bound < (1u64 << little.len()));
    let zero = b.constant(Val::ZERO);
    let one = b.constant(Val::ONE);
    let mut result = zero;
    for (i, &bit) in little.iter().enumerate() {
        result = if (bound >> i) & 1 == 1 {
            b.select(bit, one, result)
        } else {
            b.select(bit, result, zero)
        };
    }
    result
}

fn not(b: &mut ScopedProgramBuilder<'_>, bit: Wire) -> Wire {
    let one = b.constant(Val::ONE);
    b.sub(one, bit)
}

/// A fixed binary multiplexer. The index never affects compilation or witness
/// allocation order. `values` must have a power-of-two length.
fn select(b: &mut ScopedProgramBuilder<'_>, values: &[Wire], index: &[Wire]) -> Wire {
    assert_eq!(values.len(), 1usize << index.len());
    let mut layer = values.to_vec();
    for &bit in index {
        layer = layer
            .chunks_exact(2)
            .map(|pair| b.select(bit, pair[0], pair[1]))
            .collect();
    }
    layer[0]
}

fn one_hot(b: &mut ScopedProgramBuilder<'_>, index: &[Wire]) -> Vec<Wire> {
    let zero = b.constant(Val::ZERO);
    let mut layer = vec![b.constant(Val::ONE)];
    for &bit in index {
        let low: Vec<_> = layer.iter().map(|&v| b.select(bit, v, zero)).collect();
        let high = layer
            .iter()
            .map(|&v| b.select(bit, zero, v))
            .collect::<Vec<_>>();
        layer = low;
        layer.extend(high);
    }
    layer
}

fn packed(b: &mut ScopedProgramBuilder<'_>, bytes: &[ByteValue]) -> Wire {
    let mut value = b.constant(Val::ZERO);
    for (i, byte) in bytes.iter().enumerate() {
        let byte = byte.constrained.to_wire(b);
        let weight = b.constant(Val::from_u64(1u64 << (8 * i)));
        let term = b.mul(byte, weight);
        value = b.add(value, term);
    }
    value
}

/// Return exactly the first `count` accepted u32 draws, reduced modulo q.
/// Every draw in the fixed author buffer is classified. Once enough draws
/// have been accepted the counter saturates; discarded tail cannot alter output.
fn uniform(
    c: &mut ConstraintContext<'_, '_>,
    bytes: &[ByteValue],
    count: usize,
) -> Result<Vec<ResidueValue>, VerifyError> {
    assert!(count.is_power_of_two());
    assert_eq!(bytes.len() % 4, 0);
    const BOUND: u64 = 4_194_256_025; // 25*q, as in the author sampler.
    let mut native = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(4) {
        let value = u32::from_le_bytes(
            chunk
                .try_into()
                .map(|x: [ByteValue; 4]| x.map(|x| x.value))
                .unwrap(),
        ) as u64;
        if value < BOUND && native.len() < count {
            native.push(value % Q);
        }
    }
    if native.len() != count {
        return Err(VerifyError::SamplingExhausted);
    }
    let out: Vec<_> = native.into_iter().map(|x| c.residue(x, Q)).collect();
    let out_wires: Vec<_> = out.iter().map(|x| x.constrained.wire()).collect();
    let zero = c.builder.constant(Val::ZERO);
    let mut accepted_count = zero;
    let index_bits = count.trailing_zeros() as usize;
    for chunk in bytes.chunks_exact(4) {
        let candidate_bits: Vec<_> = chunk.iter().flat_map(|x| x.constrained.bits()).collect();
        let accepted = less_than(c.builder, &candidate_bits, BOUND);
        let count_bits = bits(c.builder, accepted_count, index_bits + 1);
        let remaining = not(c.builder, count_bits[index_bits]);
        let take = c.builder.mul(accepted, remaining);
        let selected = select(c.builder, &out_wires, &count_bits[..index_bits]);
        let value = u32::from_le_bytes(
            chunk
                .try_into()
                .map(|x: [ByteValue; 4]| x.map(|x| x.value))
                .unwrap(),
        ) as u64;
        let quotient = c.input(value / Q);
        modular::assert_at_most(c.builder, quotient, u32::MAX as u64 / Q)
            .expect("u32 quotient bound");
        let residue = c.residue(value % Q, Q);
        let q = c.builder.constant(Val::from_u64(Q));
        let multiple = c.builder.mul(quotient, q);
        let reconstructed = c.builder.add(multiple, residue.constrained.wire());
        let candidate = packed(c.builder, chunk);
        c.builder.assert_equal(candidate, reconstructed);
        let delta = c.builder.sub(selected, residue.constrained.wire());
        let error = c.builder.mul(take, delta);
        c.builder.assert_zero(error);
        accepted_count = c.builder.add(accepted_count, take);
    }
    let expected = c.builder.constant(Val::from_usize(count));
    c.builder.assert_equal(accepted_count, expected);
    Ok(out)
}

fn serialize(
    c: &mut ConstraintContext<'_, '_>,
    out: &mut Vec<ByteValue>,
    polys: &[Polynomial<ResidueValue>],
) {
    for poly in polys {
        for coefficient in poly {
            let decomposition = bits(c.builder, coefficient.constrained.wire(), 32);
            for i in 0..4 {
                out.push(ByteValue {
                    value: (coefficient.value >> (8 * i)) as u8,
                    constrained: Byte::from_bits(
                        c.builder,
                        decomposition[8 * i..8 * i + 8].try_into().unwrap(),
                    ),
                });
            }
        }
    }
}

pub fn parameters(
    c: &mut ConstraintContext<'_, '_>,
    seed: &[ByteValue; 32],
    context: &[ByteValue; 32],
) -> Result<GParameters<ResidueValue, ByteValue>, VerifyError> {
    let fixed = c.crypto.fixed_setup_seed;
    for (byte, expected) in seed.iter().zip(fixed) {
        let actual = byte.constrained.to_wire(c.builder);
        let expected = c.builder.constant(Val::from_u8(expected));
        c.builder.assert_equal(actual, expected);
    }
    // These matrices depend only on registered network setup constants, never
    // transaction witnesses. Context only affects the separately proved PP hash.
    let native = primitives::parameters(&fixed, &[0; 32])?;
    let mut setup = fixed.to_vec();
    setup.extend_from_slice(&[64, 4, 4, 4, 5, 5]);
    setup.extend_from_slice(&256u16.to_le_bytes());
    setup.extend_from_slice(&(Q as u32).to_le_bytes());
    setup.extend_from_slice(&(super::QHAT as u32).to_le_bytes());
    setup.push(44);
    let setup_hash = primitives::shake(&setup, 32);
    let mut binding: Vec<_> = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1"
        .iter()
        .copied()
        .chain(setup_hash)
        .map(|x| c.constant_byte(x))
        .collect();
    binding.extend_from_slice(context);
    let pp: [ByteValue; 32] = request_shake(c, binding, 32).try_into().unwrap();
    let mat1 = native
        .mat1
        .iter()
        .map(|row| {
            row.iter()
                .map(|p| p.map(|x| c.constant_residue(x, Q)))
                .collect()
        })
        .collect();
    let mat2 = native
        .mat2
        .iter()
        .map(|row| {
            row.iter()
                .map(|p| p.map(|x| c.constant_residue(x, Q)))
                .collect()
        })
        .collect();
    let mat3 = native
        .mat3
        .iter()
        .map(|row| {
            row.iter()
                .map(|p| p.map(|x| c.constant_residue(x, super::QHAT)))
                .collect()
        })
        .collect();
    Ok(GParameters {
        mat1,
        mat2,
        mat3,
        pp,
    })
}

pub fn sample_g(
    c: &mut ConstraintContext<'_, '_>,
    seed: &[ByteValue; 32],
) -> Result<Vec<Polynomial<ResidueValue>>, VerifyError> {
    let bytes = request_aes(c, seed, 0, 0, 1197 * 4);
    let coefficients = uniform(c, &bytes, 4 * D)?;
    Ok(coefficients
        .chunks_exact(D)
        .map(|p| p.try_into().unwrap())
        .collect())
}

fn sparse_alpha(
    c: &mut ConstraintContext<'_, '_>,
    bytes: &[ByteValue],
) -> Result<Polynomial<SignedValue>, VerifyError> {
    assert_eq!(bytes.len(), 127);
    let zero = c.builder.constant(Val::ZERO);
    let one = c.builder.constant(Val::ONE);
    let mut signs: Vec<_> = bytes[..5]
        .iter()
        .flat_map(|x| x.constrained.bits())
        .collect();
    signs.resize(64, zero);
    let mut used = [zero; D];
    let mut output = [zero; D];
    let mut native_output = [0i64; D];
    let mut native_used = [false; D];
    let mut native_count = 0usize;
    let native_signs = bytes[..5]
        .iter()
        .enumerate()
        .fold(0u64, |v, (i, b)| v | ((b.value as u64) << (8 * i)));
    let mut count = zero;
    for byte in &bytes[5..] {
        let index = byte.constrained.bits();
        let count_bits = bits(c.builder, count, 6);
        let remaining = less_than(c.builder, &count_bits, 39);
        let duplicate = select(c.builder, &used, &index);
        let fresh = not(c.builder, duplicate);
        let take = c.builder.mul(fresh, remaining);
        let sign_bit = select(c.builder, &signs, &count_bits);
        let two = c.builder.constant(Val::from_u8(2));
        let twice = c.builder.mul(two, sign_bit);
        let sign = c.builder.sub(one, twice);
        let selection = one_hot(c.builder, &index);
        for i in 0..D {
            let choose = c.builder.mul(take, selection[i]);
            used[i] = c.builder.add(used[i], choose);
            let term = c.builder.mul(choose, sign);
            output[i] = c.builder.add(output[i], term);
        }
        count = c.builder.add(count, take);
        let position = byte.value as usize;
        if !native_used[position] && native_count < 39 {
            native_used[position] = true;
            native_output[position] = 1 - 2 * ((native_signs >> native_count) & 1) as i64;
            native_count += 1;
        }
    }
    if native_count != 39 {
        return Err(VerifyError::SamplingExhausted);
    }
    let required = c.builder.constant(Val::from_u8(39));
    c.builder.assert_equal(count, required);
    Ok(std::array::from_fn(|i| SignedValue {
        value: native_output[i],
        constrained: modular::signed(c.builder, output[i], 1).expect("ternary coefficient"),
    }))
}

pub fn expand_alpha(
    c: &mut ConstraintContext<'_, '_>,
    seed: &[ByteValue; 32],
) -> Result<(Vec<Polynomial<ResidueValue>>, Polynomial<SignedValue>), VerifyError> {
    let bytes = request_aes(c, seed, 0x4368, 0, 643 * 4);
    let alpha = uniform(c, &bytes, 2 * D)?
        .chunks_exact(D)
        .map(|p| p.try_into().unwrap())
        .collect();
    // 2572 bytes consume 161 complete AES blocks, including 4 discarded bytes.
    let bytes = request_aes(c, seed, 0x4368, 161, 127);
    Ok((alpha, sparse_alpha(c, &bytes)?))
}

#[allow(clippy::too_many_arguments)]
pub fn hash_alpha(
    c: &mut ConstraintContext<'_, '_>,
    pp: &[ByteValue; 32],
    s: &GStatement<ResidueValue, ByteValue>,
    w_out: &[Vec<Polynomial<ResidueValue>>],
    w0: &[Polynomial<ResidueValue>],
    v: &[Polynomial<ResidueValue>],
    v2: &Polynomial<ResidueValue>,
    poly_c: &Polynomial<ResidueValue>,
    w: &Polynomial<ResidueValue>,
    w1: &[Polynomial<ResidueValue>],
    w2: &[Polynomial<ResidueValue>],
) -> [ByteValue; 32] {
    let mut input = pp.to_vec();
    for pair in &s.ring {
        for account in pair {
            serialize(c, &mut input, &account.pk);
            serialize(c, &mut input, &account.cn);
        }
    }
    for serial in &s.serials {
        input.extend_from_slice(serial);
    }
    for polys in &s.recipients {
        serialize(c, &mut input, polys);
    }
    for polys in &s.coins {
        serialize(c, &mut input, polys);
    }
    for polys in w_out {
        serialize(c, &mut input, polys);
    }
    serialize(c, &mut input, w0);
    serialize(c, &mut input, v);
    for poly in [v2, poly_c, w] {
        serialize(c, &mut input, std::slice::from_ref(poly));
    }
    serialize(c, &mut input, w1);
    serialize(c, &mut input, w2);
    request_shake(c, input, 32).try_into().unwrap()
}

fn sparse_x(
    c: &mut ConstraintContext<'_, '_>,
    bytes: &[ByteValue],
) -> Result<Polynomial<SignedValue>, VerifyError> {
    assert_eq!(bytes.len(), 137);
    let zero = c.builder.constant(Val::ZERO);
    let one = c.builder.constant(Val::ONE);
    let two = c.builder.constant(Val::from_u8(2));
    let mut signs: Vec<_> = bytes[..6]
        .iter()
        .flat_map(|x| x.constrained.bits())
        .collect();
    signs.resize(64, zero);
    let native_signs = bytes[..6]
        .iter()
        .enumerate()
        .fold(0u64, |v, (i, b)| v | ((b.value as u64) << (8 * i)));
    let mut used = [[zero; 64]; 4];
    let mut output = [zero; D];
    let mut native_used = [[false; 64]; 4];
    let mut native_output = [0i64; D];
    for group in 0..4 {
        let index = bytes[6 + group].constrained.bits();
        let selection = one_hot(c.builder, &index[..6]);
        let twice = c.builder.mul(two, signs[group]);
        let sign = c.builder.sub(one, twice);
        for i in 0..64 {
            used[group][i] = selection[i];
            output[4 * i + group] = c.builder.mul(selection[i], sign);
        }
        let i = (bytes[6 + group].value & 63) as usize;
        native_used[group][i] = true;
        native_output[4 * i + group] = 1 - 2 * ((native_signs >> group) & 1) as i64;
    }
    let mut count = c.builder.constant(Val::from_u8(4));
    let mut native_count = 4usize;
    for byte in &bytes[10..] {
        let count_bits = bits(c.builder, count, 6);
        let thresholds: [Wire; 4] =
            std::array::from_fn(|g| less_than(c.builder, &count_bits, (14 + 10 * g) as u64));
        let active: [Wire; 4] = std::array::from_fn(|g| {
            if g == 0 {
                thresholds[0]
            } else {
                c.builder.sub(thresholds[g], thresholds[g - 1])
            }
        });
        let index = byte.constrained.bits();
        let mut duplicate = zero;
        for group in 0..4 {
            let bit = select(c.builder, &used[group], &index[..6]);
            let term = c.builder.mul(active[group], bit);
            duplicate = c.builder.add(duplicate, term);
        }
        let fresh = not(c.builder, duplicate);
        let take = c.builder.mul(fresh, thresholds[3]);
        let sign_bit = select(c.builder, &signs, &count_bits);
        let twice = c.builder.mul(two, sign_bit);
        let sign = c.builder.sub(one, twice);
        let selection = one_hot(c.builder, &index[..6]);
        for group in 0..4 {
            let take_group = c.builder.mul(take, active[group]);
            for i in 0..64 {
                let choose = c.builder.mul(take_group, selection[i]);
                used[group][i] = c.builder.add(used[group][i], choose);
                let term = c.builder.mul(choose, sign);
                output[4 * i + group] = c.builder.add(output[4 * i + group], term);
            }
        }
        count = c.builder.add(count, take);
        if native_count < 44 {
            let group = (native_count - 4) / 10;
            let i = (byte.value & 63) as usize;
            if !native_used[group][i] {
                native_used[group][i] = true;
                native_output[4 * i + group] = 1 - 2 * ((native_signs >> native_count) & 1) as i64;
                native_count += 1;
            }
        }
    }
    if native_count != 44 {
        return Err(VerifyError::SamplingExhausted);
    }
    let required = c.builder.constant(Val::from_u8(44));
    c.builder.assert_equal(count, required);
    Ok(std::array::from_fn(|i| SignedValue {
        value: native_output[i],
        constrained: modular::signed(c.builder, output[i], 1).expect("ternary coefficient"),
    }))
}

pub fn hash_x(
    c: &mut ConstraintContext<'_, '_>,
    alpha: &[ByteValue; 32],
    v0: &Polynomial<ResidueValue>,
    v1: &Polynomial<ResidueValue>,
    a: &[Polynomial<ResidueValue>],
    b: &[Polynomial<ResidueValue>],
    e: &[Polynomial<ResidueValue>],
) -> Result<Polynomial<SignedValue>, VerifyError> {
    let mut input = alpha.to_vec();
    serialize(c, &mut input, std::slice::from_ref(v0));
    serialize(c, &mut input, std::slice::from_ref(v1));
    serialize(c, &mut input, a);
    serialize(c, &mut input, b);
    serialize(c, &mut input, e);
    let bytes = request_shake(c, input, 137);
    sparse_x(c, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::{MachineAir, Program, ProgramBuilder};

    fn uniform_program(raw: &[u32]) -> (Program, Vec<Val>, Vec<u64>) {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let bytes: Vec<_> = raw
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .map(|x| c.byte(x))
            .collect();
        let result = uniform(&mut c, &bytes, 2).unwrap();
        let values = result.iter().map(|x| x.value).collect();
        (builder.finish(None).unwrap(), witness, values)
    }

    #[test]
    fn uniform_classifies_rejections_and_binds_order_with_fixed_shape() {
        let raw = [4_194_256_025, u32::MAX, 7, (Q + 9) as u32, 11];
        let (program, witness, values) = uniform_program(&raw);
        assert_eq!(values, vec![7, 9]);
        let (other, _, other_values) = uniform_program(&[1, 2, 3, 4, 5]);
        assert_eq!(other_values, vec![1, 2]);
        assert_eq!(
            program, other,
            "sampling decisions must not alter program shape"
        );
        let air = MachineAir::new(program);
        air.trace(&[], &witness).unwrap();
        let mut skipped = witness.clone();
        // Turn a rejected draw into an accepted zero; output hints remain 7,9.
        skipped[..4].fill(Val::ZERO);
        assert!(air.trace(&[], &skipped).is_err());
        let mut swapped = witness.clone();
        swapped.swap(raw.len() * 4, raw.len() * 4 + 1);
        assert!(air.trace(&[], &swapped).is_err());
        let mut wrong_reduction = witness.clone();
        wrong_reduction[raw.len() * 4] += Val::ONE;
        assert!(air.trace(&[], &wrong_reduction).is_err());
    }

    #[test]
    fn sparse_alpha_consumes_duplicates_and_binds_signs() {
        let mut raw = [0u8; 127];
        raw[..5].copy_from_slice(&[0x55, 0xaa, 0x81, 0x70, 0x3f]);
        for i in 0..78 {
            raw[5 + i] = (i / 2) as u8;
        }
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let bytes: Vec<_> = raw.into_iter().map(|x| c.byte(x)).collect();
        let output = sparse_alpha(&mut c, &bytes).unwrap();
        let sign_bits = u64::from_le_bytes([0x55, 0xaa, 0x81, 0x70, 0x3f, 0, 0, 0]);
        for (i, x) in output.iter().enumerate() {
            let expected = if i < 39 {
                1 - 2 * ((sign_bits >> i) & 1) as i64
            } else {
                0
            };
            assert_eq!(x.value, expected);
            let expected = c.constant_signed(expected, 1);
            c.builder
                .assert_equal(x.constrained.wire(), expected.constrained.wire());
        }
        let air = MachineAir::new(builder.finish(None).unwrap());
        air.trace(&[], &witness).unwrap();
        let mut signs = witness.clone();
        signs[0] = Val::from_u8(raw[0] ^ 1);
        assert!(air.trace(&[], &signs).is_err());
        let mut index = witness;
        index[5] = Val::from_u8(100);
        assert!(air.trace(&[], &index).is_err());
    }

    #[test]
    fn sparse_x_binds_four_initial_draws_and_sequential_groups() {
        let mut raw = [0u8; 137];
        raw[..6].copy_from_slice(&[0x13, 0x87, 0x55, 0x19, 0x23, 0x41]);
        raw[6..10].copy_from_slice(&[0, 1, 2, 3]);
        for i in 10..137 {
            raw[i] = ((i - 10) % 64) as u8;
        }
        let signs = u64::from_le_bytes([raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], 0, 0]);
        let mut expected = [0i64; D];
        let mut used = [[false; 64]; 4];
        for group in 0..4 {
            let i = (raw[6 + group] & 63) as usize;
            used[group][i] = true;
            expected[4 * i + group] = 1 - 2 * ((signs >> group) & 1) as i64;
        }
        let mut cursor = 10;
        let mut ordinal = 4;
        for group in 0..4 {
            for _ in 0..10 {
                loop {
                    let index = (raw[cursor] & 63) as usize;
                    cursor += 1;
                    if !used[group][index] {
                        used[group][index] = true;
                        expected[4 * index + group] = 1 - 2 * ((signs >> ordinal) & 1) as i64;
                        ordinal += 1;
                        break;
                    }
                }
            }
        }
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let bytes: Vec<_> = raw.into_iter().map(|x| c.byte(x)).collect();
        let output = sparse_x(&mut c, &bytes).unwrap();
        for i in 0..D {
            assert_eq!(output[i].value, expected[i]);
            let expected = c.constant_signed(expected[i], 1);
            c.builder
                .assert_equal(output[i].constrained.wire(), expected.constrained.wire());
        }
        let air = MachineAir::new(builder.finish(None).unwrap());
        air.trace(&[], &witness).unwrap();
        let mut changed = witness;
        changed[6] = Val::from_u8(63);
        assert!(air.trace(&[], &changed).is_err());
    }
}
