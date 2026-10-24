use super::*;
use crate::block_v2::machine::program::{ExecutionError, Program};

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn fields(bytes: &[u8]) -> Vec<Val> {
    bytes.iter().map(|&v| Val::from_u8(v)).collect()
}

fn bind_public(b: &mut Builder<'_>, bytes: &[Byte]) {
    for (i, byte) in bytes.iter().enumerate() {
        let encoded = byte.to_wire(b);
        let public = b.public(i).unwrap();
        b.assert_equal(encoded, public);
    }
}

fn assert_valid_and_reject_mutations(program: &Program, expected: &[u8], witness: &[u8]) {
    let public = fields(expected);
    let witness = fields(witness);
    program.evaluate(&public, &witness).unwrap();
    let mut wrong_public = public.clone();
    wrong_public[0] += Val::ONE;
    assert_eq!(
        program.evaluate(&wrong_public, &witness),
        Err(ExecutionError::Unsatisfied)
    );
    if !witness.is_empty() {
        let mut wrong_witness = witness.clone();
        wrong_witness[0] += Val::ONE;
        assert_eq!(
            program.evaluate(&public, &wrong_witness),
            Err(ExecutionError::Unsatisfied)
        );
        wrong_witness[0] = Val::from_u64(256);
        assert_eq!(
            program.evaluate(&public, &wrong_witness),
            Err(ExecutionError::Unsatisfied)
        );
    }
}

#[test]
fn aes_sbox_all_inputs_and_byte_range_are_constrained() {
    let expected = bytes(concat!(
        "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0",
        "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275",
        "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf",
        "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2",
        "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb",
        "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08",
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e",
        "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
    ));
    let mut b = Builder::new(1).unwrap();
    let input = Byte::input(&mut b);
    let output = aes_sbox(&mut b, input);
    bind_public(&mut b, &[output]);
    let program = b.finish(None).unwrap();
    for (input, expected) in expected.into_iter().enumerate() {
        program
            .evaluate(&[Val::from_u8(expected)], &[Val::from_usize(input)])
            .unwrap();
    }
    assert_eq!(
        program.evaluate(&[Val::from_u8(0x63)], &[Val::from_u64(256)]),
        Err(ExecutionError::Unsatisfied)
    );
}

#[test]
fn aes256_known_answers_and_wrong_inputs() {
    let mut b = Builder::new(16).unwrap();
    let key = core::array::from_fn(|_| Byte::input(&mut b));
    let plaintext = core::array::from_fn(|_| Byte::input(&mut b));
    let schedule = Aes256Key::expand(&mut b, &key);
    let ciphertext = schedule.encrypt(&mut b, &plaintext);
    bind_public(&mut b, &ciphertext);
    let program = b.finish(None).unwrap();
    eprintln!(
        "pq_bytes AES256 wires={} active_rows={} height={}",
        program.wire_count(),
        program.active_rows(),
        program.height()
    );
    for (key, plaintext, expected) in [
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "dc95c078a2408989ad48a21492842087",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
        ),
    ] {
        let witness = [bytes(key), bytes(plaintext)].concat();
        assert_valid_and_reject_mutations(&program, &bytes(expected), &witness);
    }
}

#[test]
fn aes_ctr_domain_endianness_tail_discard_and_counter_wrap() {
    // Public known-answer values from AES-256-ECB on the encoded author IV.
    // Constant inputs keep this encoding-specific test small; the AES tests
    // above separately exercise the same circuit with variable witnesses.
    let mut b = Builder::new(0).unwrap();
    let key = core::array::from_fn(|i| Byte::constant(&mut b, i as u8));
    let schedule = Aes256Key::expand(&mut b, &key);
    let first = schedule.ctr(&mut b, 0x4368, 160, 9);
    let second = schedule.ctr(&mut b, 0x4368, 161, 17);
    let wrapped = schedule.ctr(&mut b, 0x4368, u32::MAX, 32);
    for (actual, expected) in [
        (first, "c71cc8fbfb5b4a3395"),
        (second, "59e8c10615cdb5a8e74f881b868dd3f14a"),
        (
            wrapped,
            "d145eb84f8dae428d7ae381ebeb10882ad584d6dce45483758818e71a71d5f3a",
        ),
    ] {
        for (byte, expected) in actual.into_iter().zip(bytes(expected)) {
            let actual = byte.to_wire(&mut b);
            let expected = b.constant(Val::from_u8(expected));
            b.assert_equal(actual, expected);
        }
    }
    b.finish(None).unwrap().evaluate(&[], &[]).unwrap();
}

#[test]
fn byte_constructor_rejects_nonboolean_bits() {
    let mut b = Builder::new(1).unwrap();
    let bits = core::array::from_fn(|_| b.input());
    let byte = Byte::from_bits(&mut b, bits);
    bind_public(&mut b, &[byte]);
    let program = b.finish(None).unwrap();
    program
        .evaluate(
            &[Val::ONE],
            &[
                Val::ONE,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
            ],
        )
        .unwrap();
    // Reconstruction alone would accept low bit2 as byte2. Booleanity must
    // reject it even when the public reconstructed value agrees.
    assert_eq!(
        program.evaluate(
            &[Val::from_u8(2)],
            &[
                Val::from_u8(2),
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO,
                Val::ZERO
            ]
        ),
        Err(ExecutionError::Unsatisfied)
    );
}

#[test]
fn shake256_abc_and_multiple_squeeze_blocks() {
    let mut b = Builder::new(64).unwrap();
    let input: Vec<_> = (0..3).map(|_| Byte::input(&mut b)).collect();
    let output = shake256(&mut b, &input, 137);
    // Bind output across both squeeze blocks while respecting the machine's
    // 64-public limit: first32 and bytes105..137.
    let selected = [output[..32].to_vec(), output[105..137].to_vec()].concat();
    bind_public(&mut b, &selected);
    let program = b.finish(None).unwrap();
    eprintln!(
        "pq_bytes SHAKE256 2permutations wires={} active_rows={} height={}",
        program.wire_count(),
        program.active_rows(),
        program.height()
    );
    let expected = bytes("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf");
    assert_valid_and_reject_mutations(&program, &expected, b"abc");
}

#[test]
fn shake256_padding_at_rate_boundaries() {
    for (length, expected) in [
        (
            0,
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        ),
        (
            135,
            "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade0",
        ),
        (
            136,
            "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a",
        ),
        (
            137,
            "01d90952c642a5eb2a8fc9d713f843a45d7ac05132dddcb2efc9bebc27e37bcb",
        ),
    ] {
        let mut b = Builder::new(32).unwrap();
        let input: Vec<_> = (0..length).map(|_| Byte::input(&mut b)).collect();
        let output = shake256(&mut b, &input, 32);
        bind_public(&mut b, &output);
        let program = b.finish(None).unwrap();
        let witness: Vec<_> = (0..length).map(|i| i as u8).collect();
        assert_valid_and_reject_mutations(&program, &bytes(expected), &witness);
    }
}

fn combined_aes_shake_program() -> (Program, Vec<Val>, Vec<Val>) {
    let mut b = Builder::new(48).unwrap();
    let key = core::array::from_fn(|_| Byte::input(&mut b));
    let plaintext = core::array::from_fn(|_| Byte::input(&mut b));
    let schedule = Aes256Key::expand(&mut b, &key);
    let ciphertext = schedule.encrypt(&mut b, &plaintext);
    let digest = shake256(&mut b, &ciphertext, 32);
    let output = [ciphertext.to_vec(), digest].concat();
    bind_public(&mut b, &output);
    let public = fields(&bytes(concat!(
        "8ea2b7ca516745bfeafc49904b496089",
        "b3057a9499b22b0cfde950406e9869f7c90a8fae523750ecfa86a309c8b3a102"
    )));
    let witness = fields(&bytes(concat!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff"
    )));
    (b.finish(None).unwrap(), public, witness)
}

#[test]
fn combined_aes_shake_geometry_and_constraints() {
    let (program, public, witness) = combined_aes_shake_program();
    program.evaluate(&public, &witness).unwrap();
    let wires = program.wire_count();
    let active_rows = program.active_rows();
    let height = program.height();
    let air = crate::block_v2::machine::MachineAir::new(program);
    let analysis = crate::block_v2::machine::analysis::analyze(&air).unwrap();
    eprintln!("pq_bytes AES256+SHAKE256 wires={wires} active_rows={active_rows} height={height} retained_lde_bytes={}", analysis.retained_lde_bytes);
}

/// Explicit integration proof: expensive CPU preprocessing and 16x LDE.
/// Run with `--ignored --test-threads=1` after checking geometry/admission.
#[test]
#[ignore = "CPU integration proof for complete AES256 and SHAKE256 circuits"]
fn combined_aes_shake_real_stark_proof_rejects_mutations() {
    use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
    use crate::block_v2::profile::Challenge;
    use crate::proving::Request;
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap()
        .install(|| {
            let (program, public, witness) = combined_aes_shake_program();
            let registered = RegisteredProgram::new_with_request(
                MachineAir::new(program),
                16_u64 << 30,
                Request::compatible(),
            )
            .unwrap();
            let mut proof = registered
                .prove_with_request(&public, &witness, Request::compatible())
                .unwrap();
            let verifier = registered.verifier();
            verifier.verify(&proof, &public).unwrap();
            let mut wrong_public = public.clone();
            wrong_public[47] += Val::ONE;
            assert!(verifier.verify(&proof, &wrong_public).is_err());
            proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] += Challenge::ONE;
            assert!(verifier.verify(&proof, &public).is_err());
        });
}
