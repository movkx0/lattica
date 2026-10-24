use super::*;
use crate::rust_verify::{constraints_crypto::CryptoObligations, D};
use lattica_prover_p3::block_v2::machine::{MachineAir, ProgramBuilder};

fn packed(values: &[u64], width: usize) -> Vec<u8> {
    let mut bytes = vec![0; (values.len() * width).div_ceil(8)];
    for (index, &value) in values.iter().enumerate() {
        for bit in 0..width {
            bytes[(index * width + bit) / 8] |=
                (((value >> bit) & 1) as u8) << ((index * width + bit) % 8);
        }
    }
    bytes
}

#[test]
fn packed_coefficients_are_bound_to_the_canonical_byte_encoding() {
    for (width, q) in [(28, Q), (32, QHAT)] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut values = [0; D];
        values[0] = q - 1;
        values[1] = 1;
        let bytes = packed(&values, width);
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let bytes: Vec<_> = bytes.iter().map(|&b| c.byte(b)).collect();
            let mut bits = Bits {
                bytes: &bytes,
                position: 0,
            };
            let poly = bits.polys(&mut c, 1, width, q)[0];
            assert_eq!(poly.map(|x| x.value), values);
        }
        let air = MachineAir::new(builder.finish(None).unwrap());
        air.trace(&[], &witness).unwrap();
        values[0] = q; // fits packed width but is a noncanonical residue
        let forged: Vec<_> = packed(&values, width)
            .into_iter()
            .map(Val::from_u8)
            .collect();
        assert!(air.trace(&[], &forged).is_err());
        witness[0] += Val::from_u64(256); // same low bits cannot encode >255
        assert!(air.trace(&[], &witness).is_err());
    }
}

#[test]
fn signed_offset_boundaries_and_padding_bits_are_constrained() {
    for (width, bound) in [(2, 1), (11, 565), (17, 38346), (24, 6212586)] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut values = [u64::from(bound); D];
        values[0] = 0;
        values[1] = 2 * u64::from(bound);
        {
            let mut c = ConstraintContext {
                builder: &mut builder,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let bytes: Vec<_> = packed(&values, width)
                .into_iter()
                .map(|b| c.byte(b))
                .collect();
            let mut bits = Bits {
                bytes: &bytes,
                position: 0,
            };
            let result = bits.signed(&mut c, 1, width, bound)[0];
            assert_eq!(result[0].value, -i64::from(bound));
            assert_eq!(result[1].value, i64::from(bound));
            assert_eq!(result[2].value, 0);
        }
        let air = MachineAir::new(builder.finish(None).unwrap());
        air.trace(&[], &witness).unwrap();
        values[0] = 2 * u64::from(bound) + 1;
        let forged: Vec<_> = packed(&values, width)
            .into_iter()
            .map(Val::from_u8)
            .collect();
        assert!(air.trace(&[], &forged).is_err());
    }
}

#[test]
fn context_setup_and_serial_checks_survive_witness_tampering() {
    let mut builder = ProgramBuilder::new(8).unwrap();
    let public = core::array::from_fn(|i| builder.public(i).unwrap());
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([7; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        bind_context(&mut c, [5; 32], public);
        let seed = [7; 32].map(|b| c.byte(b));
        bind_setup(&mut c, &seed);
        let first = [11; 32].map(|b| c.byte(b));
        let mut serial = [11; 32];
        serial[31] = 12;
        let second = serial.map(|b| c.byte(b));
        bind_serial_inequality(&mut c, &[first, second]);
    }
    let public = [Val::from_u32(u32::from_le_bytes([5; 4])); 8];
    let air = MachineAir::new(builder.finish(None).unwrap());
    air.trace(&public, &witness).unwrap();
    let mut wrong_public = public;
    wrong_public[0] += Val::ONE;
    assert!(air.trace(&wrong_public, &witness).is_err());
    for index in [0, 31, 32, 63] {
        let mut forged = witness.clone();
        forged[index] += Val::ONE;
        assert!(air.trace(&public, &forged).is_err());
    }
    let mut equal_serials = witness.clone();
    equal_serials[127] = Val::from_u8(11);
    assert!(air.trace(&public, &equal_serials).is_err());
}
