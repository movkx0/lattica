//! CPU public-statement export for the grouped-eight research experiment.
//! Verifies eight public wallet proofs and exports their 26 canonical public
//! fields. Never reads aggregate proofs, keys, profile.hex or an expected root.
//! It does not approve a registry or validate host-chain state.

use lattica_prover_p3::{
    block_v2::{
        codec, commitment, profile,
        recursive::{self, WalletProof},
    },
    joinsplit_air as js,
};
use p3_field::PrimeField64;
use std::{collections::BTreeSet, fs, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

type Error = recursive::Error;
const COUNT: usize = 8;
const FIELDS: usize = 26;
const MAGIC: &[u8; 8] = b"LBV2WL02";
const _: () = assert!(js::N_PUBLIC == FIELDS && js::N_IN == 2 && js::M_OUT == 2);
const _: () = assert!(js::PI_NF == 4 && js::PI_OUTCM == 12 && js::PI_MINT == 21);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn chain_hex(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("chain must be exactly 64 ASCII hexadecimal characters".into());
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)?;
    }
    Ok(out)
}

fn public_bytes(fields: &[u64]) -> Result<[u8; FIELDS * 8], Error> {
    if fields.len() != FIELDS || fields.iter().any(|&v| v >= commitment::MODULUS) {
        return Err("public fields must be exactly 26 canonical Goldilocks values".into());
    }
    let mut out = [0; FIELDS * 8];
    for (word, field) in out.chunks_exact_mut(8).zip(fields) {
        word.copy_from_slice(&field.to_le_bytes());
    }
    Ok(out)
}

fn wallet(path: &Path) -> Result<WalletProof, Error> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.len() > profile::MAX_PROOF_BYTES as u64 {
        return Err("wallet artifact type/size".into());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("opened wallet artifact is not regular".into());
    }
    let mut bytes = Vec::new();
    file.take(profile::MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > profile::MAX_PROOF_BYTES || !bytes.starts_with(MAGIC) {
        return Err("wallet envelope/size".into());
    }
    Ok(codec::decode(&bytes[MAGIC.len()..])?)
}

// Fixed research-fixture checks, NOT consensus or proof verification.
fn fixture_shape(public: &[[u64; FIELDS]; COUNT]) -> Result<(), Error> {
    let mut nullifiers = BTreeSet::new();
    for values in public {
        public_bytes(values)?;
        if values[js::PI_MINT] != 0 || values[..4] != public[0][..4] {
            return Err("export requires the shared-anchor, zero-mint eight-wallet fixture".into());
        }
        for nullifier in values[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
            let key: [u64; 4] = nullifier.try_into()?;
            if !nullifiers.insert(key) {
                return Err("duplicate nullifier in eight-wallet fixture".into());
            }
        }
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), Error> {
    if args.len() != 3 || args[0] != "dump-eight" {
        return Err(
            "usage: block-v2-grouped-publics dump-eight PRIVATE_JOB EXTERNAL_CHAIN_HEX".into(),
        );
    }
    let dir = Path::new(&args[1]);
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err("public fixture must be a nonsymlink directory".into());
    }
    let expected_chain = chain_hex(&args[2])?;
    let mut values = [[0; FIELDS]; COUNT];
    for (index, row) in values.iter_mut().enumerate() {
        let proof = wallet(&dir.join(format!("wallet.{index}")))?;
        if proof.chain != expected_chain {
            return Err("wallet chain differs from external chain".into());
        }
        recursive::verify_wallet(&proof)?;
        for (out, field) in row.iter_mut().zip(&proof.public) {
            *out = field.as_canonical_u64();
        }
    }
    fixture_shape(&values)?;
    // No successful export marker or row is emitted until ALL proofs/checks pass.
    println!("grouped_public_export=VERIFIED_WALLET_STATEMENTS count=8 fields=26 kind=1 chain={} registry_approved=false aggregate_verified=false production_ready=false", hex(&expected_chain));
    for (index, row) in values.iter().enumerate() {
        println!(
            "wallet_public index={index} kind=1 fields_le={}",
            hex(&public_bytes(row)?)
        );
    }
    println!("grouped_public_export_complete=true");
    Ok(())
}

fn main() {
    if cfg!(feature = "gpu") {
        eprintln!("FAILED: grouped public export requires a CPU-only build");
        std::process::exit(1);
    }
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> [[u64; FIELDS]; COUNT] {
        let mut values = [[0; FIELDS]; COUNT];
        for (index, row) in values.iter_mut().enumerate() {
            row[..4].copy_from_slice(&[11, 12, 13, 14]);
            for (slot, word) in row[4..12].iter_mut().enumerate() {
                *word = (index * 8 + slot + 1) as u64;
            }
        }
        values
    }

    #[test]
    fn external_chain_parser_is_exact_ascii_hex() {
        assert_eq!(chain_hex(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        for bad in [
            "0".repeat(63),
            "0".repeat(65),
            "é".repeat(32),
            "z0".repeat(32),
        ] {
            assert!(chain_hex(&bad).is_err());
        }
    }

    #[test]
    fn fixed_public_codec_is_little_endian_and_canonical() {
        let values = core::array::from_fn::<_, FIELDS, _>(|i| i as u64 + 1);
        let bytes = public_bytes(&values).unwrap();
        assert_eq!(bytes.len(), 208);
        assert_eq!(&bytes[..8], &1u64.to_le_bytes());
        assert_eq!(&bytes[200..], &26u64.to_le_bytes());
        assert!(public_bytes(&values[..25]).is_err());
        let mut bad = values;
        bad[7] = commitment::MODULUS;
        assert!(public_bytes(&bad).is_err());
    }

    #[test]
    fn fixture_checks_are_not_silent_on_issuance_anchor_or_duplicate_nullifiers() {
        fixture_shape(&fixture()).unwrap();
        let mut bad = fixture();
        bad[7][js::PI_MINT] = 1;
        assert!(fixture_shape(&bad).is_err());
        bad = fixture();
        bad[1][0] += 1;
        assert!(fixture_shape(&bad).is_err());
        bad = fixture();
        bad[7][4..8].copy_from_slice(&fixture()[0][4..8]);
        assert!(fixture_shape(&bad).is_err());
    }

    #[test]
    fn argument_validation_does_not_accept_missing_chain_or_extra_profile() {
        for args in [
            vec![],
            vec!["dump-eight".into(), "job".into()],
            vec![
                "dump-eight".into(),
                "job".into(),
                "00".repeat(32),
                "unexpected".into(),
            ],
        ] {
            assert!(run(&args).is_err());
        }
    }
}
