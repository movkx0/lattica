//! Read-only research artifact audit. No prover, wallet witnesses, or inner proofs
//! are loaded. The expected profile MUST come from an independent trusted source.
use lattica_prover_p3::block_v2::{
    codec, commitment,
    machine::{backend::RegisteredVerifier, programs},
    profile,
    recursive::{self, NodeProof, Registry},
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_symmetric::MerkleCap;
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io::Read, path::Path, time::Instant};

type Error = recursive::Error;

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("artifact type/size".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("artifact grew beyond limit".into());
    }
    Ok(bytes)
}

fn read<T: DeserializeOwned + Serialize>(path: &Path, magic: &[u8; 8]) -> Result<T, Error> {
    let bytes = read_bounded(path, profile::MAX_PROOF_BYTES)?;
    if !bytes.starts_with(magic) {
        return Err("artifact magic".into());
    }
    Ok(codec::decode(&bytes[8..])?)
}

fn registry(dir: &Path) -> Result<Registry, Error> {
    let height = read_bounded(&dir.join("height"), 4)?;
    let height = u32::from_le_bytes(height.as_slice().try_into()?) as usize;
    // Bound geometry before constructing any verifier state.
    if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
        return Err("artifact height".into());
    }
    let mut caps = core::array::from_fn(|_| Vec::new());
    let length = (1 << profile::CAP_HEIGHT) * 32;
    for (i, cap) in caps.iter_mut().enumerate() {
        let bytes = read_bounded(&dir.join(format!("key.{}", i + 1)), length)?;
        if bytes.len() != length {
            return Err("key size".into());
        }
        for digest in bytes.chunks_exact(32) {
            let mut fields = [Val::ZERO; 4];
            for (out, word) in fields.iter_mut().zip(digest.chunks_exact(8)) {
                let value = u64::from_le_bytes(word.try_into()?);
                if value >= commitment::MODULUS {
                    return Err("noncanonical key".into());
                }
                *out = Val::from_u64(value);
            }
            cap.push(fields);
        }
    }
    Ok(Registry { height, caps })
}

fn parse_profile(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected 64 hexadecimal profile characters".into());
    }
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

// These calls intentionally bypass Registry::verify's metadata comparison.
// They must fail at the native cryptographic verifier, not merely because the
// external expected statement differs from the artifact's public-value copy.
fn native_binding_checks(verifier: &RegisteredVerifier, node: &NodeProof) -> Result<usize, Error> {
    verifier.verify(&node.proof, &node.public)?;
    for slot in 0..programs::PUBLIC_VALUES {
        let mut wrong = node.public;
        wrong[slot] += Val::ONE;
        if verifier.verify(&node.proof, &wrong).is_ok() {
            return Err(format!("native verifier accepted changed public slot {slot}").into());
        }
    }
    let bytes = postcard::to_allocvec(node)?;
    const MUTATIONS: usize = 14;
    for mutation in 0..MUTATIONS {
        let mut wrong: NodeProof = codec::decode(&bytes)?;
        let p = &mut wrong.proof;
        let opened = &mut p.opened_values.instances[0];
        match mutation {
            0 => opened.base_opened_values.trace_local[0] += profile::Challenge::ONE,
            1 => {
                opened
                    .base_opened_values
                    .preprocessed_local
                    .as_mut()
                    .unwrap()[0] += profile::Challenge::ONE
            }
            2 => opened.base_opened_values.quotient_chunks[0][0] += profile::Challenge::ONE,
            3 => opened.permutation_local[0] += profile::Challenge::ONE,
            4 => opened.permutation_next[0] += profile::Challenge::ONE,
            5 => opened.base_opened_values.random.as_mut().unwrap()[0] += profile::Challenge::ONE,
            6 => p.opening_proof.0[0][0][0][0] += profile::Challenge::ONE,
            7 => p.opening_proof.1.final_poly[0] += profile::Challenge::ONE,
            8 => {
                p.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values[0] +=
                    profile::Challenge::ONE
            }
            9 => p.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE,
            10 => {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .1[0][0] += Val::ONE
            }
            11 => p.lookup_terminals[0].as_mut().unwrap().0 += profile::Challenge::ONE,
            12 => p.degree_bits[0] += 1,
            13 => {
                let mut roots = p.commitments.main.roots().to_vec();
                roots[0][0] += Val::ONE;
                p.commitments.main = MerkleCap::new(roots);
            }
            _ => unreachable!(),
        }
        if verifier.verify(p, &node.public).is_ok() {
            return Err(format!("native verifier accepted proof mutation {mutation}").into());
        }
    }
    Ok(programs::PUBLIC_VALUES + MUTATIONS)
}

fn require_no_inners(dir: &Path) -> Result<(), Error> {
    let names = (0..4)
        .flat_map(|i| [format!("wallet.{i}"), format!("node.0.{i}")])
        .chain((0..2).map(|i| format!("node.1.{i}")));
    for name in names {
        match fs::symlink_metadata(dir.join(&name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(format!("inner artifact still present: {name}").into()),
        }
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), Error> {
    let root = match args.first().map(String::as_str) {
        Some("root") if args.len() == 3 => true,
        Some("node") if args.len() == 4 => false,
        _ => return Err("usage: block-v2-artifact-audit root DIR PINNED_PROFILE | node DIR PINNED_PROFILE NODE_FILENAME".into()),
    };
    let dir = Path::new(&args[1]);
    let pinned = parse_profile(&args[2])?;
    let name = if root { "node.2.0" } else { &args[3] };
    if Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err("node filename must be a single local component".into());
    }
    if root {
        require_no_inners(dir)?;
    }
    let registry = registry(dir)?;
    let bytes = read_bounded(&dir.join(name), profile::MAX_PROOF_BYTES)?;
    let node = codec::decode_node(&bytes)?;
    let expected = if root {
        let expected: [Val; programs::PUBLIC_VALUES] = read(&dir.join("expected"), b"LBV2ST01")?;
        if expected[programs::MODE] != Val::from_u64(programs::MERGE)
            || expected[programs::LEVEL] != Val::from_u64(2)
            || expected[programs::COUNT] != Val::from_u64(4)
        {
            return Err("not the two-level/four-wallet expected statement".into());
        }
        expected
    } else {
        node.public
    };
    registry.verify(pinned, &node, &expected)?;
    use p3_field::PrimeField64;
    let mode = node.public[programs::MODE].as_canonical_u64();
    let verifier = registry.verifier(pinned, mode)?;
    let native_rejections = native_binding_checks(&verifier, &node)?;

    // Verify native key binding as well as the independent registry pin policy.
    let mut changed_key = registry.clone();
    changed_key.caps[(mode - 1) as usize][0][0] += Val::ONE;
    let wrong_verifier = changed_key.verifier(changed_key.id()?, mode)?;
    if wrong_verifier.verify(&node.proof, &node.public).is_ok() {
        return Err("native verifier accepted substituted preprocessing cap".into());
    }
    for key in 0..3 {
        let mut changed = registry.clone();
        changed.caps[key][0][0] += Val::ONE;
        if changed.verify(pinned, &node, &expected).is_ok() {
            return Err("accepted substituted registry key".into());
        }
    }
    let mut wrong_pin = pinned;
    wrong_pin[0] ^= 1;
    if registry.verify(wrong_pin, &node, &expected).is_ok() {
        return Err("accepted wrong profile pin".into());
    }
    println!("artifact_audit=PASS kind={} proof_bytes={} native_mutation_rejections={} registry_policy_rejections=4 inner_proofs_loaded=0 full_tree_security=UNREVIEWED production_ready=false",
        if root { "two-level-root" } else { "node-only" }, bytes.len(), native_rejections + 1);
    Ok(())
}

fn main() {
    let start = Instant::now();
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("artifact_audit=FAIL {error}");
        std::process::exit(1);
    }
    println!("audit_elapsed_ms={}", start.elapsed().as_millis());
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::{
        backend::RegisteredProgram, MachineAir, ProgramBuilder,
    };

    #[test]
    fn profile_parser_is_strict_and_never_slices_unicode() {
        assert_eq!(parse_profile(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        for value in [
            "é".repeat(32),
            "z0".repeat(32),
            "0".repeat(63),
            "0".repeat(65),
        ] {
            assert!(parse_profile(&value).is_err());
        }
    }

    #[test]
    fn real_small_execution_proof_exercises_every_native_mutation() {
        let mut b = ProgramBuilder::new(programs::PUBLIC_VALUES).unwrap();
        for i in 0..programs::PUBLIC_VALUES {
            let public = b.public(i).unwrap();
            let value = b.input();
            b.assert_equal(public, value);
        }
        let registered =
            RegisteredProgram::new(MachineAir::new(b.finish(Some(32)).unwrap())).unwrap();
        let public = core::array::from_fn(|i| Val::from_usize(i + 1));
        let proof = registered.prove(&public, &public).unwrap();
        let verifier = registered.verifier();
        drop(registered);
        let node = NodeProof { public, proof };
        assert_eq!(native_binding_checks(&verifier, &node).unwrap(), 37);
    }
}
