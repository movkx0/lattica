//! CPU-only public-artifact measurements; no recursive proof generation.
use lattica_pq_ringct_research::{
    compact::{
        self,
        ledger::{AccountBytes, LedgerSnapshot, ACCOUNT_BYTES, RING_ACCOUNTS},
        v2,
    },
    native::{self, FixtureAmounts},
    native_packet::{self, NativePacket},
    rust_verify,
};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{error::Error, fs, path::Path, time::Instant};

const SAMPLES: usize = 11;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn save(directory: &Path, name: &str, bytes: &[u8]) -> Result<Value, Box<dyn Error>> {
    fs::write(directory.join(name), bytes)?;
    Ok(json!({"file":name,"bytes":bytes.len(),"sha3_256":sha3_256(bytes)}))
}

// SHA3 is used here for artifact integrity; the field name names that algorithm.
fn sha3_256(bytes: &[u8]) -> String {
    hex(&Sha3_256::digest(bytes))
}

fn timings<T>(
    mut operation: impl FnMut() -> Result<T, compact::Error>,
) -> Result<Value, Box<dyn Error>> {
    drop(operation()?); // Separate one untimed warm-up.
    let mut values = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let output = operation()?;
        let elapsed = start.elapsed().as_nanos() as u64;
        std::hint::black_box(&output);
        values.push(elapsed);
        drop(output);
    }
    values.sort_unstable();
    Ok(
        json!({"samples":SAMPLES,"median_ns":values[SAMPLES / 2],"min_ns":values[0],"max_ns":values[SAMPLES - 1]}),
    )
}

fn accepted(context: &[u8; 32], packet: &NativePacket) -> Result<(), Box<dyn Error>> {
    if !native::verify(context, &packet.statement, &packet.proof)?
        || !rust_verify::verify(context, &packet.statement, &packet.proof)?
    {
        return Err("a reconstructed proof failed independent verification".into());
    }
    Ok(())
}

fn rejected(context: &[u8; 32], packet: &NativePacket) -> Result<(), Box<dyn Error>> {
    if native::verify(context, &packet.statement, &packet.proof).unwrap_or(false)
        || rust_verify::verify(context, &packet.statement, &packet.proof).unwrap_or(false)
    {
        return Err("a mutated statement/proof was accepted".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: pq-ringct-compact-v2-measure NEW_OUTPUT_DIRECTORY".into());
    }
    if !native::available() {
        return Err("native reference backend unavailable".into());
    }
    let directory = Path::new(&args[1]);
    fs::create_dir(directory)?;
    let max = (1u64 << 52) - 1;
    let profiles = [
        ([0, 0], [0, 0]),
        ([1, 0], [0, 1]),
        ([1, 1], [1, 1]),
        ([max, 0], [0, max]),
        ([max, max], [max, max]),
        ([max, 1], [1, max]),
        ([max, max - 1], [max - 1, max]),
        ([1 << 51, 1 << 51], [max, 1]),
        ([1 << 32, 1 << 16], [(1 << 32) - 1, (1 << 16) + 1]),
        ([1234, 5678], [3456, 3456]),
        ([1 << 26, 1 << 26], [0, 1 << 27]),
        ([max - 2, 2], [max - 1, 1]),
        ([42, 58], [99, 1]),
        ([0, 1], [1, 0]),
        ([max - 1, 0], [(1 << 51) - 1, (1 << 51) - 1]),
        ([123456789, 987654321], [555555555, 555555555]),
    ];
    let mut cases = Vec::new();
    for (ordinal, (input, output)) in profiles.into_iter().enumerate() {
        let context = [91 + ordinal as u8; 32];
        let setup_seed = [111 + ordinal as u8; 32];
        let index = ordinal as u64 % 10;
        let fixture = native::generate_fixture_with_setup_seed(
            context,
            setup_seed,
            index,
            FixtureAmounts { input, output },
        )?;
        let generation_ns = fixture.generation_ns;
        let original = NativePacket {
            context,
            statement: fixture.statement,
            proof: fixture.proof,
        };
        let start = Instant::now();
        if !native::verify(&context, &original.statement, &original.proof)? {
            return Err("native verification failed".into());
        }
        let c_verify_ns = start.elapsed().as_nanos() as u64;
        let start = Instant::now();
        if !rust_verify::verify(&context, &original.statement, &original.proof)? {
            return Err("Rust verification failed".into());
        }
        let rust_verify_ns = start.elapsed().as_nanos() as u64;
        let native_packet = original.encode()?;
        let v1_proof = compact::encode_proof(&original.proof)?;
        let proof = v2::encode_proof(&original.proof)?;
        let full = v2::encode_packet(&original)?;
        let accounts: Vec<AccountBytes> = original.statement
            [32..32 + RING_ACCOUNTS * ACCOUNT_BYTES]
            .chunks_exact(ACCOUNT_BYTES)
            .map(|a| a.try_into().unwrap())
            .collect();
        let domain = [131; 32];
        let store = LedgerSnapshot::new(domain, setup_seed, accounts)?;
        let checkpoint = store.checkpoint();
        let indices = std::array::from_fn(|i| i as u64);
        let referenced = v2::encode_referenced_packet(&original, &checkpoint, &indices, &store)?;
        let decoded_full = v2::decode_packet(&full, &context)?;
        let decoded_refs =
            v2::decode_referenced_packet(&referenced, &context, &checkpoint, &store)?;
        if decoded_full != original
            || decoded_refs != original
            || v2::decode_proof(&proof)? != original.proof
            || compact::decode_proof(&v1_proof)? != original.proof
        {
            return Err("lossless round trip changed native bytes".into());
        }
        accepted(&context, &decoded_full)?;
        accepted(&context, &decoded_refs)?;
        // Change raw alpha, leaving the transport canonical and parseable.
        let mut changed = original.clone();
        changed.proof[11_392] ^= 1;
        rejected(
            &context,
            &v2::decode_packet(&v2::encode_packet(&changed)?, &context)?,
        )?;
        let mut changed = referenced.clone();
        changed[144..152].copy_from_slice(&1u64.to_le_bytes());
        rejected(
            &context,
            &v2::decode_referenced_packet(&changed, &context, &checkpoint, &store)?,
        )?;
        let mut duplicate = original.clone();
        let end = duplicate.statement.len();
        let first = duplicate.statement[end - 64..end - 32].to_vec();
        duplicate.statement[end - 32..].copy_from_slice(&first);
        rejected(
            &context,
            &v2::decode_packet(&v2::encode_packet(&duplicate)?, &context)?,
        )?;
        let measured = json!({
            "v1_proof_encode":timings(|| compact::encode_proof(&original.proof))?,
            "v1_proof_decode":timings(|| compact::decode_proof(&v1_proof))?,
            "proof_encode":timings(|| v2::encode_proof(&original.proof))?,
            "proof_decode":timings(|| v2::decode_proof(&proof))?,
            "standalone_encode":timings(|| v2::encode_packet(&original))?,
            "standalone_decode":timings(|| v2::decode_packet(&full, &context))?,
            "referenced_encode":timings(|| v2::encode_referenced_packet(&original, &checkpoint, &indices, &store))?,
            "referenced_decode":timings(|| v2::decode_referenced_packet(&referenced, &context, &checkpoint, &store))?,
        });
        let artifacts = json!({
            "native":save(directory,&format!("case-{ordinal}-native.bin"),&native_packet)?,
            "v1_proof":save(directory,&format!("case-{ordinal}-v1_proof.bin"),&v1_proof)?,
            "proof":save(directory,&format!("case-{ordinal}-proof.bin"),&proof)?,
            "standalone":save(directory,&format!("case-{ordinal}-standalone.bin"),&full)?,
            "referenced":save(directory,&format!("case-{ordinal}-referenced.bin"),&referenced)?,
        });
        cases.push(json!({
            "ordinal":ordinal,"ring_index":index,"input_amounts":input,"output_amounts":output,
            "context_hex":hex(&context),"setup_seed_hex":hex(&setup_seed),
            "ledger_domain_hex":hex(&domain),"ledger_root_hex":hex(&checkpoint.tree_root()),
            "ledger_checkpoint_hex":hex(&checkpoint.id()),"ledger_account_count":checkpoint.account_count(),
            "proof_mode":proof[0],"rice_parameters":if proof[0] == 1 { Some(&proof[1..6]) } else { None },
            "native_generation_ns":generation_ns,"c_verify_ns":c_verify_ns,"rust_verify_ns":rust_verify_ns,
            "c_reference_verified":true,"rust_verified":true,"exact_native_round_trips":true,
            "proof_mutation_rejected":true,"reference_mutation_rejected":true,"duplicate_serial_rejected":true,
            "codec_timings":measured,"artifacts":artifacts,
        }));
        println!("case {ordinal}: proof={} bytes, referenced={} bytes; exact reconstruction and both verifiers passed", proof.len(), referenced.len());
    }
    let report = json!({
        "schema":"ringct-compact-encoding-measurement-v2","artifact_digest":"sha3-256",
        "gpu_used":false,"profile":"MatRiCT+ n10, two inputs, two outputs, unchanged native parameters",
        "fixed_sizes_bytes":{"native_proof":native_packet::PROOF_BYTES,"v1_proof":compact::PROOF_BYTES,"native_packet":native_packet::PACKET_BYTES,"v1_standalone":compact::PACKET_BYTES,"v1_referenced":compact::REFERENCED_PACKET_BYTES},
        "proof_parser_bounds":{"min":v2::MIN_PROOF_BYTES,"max":v2::MAX_PROOF_BYTES},
        "reference_scope":"Account data and Merkle paths already locally available; initial synchronization excluded from packet size and codec timings.",
        "timing_scope":"Release CPU codec calls with one warmup and 11 timed samples, including allocation and membership checks; excludes proof generation, cryptographic verification, ledger construction, and disk output. Verification fields are single samples.",
        "production_acceptance_changed":false,"recursive_workflow_speedup_measured":false,"cases":cases,
    });
    fs::write(
        directory.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
