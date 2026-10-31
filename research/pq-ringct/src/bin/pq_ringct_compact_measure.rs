//! CPU-only public-artifact measurements; no recursive proof generation.
use lattica_pq_ringct_research::{
    compact::{
        self,
        ledger::{AccountBytes, LedgerSnapshot, ACCOUNT_BYTES, RING_ACCOUNTS},
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
        return Err("usage: pq-ringct-compact-measure NEW_OUTPUT_DIRECTORY".into());
    }
    if !native::available() {
        return Err("native reference backend unavailable".into());
    }
    let directory = Path::new(&args[1]);
    fs::create_dir(directory)?; // Never replace an earlier measurement directory.
    let mut cases = Vec::new();
    for ordinal in 0..3u8 {
        let context = [51 + ordinal; 32];
        let fixture = native::generate_fixture_with_setup_seed(
            context,
            [61 + ordinal; 32],
            u64::from(ordinal) * 4,
            FixtureAmounts {
                input: [1000 + u64::from(ordinal), 2000],
                output: [1500, 1500 + u64::from(ordinal)],
            },
        )?;
        let generation_ns = fixture.generation_ns;
        let original = NativePacket {
            context,
            statement: fixture.statement,
            proof: fixture.proof,
        };
        accepted(&context, &original)?;
        let native_packet = original.encode()?;
        let proof = compact::encode_proof(&original.proof)?;
        let full = compact::encode_packet(&original)?;
        let accounts: Vec<AccountBytes> = original.statement
            [32..32 + RING_ACCOUNTS * ACCOUNT_BYTES]
            .chunks_exact(ACCOUNT_BYTES)
            .map(|a| a.try_into().unwrap())
            .collect();
        let domain = [71; 32];
        let store = LedgerSnapshot::new(domain, original.statement[..32].try_into()?, accounts)?;
        let checkpoint = store.checkpoint();
        let indices = std::array::from_fn(|i| i as u64);
        let referenced =
            compact::encode_referenced_packet(&original, &checkpoint, &indices, &store)?;
        let decoded_full = compact::decode_packet(&full, &context)?;
        let decoded_refs =
            compact::decode_referenced_packet(&referenced, &context, &checkpoint, &store)?;
        if decoded_full != original
            || decoded_refs != original
            || compact::decode_proof(&proof)? != original.proof
        {
            return Err("lossless round trip changed native bytes".into());
        }
        accepted(&context, &decoded_full)?;
        accepted(&context, &decoded_refs)?;
        let mut changed = full.clone();
        changed[80 + compact::STATEMENT_BYTES + 11_200] ^= 1;
        rejected(&context, &compact::decode_packet(&changed, &context)?)?;
        let mut changed = referenced.clone();
        changed[144..152].copy_from_slice(&1u64.to_le_bytes());
        rejected(
            &context,
            &compact::decode_referenced_packet(&changed, &context, &checkpoint, &store)?,
        )?;
        let mut duplicate_serial = original.clone();
        let end = duplicate_serial.statement.len();
        let first = duplicate_serial.statement[end - 64..end - 32].to_vec();
        duplicate_serial.statement[end - 32..].copy_from_slice(&first);
        let duplicate_serial = compact::encode_packet(&duplicate_serial)?;
        rejected(
            &context,
            &compact::decode_packet(&duplicate_serial, &context)?,
        )?;
        let measured = json!({
            "proof_encode":timings(|| compact::encode_proof(&original.proof))?,
            "proof_decode":timings(|| compact::decode_proof(&proof))?,
            "standalone_encode":timings(|| compact::encode_packet(&original))?,
            "standalone_decode":timings(|| compact::decode_packet(&full, &context))?,
            "referenced_encode":timings(|| compact::encode_referenced_packet(&original, &checkpoint, &indices, &store))?,
            "referenced_decode":timings(|| compact::decode_referenced_packet(&referenced, &context, &checkpoint, &store))?,
        });
        let artifacts = json!({
            "native":save(directory,&format!("case-{ordinal}-native.bin"),&native_packet)?,
            "proof":save(directory,&format!("case-{ordinal}-proof.bin"),&proof)?,
            "standalone":save(directory,&format!("case-{ordinal}-standalone.bin"),&full)?,
            "referenced":save(directory,&format!("case-{ordinal}-referenced.bin"),&referenced)?,
        });
        cases.push(json!({
            "ordinal":ordinal,"context_hex":hex(&context),"ledger_domain_hex":hex(&domain),
            "setup_seed_hex":hex(&checkpoint.setup_seed()),"ledger_root_hex":hex(&checkpoint.tree_root()),
            "ledger_checkpoint_hex":hex(&checkpoint.id()),"ledger_account_count":checkpoint.account_count(),
            "native_generation_ns":generation_ns,"artifacts":artifacts,"codec_timings":measured,
            "exact_native_round_trips":true,"c_reference_verified":true,"rust_verified":true,
            "proof_mutation_rejected":true,"reference_mutation_rejected":true,"duplicate_serial_rejected":true,
        }));
    }
    let report = json!({
        "schema":"ringct-compact-encoding-measurement-v1","artifact_digest":"sha3-256",
        "gpu_used":false,"profile":"MatRiCT+ n10, two inputs, two outputs, unchanged native parameters",
        "sizes_bytes":{"native_proof":native_packet::PROOF_BYTES,"compact_proof":compact::PROOF_BYTES,
            "native_packet":native_packet::PACKET_BYTES,"standalone_compact_packet":compact::PACKET_BYTES,
            "referenced_compact_packet":compact::REFERENCED_PACKET_BYTES},
        "reference_scope":"Account data and Merkle paths are already locally available; their initial synchronization is excluded from packet size and codec timings.",
        "timing_scope":"CPU codec calls including allocation and membership checks; excludes native proof generation, cryptographic verification, ledger construction, and disk output.",
        "production_acceptance_changed":false,"recursive_workflow_speedup_measured":false,"cases":cases,
    });
    fs::write(
        directory.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
