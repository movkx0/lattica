//! Native research measurements only; no recursive or on-chain performance claim.

#[cfg(not(feature = "native-matrict"))]
fn main() -> std::process::ExitCode {
    eprintln!("This research binary requires an explicit --features native-matrict build.");
    std::process::ExitCode::FAILURE
}

#[cfg(feature = "native-matrict")]
fn main() -> std::process::ExitCode {
    match enabled::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("matrict-bench: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "native-matrict")]
mod enabled {
    use lattica_pq_ringct_research::native::{self, FixtureAmounts, NativeFixture};
    use lattica_pq_ringct_research::native_packet::{
        NativePacket, PROFILE_DESCRIPTION, PROFILE_PARAMETERS,
    };
    use serde_json::{json, Value};
    use sha3::{Digest, Sha3_256};
    use std::{
        error::Error,
        fs::{File, OpenOptions},
        io::{Read, Write},
        path::{Path, PathBuf},
        time::Instant,
    };

    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    const PROFILE: &str = "upstream-matrict-plus-n10-research";
    const MAX_PACKET_BYTES: u64 = 64 * 1024 * 1024;
    const MEASURED_SAMPLES: usize = 3;

    pub fn run() -> Result<()> {
        let mut arguments = std::env::args().skip(1);
        let command = arguments.next().unwrap_or_else(|| "benchmark".into());
        if matches!(command.as_str(), "--help" | "-h" | "help") {
            println!("matrict-bench benchmark [--report FILE] [--packet FILE]\nmatrict-bench verify --packet FILE --context HEX32\n\nExplicit native-matrict feature required. CPU-only native research; no recursive or on-chain claim.");
            return Ok(());
        }
        if command != "benchmark" && command != "verify" {
            return Err(format!("unknown command {command}").into());
        }
        let mut report_path = None;
        let mut packet_path = None;
        let mut trusted_context = None;
        while let Some(flag) = arguments.next() {
            if flag == "--context" && command == "verify" {
                if trusted_context.is_some() {
                    return Err("duplicate option --context".into());
                }
                let encoded = arguments.next().ok_or("missing --context value")?;
                trusted_context = Some(
                    unhex(&encoded)?
                        .try_into()
                        .map_err(|_| "trusted context must contain 32 bytes")?,
                );
                continue;
            }
            let destination = match flag.as_str() {
                "--report" if command == "benchmark" => &mut report_path,
                "--packet" => &mut packet_path,
                _ => return Err(format!("unknown option {flag}").into()),
            };
            if destination.is_some() {
                return Err(format!("duplicate option {flag}").into());
            }
            *destination = Some(PathBuf::from(
                arguments.next().ok_or("missing option path")?,
            ));
        }
        if !native::available() {
            return Err("native MatRiCT+ is unavailable on this build/CPU".into());
        }
        if command == "verify" {
            if let Some(path) = packet_path {
                return verify_packet(
                    &path,
                    trusted_context
                        .as_ref()
                        .ok_or("verify requires --context HEX32 from a trusted source")?,
                );
            }
            return Err("verify requires --packet FILE".into());
        }
        if report_path.is_some() && report_path == packet_path {
            return Err("report and packet destinations must differ".into());
        }
        benchmark(report_path.as_deref(), packet_path.as_deref())
    }

    fn context() -> Result<[u8; 32]> {
        let mut context = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut context)?;
        Ok(context)
    }

    fn fixture(context: [u8; 32], index: u64) -> Result<NativeFixture> {
        native::generate_fixture(
            context,
            index,
            FixtureAmounts {
                input: [100, 200],
                output: [125, 175],
            },
        )
        .map_err(|e| format!("native fixture generation: {e}").into())
    }

    fn verify(context: &[u8; 32], statement: &[u8], proof: &[u8]) -> Result<bool> {
        native::verify(context, statement, proof)
            .map_err(|e| format!("native verification: {e}").into())
    }

    fn mutation_checks(context: &[u8; 32], fixture: &NativeFixture) -> Result<()> {
        let mut bad_proof = fixture.proof.clone();
        *bad_proof
            .first_mut()
            .ok_or("native fixture returned an empty proof")? ^= 1;
        if matches!(
            native::verify(context, &fixture.statement, &bad_proof),
            Ok(true)
        ) {
            return Err("native verifier accepted mutated proof".into());
        }
        let mut bad_context = *context;
        bad_context[0] ^= 1;
        if matches!(
            native::verify(&bad_context, &fixture.statement, &fixture.proof),
            Ok(true)
        ) {
            return Err("native verifier accepted mutated context".into());
        }
        Ok(())
    }

    fn benchmark(report_path: Option<&Path>, packet_path: Option<&Path>) -> Result<()> {
        // Fail before performing an expensive run if an output already exists.
        for path in [report_path, packet_path].into_iter().flatten() {
            if path.exists() {
                return Err(format!("output already exists: {}", path.display()).into());
            }
        }
        let warmup_context = context()?;
        let warmup = fixture(warmup_context, 0)?;
        if !verify(&warmup_context, &warmup.statement, &warmup.proof)? {
            return Err("warmup public verification failed".into());
        }
        mutation_checks(&warmup_context, &warmup)?;
        let mut samples = Vec::new();
        let mut generation_times = Vec::new();
        let mut verification_times = Vec::new();
        let mut last_packet = None;
        let mut last_context = None;
        for index in 0..MEASURED_SAMPLES {
            let context = context()?;
            let fixture = fixture(context, (index + 1) as u64)?;
            let started = Instant::now();
            let accepted = verify(&context, &fixture.statement, &fixture.proof)?;
            let verification_ns = u64::try_from(started.elapsed().as_nanos())?;
            if !accepted {
                return Err("measured fixture public verification failed".into());
            }
            mutation_checks(&context, &fixture)?;
            generation_times.push(fixture.generation_ns);
            verification_times.push(verification_ns);
            samples.push(json!({
                "sample": index + 1,
                "native_fixture_generation_ns": fixture.generation_ns,
                "initial_fixture_verification_ns": fixture.verification_ns,
                "public_verification_ns": verification_ns,
                "proof_bytes": fixture.proof.len(),
                "complete_public_statement_bytes": fixture.statement.len(),
                "public_verification_accepted": true,
                "mutated_proof_rejected": true,
                "mutated_context_rejected": true,
            }));
            last_context = Some(hex(&context));
            last_packet = Some(
                NativePacket {
                    context,
                    statement: fixture.statement,
                    proof: fixture.proof,
                }
                .encode()?,
            );
        }
        generation_times.sort_unstable();
        verification_times.sort_unstable();
        let report = json!({
            "schema": "lattica-matrict-native-benchmark-v1",
            "profile": PROFILE,
            "profile_parameters_hex": hex(&PROFILE_PARAMETERS),
            "profile_description": PROFILE_DESCRIPTION,
            "backend": "CPU native upstream research implementation",
            "architecture": std::env::consts::ARCH,
            "os": std::env::consts::OS,
            "cpu_model": cpu_model(),
            "binary_sha3_256": format!("{:x}", Sha3_256::digest(std::fs::read(std::env::current_exe()?)?)),
            "ring_pairs": native::RING_PAIRS,
            "inputs": 2,
            "outputs": 2,
            "zero_fee_fixture": true,
            "exported_packet_expected_context_hex": last_context,
            "standalone_public_packet_bytes": last_packet.as_ref().map(Vec::len),
            "warmups": 1,
            "measured_samples": MEASURED_SAMPLES,
            "fresh_context_per_sample": true,
            "samples": samples,
            "summary": {
                "median_native_fixture_generation_ns": generation_times[MEASURED_SAMPLES / 2],
                "median_public_verification_ns": verification_times[MEASURED_SAMPLES / 2],
            },
            "timing": {
                "native_fixture_generation": "Wrapper whole-fixture generation, including setup, key generation, minting and spend; not spend-only proving",
                "public_verification": "Rust native verify API wall clock on public context/statement/proof, excluding fixture generation, mutation probes, packet encoding and disk I/O",
                "initial_fixture_verification": "Separately reported native wrapper verification after fixture generation",
                "cache_state": "One warmup; fresh fixtures in one process; OS caches not cleared",
            },
            "limitations": [
                "Native CPU measurements only; no recursive-verifier, block-aggregation or GPU speedup claim",
                "Complete standalone public statement includes verifier data; it is not an integrated on-chain transaction encoding",
                "The proposed Lattica RingCT wire format, state transition, encrypted notes and HTLC support are not integrated here",
                "Research implementation and parameter set; successful checks are not a security audit or post-quantum security qualification",
                "Three measured samples do not qualify throughput, tail latency, energy or production operation",
                "Fresh public context comes from /dev/urandom; upstream native randomness and implementation limitations require separate review",
            ],
        });
        if let Some(path) = packet_path {
            let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
            output.write_all(last_packet.as_ref().unwrap())?;
            output.flush()?;
        }
        if let Some(path) = report_path {
            write_new_json(path, &report)?;
        }
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }

    fn cpu_model() -> Option<String> {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()?
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "model name").then(|| value.trim().to_owned())
            })
    }

    fn write_new_json(path: &Path, value: &Value) -> Result<()> {
        let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
        serde_json::to_writer_pretty(&mut output, value)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }

    fn verify_packet(path: &Path, expected_context: &[u8; 32]) -> Result<()> {
        let mut encoded = Vec::new();
        File::open(path)?
            .take(MAX_PACKET_BYTES + 1)
            .read_to_end(&mut encoded)?;
        if encoded.len() as u64 > MAX_PACKET_BYTES {
            return Err("public packet exceeds 64 MiB artifact limit".into());
        }
        let packet = NativePacket::decode(&encoded)?;
        if !packet.verify(expected_context)? {
            return Err("public packet verification rejected".into());
        }
        println!(
            "{}",
            json!({
                "schema": "lattica-matrict-public-verification-v1", "accepted": true,
            "profile": PROFILE, "proof_bytes": packet.proof.len(),
            "profile_parameters_hex": hex(&PROFILE_PARAMETERS),
            "complete_public_statement_bytes": packet.statement.len(),
            "standalone_public_packet_bytes": encoded.len(),
                "scope": "Independent native verification of public packet; no ledger acceptance",
            })
        );
        Ok(())
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push(DIGITS[usize::from(byte >> 4)] as char);
            text.push(DIGITS[usize::from(byte & 15)] as char);
        }
        text
    }

    fn unhex(text: &str) -> Result<Vec<u8>> {
        if text.len() % 2 != 0 {
            return Err("hex field has odd length".into());
        }
        fn nibble(byte: u8) -> Result<u8> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err("hex field must use lowercase hexadecimal".into()),
            }
        }
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
            .collect()
    }
}
