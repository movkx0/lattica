//! Diagnostic for the bounded execution engine. Never emits a block/recursive
//! proof, and exits 2 after a successful probe because this fixture does not test recursion.
use lattica_prover_p3::block_v2::{
    commitment,
    machine::{backend::RegisteredProgram, MachineAir, ProgramBuilder},
    profile,
};
use p3_batch_stark::BatchProof;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks as Val};
use p3_symmetric::Permutation;
use std::io::Read;
use std::{error::Error, fs, path::Path, process::Command, time::Instant};

const MAGIC: &[u8; 8] = b"LBV2EX01";

fn fixture() -> Result<(RegisteredProgram, Vec<Val>, Vec<Val>), Box<dyn Error>> {
    let mut b = ProgramBuilder::new(8).map_err(|e| format!("{e:?}"))?;
    let x = b.input();
    let y = b.input();
    let sum = b.add(x, y);
    let product = b.mul(x, sum);
    let inverse = b.inverse(product);
    let one = b.mul(product, inverse);
    let c1 = b.constant(Val::ONE);
    b.assert_equal(one, c1);
    let _ = b.bits(x);
    let zero = b.constant(Val::ZERO);
    let output = b.poseidon([sum, product, inverse, one, x, y, zero, c1]);
    for (i, wire) in output.into_iter().enumerate() {
        b.assert_equal(wire, b.public(i).map_err(|e| format!("{e:?}"))?);
    }
    let program = b.finish(None).map_err(|e| format!("{e:?}"))?;
    let registered =
        RegisteredProgram::new(MachineAir::new(program)).map_err(|e| format!("{e:?}"))?;
    let x = Val::from_u64(19);
    let y = Val::from_u64(23);
    let product = x * (x + y);
    let mut public = [
        x + y,
        product,
        product.inverse(),
        Val::ONE,
        x,
        y,
        Val::ZERO,
        Val::ONE,
    ];
    default_goldilocks_poseidon2_8().permute_mut(&mut public);
    Ok((registered, public.to_vec(), vec![x, y]))
}

fn verify_execution(path: &Path) -> Result<(), Box<dyn Error>> {
    // This CLI consumes only its own local, fixed-fixture artifacts. It is NOT
    // an untrusted network parser, a recursive envelope, or a production API.
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > profile::MAX_PROOF_BYTES as u64 {
        return Err("execution artifact must be a regular file <= 2 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(profile::MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err("execution artifact grew past size limit".into());
    }
    if bytes.len() < 40 || &bytes[..8] != MAGIC {
        return Err("wrong execution envelope".into());
    }
    let (registered, public, _) = fixture()?;
    if commitment::digest_from_bytes(&bytes[8..40]).map_err(|e| format!("{e:?}"))?
        != registered.id()
    {
        return Err("unregistered execution program".into());
    }
    let (proof, rest): (BatchProof<profile::Config>, _) = postcard::take_from_bytes(&bytes[40..])?;
    if !rest.is_empty() || postcard::to_allocvec(&proof)? != bytes[40..] {
        return Err("noncanonical execution encoding".into());
    }
    registered
        .verify(&proof, &public)
        .map_err(|e| format!("execution verification: {e}"))?;
    println!("standalone_execution_verification=PASS inner_proofs_loaded=0 recursive_verification=NOT_TESTED_BY_THIS_PROBE");
    Ok(())
}

fn peak_rss_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|s| s.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn run() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let (registered, public, witness) = fixture()?;
    let setup_ms = start.elapsed().as_millis();
    let a = registered.analysis();
    println!("stage=execution_only height={} active_rows={} main_width={} preprocessed_width={} permutation_width_base={} quotient_chunks={}",
        a.height, registered.air().program().active_rows(), a.main_width, a.preprocessed_width, a.permutation_width_base, a.quotient_chunks);
    println!("constraints={} max_degree={} query_multiplicity_bound={} retained_lde_lower_bound_bytes={} fri_ali_bits={} lookup_security=UNREVIEWED composition_security=NOT_ESTABLISHED",
        a.constraints, a.max_constraint_degree, a.query_multiplicity_bound, a.retained_lde_bytes, a.fri_ali_bits);
    let now = Instant::now();
    let proof = registered
        .prove(&public, &witness)
        .map_err(|e| format!("{e:?}"))?;
    let prove_ms = now.elapsed().as_millis();
    let now = Instant::now();
    registered
        .verify(&proof, &public)
        .map_err(|e| format!("{e}"))?;
    let verify_ms = now.elapsed().as_millis();
    let mut bytes = MAGIC.to_vec();
    bytes.extend(commitment::digest_bytes(registered.id())?);
    bytes.extend(postcard::to_allocvec(&proof)?);
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err("execution probe proof exceeds 2 MiB".into());
    }
    // Create a private, uniquely named directory, never follow an existing one.
    use rand::RngExt;
    let nonce: u64 = rand::rng().random();
    let dir = std::env::temp_dir().join(format!(
        "lattica-execution-probe-{}-{nonce:016x}",
        std::process::id()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&dir)?;
    let path = dir.join("execution.proof");
    let result = (|| -> Result<(), Box<dyn Error>> {
        fs::write(&path, &bytes)?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--verify-execution")
            .arg(&path)
            .status()?;
        if !status.success() {
            return Err("fresh-process execution verification failed".into());
        }
        Ok(())
    })();
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir(&dir);
    result?;
    println!("setup_ms={setup_ms} prove_ms={prove_ms} verify_ms={verify_ms} proof_bytes={} peak_rss_kib={:?} scratch_artifact_bytes={} gpu_used=false",
        bytes.len(), peak_rss_kib(), bytes.len());
    println!("execution_gate=PASS recursion_gate=NOT_TESTED_BY_THIS_PROBE final_block_proofs=0");
    println!("recursive_evidence=use_block-v2-recursion-probe composition_security=UNREVIEWED production_ready=false");
    Ok(())
}

fn main() {
    if std::env::var_os("RAYON_NUM_THREADS").is_none() {
        std::env::set_var("RAYON_NUM_THREADS", "8");
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "--verify-execution" {
        if let Err(e) = verify_execution(Path::new(&args[1])) {
            eprintln!("execution_verification=FAIL error={e}");
            std::process::exit(1);
        }
        return;
    }
    if !args.is_empty() {
        eprintln!("usage: block-v2-execution-probe [--verify-execution PATH]");
        std::process::exit(1);
    }
    if let Err(e) = run() {
        eprintln!("execution_gate=FAIL error={e}");
        std::process::exit(1);
    }
    std::process::exit(2);
}
