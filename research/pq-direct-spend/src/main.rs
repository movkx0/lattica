//! Explicit research selectors; never a production transaction command.
use lattica_pq_direct_spend_research::{note, ring, Context};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let context = Context([19; 32]);
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["private-note"] => {
            let (s, w) = note::fixture(context)?;
            note::check_relation(&s, &w, context)?;
            println!("{{\"profile\":\"private-note-direct-v1\",\"host_relation_only\":true,\"cryptographic_proof_generated\":false}}");
        }
        ["private-note", "--prove"] => {
            let (s, w) = note::fixture(context)?;
            let (_, report) = note::prove(&s, &w, context)?;
            println!("{}", serde_json::to_string(&report)?);
        }
        ["ring-direct"] => {
            let (s, w) = ring::fixture(context)?;
            ring::check_relation(&s, &w, context)?;
            println!("{{\"profile\":\"ring-direct-v1\",\"host_relation_only\":true,\"cryptographic_proof_generated\":false,\"proof_status\":\"incomplete\"}}");
        }
        #[cfg(feature = "ring-circuit")]
        ["ring-direct", "--compile"] => {
            let (s, w) = ring::fixture(context)?;
            let program = match lattica_pq_direct_spend_research::ring_circuit::compile_with_diagnostics(&s, &w, context, 400 << 20) {
                Ok(program) => program,
                Err(failure) => {
                    eprintln!("{}", serde_json::to_string(&failure)?);
                    return Err(failure.error.into());
                }
            };
            println!("{}", serde_json::to_string(program.summary())?);
        }
        _ => return Err("usage: lattica-pq-direct-spend-research {private-note [--prove]|ring-direct [--compile]}; deterministic public fixtures only".into()),
    }
    Ok(())
}
