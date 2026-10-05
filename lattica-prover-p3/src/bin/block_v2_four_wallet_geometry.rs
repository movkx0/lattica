//! Read-only compiler and RAM-admission research using completed wallet proofs.
#![allow(dead_code)]
mod grouped_common;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        if args.len() != 1 {
            return Err("usage: block-v2-four-wallet-geometry EXISTING_FIXTURE_DIR".into());
        }
        let command =
            grouped_common::parse_command(&["four-wallet-geometry".into(), args[0].clone()])?;
        grouped_common::run(command, None, true)
    })();
    if let Err(error) = result {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}
