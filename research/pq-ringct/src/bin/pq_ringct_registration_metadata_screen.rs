//! CPU-only metadata measurements; launch under the serialized resource guard.
use lattica_prover_p3::block_v2::machine::backend::metadata_screen;
use std::io::{self, Write};

const MAX_REPORT_BYTES: usize = 512 << 10;
struct BoundedReport(Vec<u8>);
impl Write for BoundedReport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_REPORT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other(
                "metadata screen report exceeds reservation",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(argument) = args.next() else {
        return Err("--host-bytes is required".into());
    };
    if argument == "--help" {
        println!("pq-ringct-registration-metadata-screen --host-bytes N\nRelease x86_64 wide profile only. CPU metadata construction and synthetic lookup measurements; no GPU operation or proof. Use the external serialized resource guard.");
        return Ok(());
    }
    if argument != "--host-bytes" {
        return Err("expected --host-bytes".into());
    }
    let host = args
        .next()
        .ok_or("missing host allowance")?
        .parse::<usize>()
        .map_err(|e| e.to_string())?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let report = metadata_screen::run(host)?;
    // Only a bounded measurement report escapes the backend screen.
    let mut encoded = BoundedReport(Vec::with_capacity(MAX_REPORT_BYTES));
    serde_json::to_writer_pretty(&mut encoded, &report).map_err(|e| e.to_string())?;
    let mut output = io::stdout().lock();
    output.write_all(&encoded.0).map_err(|e| e.to_string())?;
    output.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("metadata screen refused: {error}");
        std::process::exit(1);
    }
}
