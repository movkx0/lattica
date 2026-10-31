//! Fresh-process entry point; use the guarded OpenCL qualification harness.
use lattica_pq_ringct_research::opencl::{self, Limits, Stage};

fn run() -> Result<(), String> {
    let mut stage = None;
    let mut host = None;
    let mut device = None;
    let mut rows = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--help" {
            println!("pq-ringct-opencl-probe --stage pq-byte|pq-aes-component --host-bytes N --device-bytes N --max-rows N\nRelease only. Requires explicit owned OpenCL environment and external exclusive memory admission.");
            return Ok(());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        match argument.as_str() {
            "--stage" if stage.is_none() => stage = Some(Stage::parse(&value)?),
            "--host-bytes" if host.is_none() => {
                host = Some(value.parse::<u64>().map_err(|e| e.to_string())?)
            }
            "--device-bytes" if device.is_none() => {
                device = Some(value.parse::<u64>().map_err(|e| e.to_string())?)
            }
            "--max-rows" if rows.is_none() => {
                rows = Some(value.parse::<usize>().map_err(|e| e.to_string())?)
            }
            _ => return Err(format!("unknown or duplicate argument {argument}")),
        }
    }
    let limits = Limits {
        host_bytes: host.ok_or("--host-bytes is required")?,
        device_bytes: device.ok_or("--device-bytes is required")?,
        max_rows: rows.ok_or("--max-rows is required")?,
    };
    let result = opencl::qualify(stage.ok_or("--stage is required")?, limits)?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pq_opencl_qualification_failed: {error}");
        std::process::exit(1);
    }
}
