//! Experimental single-task CPU worker; no network listener or production ABI.
#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use lattica_prover_p3::block_v2::execution::{process, transport};
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(flag), None, None) if flag == "--fingerprint" => {
            for byte in transport::running_image_fingerprint()? {
                print!("{byte:02x}");
            }
            println!();
            Ok(())
        }
        (Some(flag), Some(path), None) if flag == "--task" => {
            // SAFETY: main has not spawned threads or initialized the allocator's
            // spill configuration. This process handles exactly one task and exits.
            unsafe { process::run_task_single_threaded(std::path::Path::new(&path)) }
        }
        _ => Err("usage: block-v2-cpu-worker --fingerprint | --task /absolute/task/path".into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("experimental CPU worker requires Linux cgroup v2".into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("cpu_task=REJECTED error={error}");
        std::process::exit(2);
    }
}
