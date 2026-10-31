//! Launch with the serialized RingCT worker guard and its unchanged limits.
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
fn run() -> Result<(), String> {
    fn hex32(value: &str) -> Result<[u8; 32], String> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("seed and context must each contain64hexadecimal digits".into());
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
                .map_err(|_| "invalid hexadecimal value")?;
        }
        Ok(out)
    }
    let mut case = None;
    let mut paired = None;
    let mut seed = None;
    let mut context = None;
    let mut identity_schedule = None;
    let mut identity_streams = None;
    let mut host_profile = None;
    let mut planning_cache = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--help" {
            println!("Host memory: --host-profile standard|expanded-36|expanded-40 (default standard); must match the runner. No automatic escalation.");
            println!("Planning: --planning-cache off|geometry-v1 (default off), 64 numerical entries within the 64 MiB metadata allowance.");
            println!("Optional preprocessing: --identity-preprocessing serial|batched-v1 --identity-max-streams 1|2|4|8|16. Batched mode requires identity-batch-experiment and complete pre-dispatch memory admission; default is serial.");
            println!("pq-ringct-full-workflow --case n3|n4 --layout singleton|paired-v1 --seed HEX64 --context HEX64\nFresh transaction generation, complete proof graphs, aggregation and CPU verification. Run with the serialized resource guard. Artifact and mutation qualification are explicit report fields.");
            return Ok(());
        }
        let value = args.next().ok_or("missing option value")?;
        match argument.as_str() {
            "--planning-cache" if planning_cache.is_none() => {
                planning_cache = Some(match value.as_str() {
                    "off" => false, "geometry-v1" => true,
                    _ => return Err("expected off or geometry-v1".into()),
                });
            }
            "--host-profile" if host_profile.is_none() => {
                host_profile = Some(value.parse::<lattica_pq_ringct_research::host_memory_profile::HostMemoryProfile>()?);
            }
            "--case" if case.is_none() => {
                case = Some(match value.as_str() {
                    "n3" => 3,
                    "n4" => 4,
                    _ => return Err("expected n3 or n4".into()),
                })
            }
            "--layout" if paired.is_none() => {
                paired = Some(match value.as_str() {
                    "singleton" => false,
                    "paired-v1" => true,
                    _ => return Err("expected singleton or paired-v1".into()),
                })
            }
            "--seed" if seed.is_none() => seed = Some(hex32(&value)?),
            "--context" if context.is_none() => context = Some(hex32(&value)?),
            "--identity-preprocessing" if identity_schedule.is_none() => identity_schedule = Some(value),
            "--identity-max-streams" if identity_streams.is_none() =>
                identity_streams = Some(value.parse::<usize>().map_err(|_| "invalid identity stream ceiling")?),
            _ => return Err("unknown or repeated option".into()),
        }
    }
    let limits = lattica_prover_p3::block_v2::machine::backend::identity_batch::IdentityBatchLimits::parse(
        identity_schedule.as_deref().unwrap_or("serial"), identity_streams).map_err(str::to_owned)?;
    lattica_pq_ringct_research::full_workflow_experiment::run_case_with_options(
        case.ok_or("--case is required")?,
        paired.ok_or("--layout is required")?,
        seed.ok_or("--seed is required")?,
        context.ok_or("--context is required")?,
        limits,
        host_profile.unwrap_or_default(),
        planning_cache.unwrap_or(false),
    )
}
fn main() {
    #[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("full workflow requires a release Linux x86_64 build");
        std::process::exit(2);
    }
}
