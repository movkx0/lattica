//! Explicit research selectors; never a production transaction command.
use lattica_pq_direct_spend_research::{note, ring, Context};
#[cfg(feature = "gpu-proving")]
mod gpu_workflow;
#[cfg(all(test, feature = "gpu-proving"))]
mod gpu_memory_tests;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let context = Context([19; 32]);
    let arg_refs: Vec<_> = args.iter().map(String::as_str).collect();
    #[cfg(feature = "gpu-proving")]
    let argument_host_bytes = args
        .iter()
        .try_fold(
            args.capacity() * std::mem::size_of::<String>()
                + arg_refs.capacity() * std::mem::size_of::<&str>(),
            |sum, arg| sum.checked_add(arg.capacity()),
        )
        .ok_or("argument capacity overflow")?;
    match arg_refs.as_slice() {
        ["private-note"] => {
            let (s, w) = note::fixture(context)?;
            note::check_relation(&s, &w, context)?;
            println!("{{\"profile\":\"private-note-direct-v1\",\"host_relation_only\":true,\"cryptographic_proof_generated\":false}}");
        }
        #[cfg(feature = "note-gpu")]
        ["private-note", "--inspect-gpu-memory"] => {
            let (statement, _) = note::fixture(context)?;
            let report = lattica_pq_direct_spend_research::note_gpu::diagnose(
                &statement,
                context,
                lattica_pq_direct_spend_research::note_gpu::Limits::campaign(),
            )?;
            println!("{}", serde_json::to_string(&report)?);
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
        ["ring-direct", "--compile", options @ ..] => {
            compile(context, parse_compile_options(options)?)?;
        }
        #[cfg(feature = "gpu-proving")]
        ["ring-direct", "--prove", options @ ..] => {
            gpu_workflow::run(context, options, argument_host_bytes)?;
        }
        _ => return Err("usage: lattica-pq-direct-spend-research {private-note [--prove|--inspect-gpu-memory (note-gpu feature)]|ring-direct [--compile [--memory-profile {256m|2g|8g|24g}] [--wire-profile {16m|64m}] [--representation {inline-public-montgomery-constants-v2|fused-public-linear-v1|fused-public-ntt-v1|fused-ternary-ntt-v1|fused-ternary-ranges-v1}] [--evaluate [--evaluation-backend {trace|constraints-only}]]]; ring-direct --prove --output-dir NEW_DIRECTORY [--memory-profile {2g|8g|24g}] [--wire-profile {16m|64m}] (gpu-proving feature)}; deterministic public fixtures only".into()),
    }
    Ok(())
}

#[cfg(feature = "ring-circuit")]
struct CompileOptions {
    capacity: lattica_pq_direct_spend_research::ring_circuit::CompilerCapacityProfile,
    representation: lattica_pq_direct_spend_research::ring_circuit::CompilerRepresentation,
    evaluate: bool,
    inspect_gpu_memory: bool,
    evaluation_backend: lattica_pq_direct_spend_research::ring_circuit::EvaluationBackend,
}

#[cfg(feature = "ring-circuit")]
fn parse_compile_options(args: &[&str]) -> Result<CompileOptions, Box<dyn std::error::Error>> {
    use lattica_pq_direct_spend_research::ring_circuit::CompilerCapacityProfile;
    let (mut memory, mut wires, mut representation) = (None, None, None);
    let mut evaluation_backend = None;
    let mut evaluate = false;
    let mut inspect_gpu_memory = false;
    let mut args = args.iter();
    while let Some(&option) = args.next() {
        if option == "--inspect-gpu-memory" {
            if inspect_gpu_memory || !cfg!(feature = "gpu-proving") {
                return Err(
                    "--inspect-gpu-memory requires gpu-proving and may appear only once".into(),
                );
            }
            inspect_gpu_memory = true;
            continue;
        }
        if option == "--evaluate" {
            if evaluate {
                return Err("repeated --evaluate".into());
            }
            evaluate = true;
            continue;
        }
        let value = args.next().ok_or("compiler option requires a value")?;
        match option {
            "--memory-profile" if memory.is_none() => memory = Some(value.parse()?),
            "--wire-profile" if wires.is_none() => wires = Some(value.parse()?),
            "--representation" if representation.is_none() => representation = Some(value.parse()?),
            "--evaluation-backend" if evaluation_backend.is_none() => {
                evaluation_backend = Some(value.parse()?)
            }
            _ => return Err("unknown or repeated compiler option".into()),
        }
    }
    if evaluation_backend.is_some() && !evaluate {
        return Err("--evaluation-backend requires --evaluate".into());
    }
    if evaluate && inspect_gpu_memory {
        return Err("choose either --evaluate or --inspect-gpu-memory for this diagnostic".into());
    }
    Ok(CompileOptions {
        capacity: CompilerCapacityProfile::new(
            memory.unwrap_or_default(),
            wires.unwrap_or_default(),
        ),
        representation: representation.unwrap_or_default(),
        evaluate,
        inspect_gpu_memory,
        evaluation_backend: evaluation_backend.unwrap_or_default(),
    })
}

#[cfg(feature = "ring-circuit")]
fn compile(context: Context, options: CompileOptions) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let representation = options.representation.name();
    let evaluate = options.evaluate;
    let evaluation_backend = options.evaluation_backend.name();
    let result = compile_diagnostic(context, options);
    eprintln!(
        "{}",
        serde_json::json!({
            "research_timing": "compiler_diagnostic_total",
            "representation": representation,
            "wall_seconds": started.elapsed().as_secs_f64(),
            "host_evaluation_requested": evaluate,
            "evaluation_backend": evaluation_backend,
            "diagnostic_succeeded": result.is_ok(),
            "includes_fixture_planning_and_drop": true,
            "cryptographic_proof_started": false,
        })
    );
    result
}

#[cfg(feature = "ring-circuit")]
fn compile_diagnostic(
    context: Context,
    options: CompileOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_allowance = usize::try_from(options.capacity.limits().required_host_bytes)?;
    let (s, w) = ring::fixture(context)?;
    let started = std::time::Instant::now();
    let result =
        lattica_pq_direct_spend_research::ring_circuit::compile_with_representation_diagnostics(
            &s,
            &w,
            context,
            options.capacity,
            options.representation,
            host_allowance,
        );
    eprintln!(
        "{}",
        serde_json::json!({
            "research_timing": "compiler_only",
            "representation": options.representation.name(),
            "wall_seconds": started.elapsed().as_secs_f64(),
            "cryptographic_proof_started": false,
        })
    );
    let program = match result {
        Ok(program) => program,
        Err(failure) => {
            eprintln!("{}", serde_json::to_string(&failure)?);
            return Err(failure.error.into());
        }
    };
    println!("{}", serde_json::to_string(program.summary())?);
    #[cfg(feature = "gpu-proving")]
    if options.inspect_gpu_memory {
        let footprint = program.into_gpu_memory_diagnostic()?;
        println!(
            "{}",
            serde_json::json!({
                "research_diagnostic": "gpu_memory_footprint",
                "cryptographic_proof_started": false,
                "gpu_dispatch_started": false,
                "footprint": footprint,
            })
        );
        return Ok(());
    }
    if options.evaluate {
        let plan = program.plan_evaluation_with_backend(options.evaluation_backend)?;
        let footprint = plan.footprint();
        eprintln!(
            "{}",
            serde_json::json!({
                "research_evaluation": "requested",
                "evaluation_backend": options.evaluation_backend.name(),
                "footprint": footprint,
                "host_allowance_bytes": 32_u64 << 30,
                "cryptographic_proof_started": false,
            })
        );
        let started = std::time::Instant::now();
        let evaluation_admitted = footprint.required_host_bytes <= 32_u64 << 30;
        let result = plan.evaluate_with_host_allowance(32_u64 << 30);
        eprintln!(
            "{}",
            serde_json::json!({
                "research_timing": "host_constraint_evaluation",
                "representation": options.representation.name(),
                "evaluation_backend": options.evaluation_backend.name(),
                "wall_seconds": started.elapsed().as_secs_f64(),
                "evaluation_admitted": evaluation_admitted,
                "constraints_satisfied": evaluation_admitted.then_some(result.is_ok()),
                "cryptographic_proof_started": false,
            })
        );
        result?;
    }
    Ok(())
}

#[cfg(all(test, feature = "ring-circuit"))]
mod tests {
    use super::*;

    #[test]
    fn omitted_selector_keeps_original_representation_and_limits() {
        let options = parse_compile_options(&[]).unwrap();
        assert_eq!(
            options.representation.name(),
            "inline-public-montgomery-constants-v2"
        );
        assert_eq!(options.capacity.limits().program_byte_limit, 256 << 20);
        assert_eq!(options.capacity.limits().wire_limit, 1 << 24);
        assert!(!options.evaluate);
        assert_eq!(options.evaluation_backend.name(), "trace");
    }

    #[test]
    fn explicit_selectors_are_order_independent_without_fallback() {
        for representation in [
            "fused-public-linear-v1",
            "fused-public-ntt-v1",
            "fused-ternary-ntt-v1",
            "fused-ternary-ranges-v1",
        ] {
            let options = parse_compile_options(&[
                "--representation",
                representation,
                "--wire-profile",
                "64m",
                "--evaluate",
                "--memory-profile",
                "24g",
            ])
            .unwrap();
            assert_eq!(options.representation.name(), representation);
            assert_eq!(options.capacity.limits().program_byte_limit, 24 << 30);
            assert_eq!(options.capacity.limits().wire_limit, 1 << 26);
            assert!(options.evaluate);
            assert_eq!(options.evaluation_backend.name(), "trace");
        }
        for args in [
            vec!["--representation", "unknown"],
            vec!["--wire-profile", "128m"],
            vec!["--memory-profile", "32g"],
            vec!["--representation"],
            vec!["--wire-profile", "16m", "--wire-profile", "64m"],
            vec![
                "--representation",
                "fused-public-linear-v1",
                "--representation",
                "inline-public-montgomery-constants-v2",
            ],
            vec!["--unsupported", "value"],
            vec!["--evaluate", "--evaluate"],
            vec!["--evaluation-backend", "constraints-only"],
            vec!["--evaluate", "--evaluation-backend", "unknown"],
            vec!["--evaluate", "--evaluation-backend"],
            vec![
                "--evaluate",
                "--evaluation-backend",
                "trace",
                "--evaluation-backend",
                "constraints-only",
            ],
        ] {
            assert!(parse_compile_options(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn evaluation_backend_is_independent_of_representation_and_capacity() {
        for backend in ["trace", "constraints-only"] {
            for representation in ["fused-ternary-ntt-v1", "fused-ternary-ranges-v1"] {
                let options = parse_compile_options(&[
                    "--evaluation-backend",
                    backend,
                    "--representation",
                    representation,
                    "--memory-profile",
                    "8g",
                    "--evaluate",
                ])
                .unwrap();
                assert_eq!(options.evaluation_backend.name(), backend);
                assert_eq!(options.representation.name(), representation);
                assert_eq!(options.capacity.limits().program_byte_limit, 8 << 30);
                assert_eq!(options.capacity.limits().wire_limit, 1 << 24);
                assert!(options.evaluate);
            }
        }
    }
}
