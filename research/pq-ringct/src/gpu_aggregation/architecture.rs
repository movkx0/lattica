//! Architectural geometry and bounded GPU proof screens on trusted programs.
//! Field counts describe work, not latency or a peak-allocation certificate.
use super::*;
mod reference;
mod request;
use lattica_prover_p3::block_v2::machine::{
    analysis, recursion::RecursionTemplate, MachineAir, Program,
};

pub(crate) fn gpu_limits() -> lattica_prover_p3::block_v2::machine::recursion::GpuTemplateLimits {
    lattica_prover_p3::block_v2::machine::recursion::GpuTemplateLimits {
        host_bytes: policy::current().backend_host_bytes as usize,
        // Reserve the additional public salt backing within the same backend
        // allowance; PCS operations retain their own enforced scratch bound.
        pcs_host_bytes: if policy::current().name == "typed-batch" {
            11 << 30
        } else {
            12 << 30
        },
        max_rows: if policy::current().name == "typed-batch" {
            1 << 20
        } else {
            1 << 19
        },
    }
}

/// Native coverage remains checked by the original request schedule. The new
/// multi-table backend must not inherit the old MachineAir padding limit.
pub(crate) fn direct_spans(
    request: &graph_crypto::Request,
    maximum: usize,
) -> Result<Vec<graph_crypto::ShakeWrapperSpan>> {
    ensure(
        matches!(maximum, 1 | 2 | 4 | 8 | 16),
        "typed native batch size",
    )?;
    match request.descriptor() {
        graph_crypto::RequestDescriptor::Shake(_) => {
            request
                .shake_wrapper_schedule(graph_crypto::ShakeWrapperLayout::Singleton)
                .map_err(error)?;
        }
        graph_crypto::RequestDescriptor::Aes(descriptor) => {
            use p3_air::BaseAir;
            let mut end = 0usize;
            for segment in request.segments() {
                ensure(segment.first_unit == end, "AES native schedule coverage")?;
                let air = crate::aes_lane_air::AesLaneAir::segment(
                    descriptor,
                    segment.first_unit,
                    segment.units,
                )
                .map_err(|error| format!("AES schedule: {error:?}"))?;
                ensure(
                    air.height == segment.height && air.width() == segment.width,
                    "AES native schedule geometry",
                )?;
                end = end
                    .checked_add(segment.units)
                    .ok_or("AES schedule overflow")?;
            }
            ensure(
                end == descriptor.blocks() && end != 0,
                "AES native schedule completeness",
            )?;
        }
    }
    let mut spans = Vec::new();
    for first in (0..request.segments().len()).step_by(maximum) {
        let count = maximum.min(request.segments().len() - first);
        let start = &request.segments()[first];
        let last = &request.segments()[first + count - 1];
        spans.push(graph_crypto::ShakeWrapperSpan {
            first_segment: first,
            segment_count: count,
            first_unit: start.first_unit,
            units: last.first_unit + last.units - start.first_unit,
        });
    }
    Ok(spans)
}

fn profile_gpu(
    node: &component_tree::CompiledNode,
    options: &Options,
    deadline: &Deadline,
) -> Result<serde_json::Value> {
    use lattica_prover_p3::block_v2::machine::recursion::PreparedGpuRecursionTemplate;
    deadline.check()?;
    let started = Instant::now();
    let template = RecursionTemplate::new(
        node.shared_program(),
        crate::graph_proofs::compiled_source_fingerprint(),
    )?;
    let geometry = template.geometry()?;
    let prepared = template.prepare_gpu(gpu_limits())?;
    let setup_seconds = started.elapsed().as_secs_f64();
    let mut samples = Vec::new();
    let mut parent_owner: Option<PreparedGpuRecursionTemplate> = None;
    let mut parent_identity = None;
    let mut parent_geometry = None;
    for repetition in 0..options.repetitions {
        deadline.check()?;
        let (proof, measurement) = prepared.prove(node.public_values(), node.witness_values())?;
        eprintln!(
            "GPU_AGGREGATION_ARCHITECTURE_PROOF {}",
            serde_json::to_string(&measurement).map_err(error)?
        );
        let parent = if options.command == "architecture-parent" {
            deadline.check()?;
            let started = Instant::now();
            let compiled = prepared.compile_verifier(&proof, construction())?;
            let template = RecursionTemplate::new(
                Arc::clone(compiled.program()),
                crate::graph_proofs::compiled_source_fingerprint(),
            )?;
            let compile_seconds = started.elapsed().as_secs_f64();
            let mut setup_seconds = 0.0;
            if parent_owner.is_none() {
                let started = Instant::now();
                parent_identity = Some(template.identity());
                parent_geometry = Some(template.geometry()?);
                parent_owner = Some(template.prepare_gpu(gpu_limits())?);
                setup_seconds = started.elapsed().as_secs_f64();
            }
            ensure(
                parent_identity == Some(template.identity()),
                "fresh child proof changed trusted parent template",
            )?;
            deadline.check()?;
            let (_, parent_measurement) = parent_owner
                .as_ref()
                .unwrap()
                .prove(node.public_values(), compiled.witness())?;
            eprintln!(
                "GPU_AGGREGATION_ARCHITECTURE_PARENT {}",
                serde_json::to_string(&parent_measurement).map_err(error)?
            );
            Some(serde_json::json!({"compile_seconds":compile_seconds,
                "setup_seconds":setup_seconds,"measurement":parent_measurement,
                "constrained_child_verification":true}))
        } else {
            None
        };
        samples.push(
            serde_json::json!({"repetition":repetition,"measurement":measurement,"parent":parent}),
        );
    }
    Ok(
        serde_json::json!({"scope":if options.command == "architecture-parent" {"native-wrapper-and-constrained-parent-gpu-proof"} else {"single-native-wrapper-gpu-proof"},"complete_aggregation":false,
        "production_qualified":false,"template_identity":hex(&template.identity()),"geometry":geometry,
        "setup_seconds":setup_seconds,"samples":samples,"parent_geometry":parent_geometry,
        "parent_template_identity":parent_identity.map(|id|hex(&id)),"host_witness_generation":true,
        "gpu_backend_only":true,"independent_cpu_verification":true}),
    )
}

pub(crate) fn inspect(program: Arc<Program>) -> Result<serde_json::Value> {
    let started = Instant::now();
    let old = analysis::analyze_bounded_cpu(&MachineAir::from_shared_program(Arc::clone(&program)))
        .map_err(|e| format!("reference architecture geometry: {e:?}"))?;
    // This is a diagnostic namespace, not a production registry or acceptance
    // identity. The program itself still binds every actual native child key.
    let template =
        RecursionTemplate::new(program, crate::graph_proofs::compiled_source_fingerprint())?;
    let new = template.geometry()?;
    let report = serde_json::json!({
        "schema":"ringct-recursion-architecture-screen-v1",
        "scope":"compiled-verifier-geometry-only",
        "proofs_generated":0,
        "production_qualified":false,
        "baseline_height":old.height,
        "baseline_lde_payload_bytes":old.retained_lde_bytes,
        "baseline_quotient_chunks":old.quotient_chunks,
        "candidate":new,
        "lde_work_ratio":new.lde_payload_bytes as f64/old.retained_lde_bytes as f64,
        "seconds":started.elapsed().as_secs_f64(),
    });
    eprintln!("GPU_AGGREGATION_ARCHITECTURE {report}");
    Ok(report)
}

/// Read an old bundle without rewriting any file or manufacturing a current
/// source receipt. Native acceptance comes only from import_segment's current
/// exact-request verifier. This command cannot create an aggregate artifact.
pub(crate) fn archive_request(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    let (archive_source, inventory) = bundle::validate_archive(options)?;
    let (cases, input_sha3) = inputs::load(options)?;
    let case = &cases[0];
    let index = options.request.ok_or("archive preflight needs a request")?;
    let request = case
        .plan
        .requests()
        .get(index)
        .ok_or("archive request index")?;
    ensure(
        matches!(
            (request.descriptor(), options.family.as_str()),
            (graph_crypto::RequestDescriptor::Shake(_), "shake")
                | (graph_crypto::RequestDescriptor::Aes(_), "aes")
        ),
        "archive request family mismatch",
    )?;
    let typed = options.typed_recursion();
    let spans = if typed || options.family == "aes" {
        direct_spans(request, options.group_width)?
    } else {
        graph_crypto::imported_group_spans(request, options.group_width, options.max_rows())
            .map_err(error)?
    };
    if options.command == "architecture-request" {
        ensure(
            (1..=8).contains(&spans.len()),
            "request screen requires one to eight native groups",
        )?;
    }
    let caches = bundle::Caches::new(&options.bundle, false)?;
    let execution = context(options)?;
    let outcome: Result<serde_json::Value> = (|| {
        let limits = execution.aggregation_backend_limits()?;
        let contract = request.contract().map_err(error)?;
        let endpoints = request.endpoint_context_hint(&case.context);
        let mut architecture = Vec::new();
        let imports = std::sync::Mutex::new(Vec::new());
        let imported_segments = std::sync::Mutex::new(std::collections::BTreeSet::new());
        let prepare = |index: usize| -> Result<(component_tree::CompiledNode, bool)> {
            let span = &spans[index];
            let mut native_order_rejected = false;
            deadline.check()?;
            let mut children = Vec::new();
            for i in span.first_segment..span.first_segment + span.segment_count {
                let key = request
                    .cache_key_at_source(i, archive_source)
                    .map_err(error)?;
                let relative = format!("crypto/{}.json", hex(&key));
                let expected = inventory
                    .get(&relative)
                    .ok_or("archive component absent from inventory")?;
                let imported = caches
                    .crypto
                    .import_segment(request, i, &options.bundle.join(&relative))
                    .map_err(error)?;
                ensure(
                    imported.archived_key == key && &hex(&imported.archive_sha3_256) == expected,
                    "archive changed during revalidation",
                )?;
                if imported_segments.lock().map_err(error)?.insert(i) {
                    imports.lock().map_err(error)?.push(serde_json::json!({"segment":i,"archive_key":hex(&key),"archive_sha3":expected,"current_request_key":hex(&imported.current_key),"verified_against_current_contract":true}));
                }
                children.push(imported.artifact);
            }
            if options.family == "aes" {
                let mut members = children
                    .iter()
                    .enumerate()
                    .map(|(offset, artifact)| {
                        let graph_crypto::SegmentArtifact::Aes(proof) = artifact else {
                            return Err("archive AES artifact family".to_owned());
                        };
                        let segment = &request.segments()[span.first_segment + offset];
                        Ok(component_tree::aes_group::Member {
                            first: segment.first_unit.try_into().map_err(error)?,
                            count: segment.units.try_into().map_err(error)?,
                            proof,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let compile_limits = super::typed::job_limits(span.segment_count)?.0;
                if members.len() > 1 {
                    members.swap(0, 1);
                    ensure(
                        component_tree::aes_group::compile(
                            &contract,
                            &members,
                            &endpoints,
                            compile_limits,
                        )
                        .is_err(),
                        "AES batch accepted reordered native segments",
                    )?;
                    members.swap(0, 1);
                    native_order_rejected = true;
                }
                let node = component_tree::aes_group::compile(
                    &contract,
                    &members,
                    &endpoints,
                    compile_limits,
                )
                .map_err(error)?;
                if !typed {
                    node.preflight_imported(limits)?;
                }
                return Ok((node, native_order_rejected));
            }
            let mut members = children
                .iter()
                .enumerate()
                .map(|(offset, artifact)| {
                    let graph_crypto::SegmentArtifact::Shake(proof) = artifact else {
                        return Err("archive artifact family".to_owned());
                    };
                    let segment = &request.segments()[span.first_segment + offset];
                    Ok(component_tree::ShakeGroupMember {
                        first: segment.first_unit.try_into().map_err(error)?,
                        count: segment.units.try_into().map_err(error)?,
                        proof,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if options.command == "architecture-request" && members.len() > 1 {
                members.swap(0, 1);
                ensure(
                    component_tree::compile_shake_group_bounded_with_context(
                        &contract,
                        &members,
                        &endpoints,
                        None,
                        construction(),
                        crate::component_tree::paired_runtime::source::AUXILIARY_BYTES,
                    )
                    .is_err(),
                    "direct batch accepted reordered native proofs",
                )?;
                members.swap(0, 1);
                native_order_rejected = true;
            }
            let compiled = component_tree::compile_shake_group_bounded_with_context(
                &contract,
                &members,
                &endpoints,
                None,
                if typed {
                    super::typed::job_limits(span.segment_count)?.0
                } else {
                    construction()
                },
                crate::component_tree::paired_runtime::source::AUXILIARY_BYTES,
            )
            .map_err(error)?;
            let component_tree::ShakeGroupCompileOutcome::Compiled(node) = compiled else {
                return Err("archive wrapper compiler admission".into());
            };
            if !typed {
                node.preflight_imported(limits)?;
            }
            Ok((node, native_order_rejected))
        };
        if options.command == "architecture-request" {
            let weights = spans
                .iter()
                .map(|s| super::typed::job_limits(s.segment_count).map(|(_, weight)| weight))
                .collect::<Result<Vec<_>>>()?;
            let mut proof_profile = if typed {
                request::profile(&weights, &contract, options, deadline, &prepare)?
            } else {
                reference::profile(
                    spans.len(),
                    &endpoints,
                    options,
                    deadline,
                    &execution,
                    &prepare,
                )?
            };
            proof_profile["first_request_including_native_preparation_seconds"] =
                proof_profile["samples"][0]["seconds"].clone();
            proof_profile["native_preparation_seconds"] =
                proof_profile["samples"][0]["native_preparation_seconds"].clone();
            drop(prepare);
            return Ok(
                serde_json::json!({"scope":"recursion-architecture-request-screen",
                "proofs_generated":options.repetitions*proof_profile["proofs_per_sample"].as_u64().unwrap() as usize,"native_proofs_generated":0,
                "complete_aggregation":false,"complete_request":true,"verified":true,
                "native_components":request.segments().len(),"proof_profile":proof_profile,
                "source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),"input_sha3":input_sha3,
                "archive_source_sha3":hex(&archive_source),"archive_source_is_untrusted_metadata":true,
                "archive_files_rewritten":0,"current_cache_entries_created":0,"imports":imports}),
            );
        }
        for (index, span) in spans.iter().enumerate() {
            let (node, _) = prepare(index)?;
            if matches!(
                options.command.as_str(),
                "architecture-proof" | "architecture-parent"
            ) {
                let proof_profile = profile_gpu(&node, options, deadline)?;
                drop(prepare);
                return Ok(
                    serde_json::json!({"scope":"recursion-architecture-proof-screen",
                    "proofs_generated":options.repetitions * if options.command == "architecture-parent" {2} else {1},"native_proofs_generated":0,
                    "complete_aggregation":false,"verified":true,"wrapper_first_segment":span.first_segment,
                    "wrapper_native_components":span.segment_count,"proof_profile":proof_profile,
                    "source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),"input_sha3":input_sha3,
                    "archive_source_sha3":hex(&archive_source),"archive_source_is_untrusted_metadata":true,
                    "archive_files_rewritten":0,"current_cache_entries_created":0,"imports":imports}),
                );
            }
            architecture.push(inspect(node.shared_program())?);
        }
        drop(prepare);

        Ok(
            serde_json::json!({"scope":"shake-group-preflight","proofs_generated":0,"native_proofs_generated":0,
            "source_and_backend_checked":true,"admitted_maximum_group":spans.iter().map(|s|s.segment_count).max().unwrap_or(1),
            "source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),"input_sha3":input_sha3,
            "archive_source_sha3":hex(&archive_source),"archive_source_is_untrusted_metadata":true,
            "archive_files_rewritten":0,"current_cache_entries_created":0,"imports":imports,"architecture":architecture}),
        )
    })();
    let cleanup = execution.close_without_completion()?;
    let mut report: serde_json::Value = outcome?;
    report["session"] = cleanup;
    Ok(report)
}
