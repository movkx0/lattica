//! Pure CPU preparation for a bounded lookahead worker. This API never creates
//! a device configuration/session; the existing retired-GPU-analysis API keeps
//! its original retirement requirement.
use super::*;
impl IdentityCpuContext {
    pub fn prepare_cpu_only(
        &self,
        program: &Arc<Program>,
        host_allowance: u64,
    ) -> Result<(CompletedIdentityPrefix, CpuWorkerReport), String> {
        let footprint = IdentityBatchFootprint::for_borrowed_program_bounds(
            1,
            program.source_host_bytes()? as u64,
        )?;
        if footprint.host_bytes > host_allowance {
            return Err("CPU lookahead identity exceeds admitted auxiliary storage".into());
        }
        let job = self
            .next_batch
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| "CPU lookahead identity ordinal overflow")?;
        let run = cpu_run("block_v2_cpu_lookahead_identity")?;
        let started = std::time::Instant::now();
        let output = run
            .measure(
                Stage::Preprocessing,
                Backend::Cpu,
                || -> Result<_, String> {
                    let air = MachineAir::from_shared_program(Arc::clone(program));
                    let symbolic = super::super::super::symbolic::prepare_machine(
                        &air,
                        super::super::super::compiler_constants::Constants::cpu(),
                    )
                    .map_err(|e| format!("CPU prefix analysis: {e:?}"))?;
                    let analysis = analysis::analyze_prepared(&air, &symbolic)
                        .map_err(|e| format!("CPU prefix analysis: {e:?}"))?;
                    let (_, constraints) = symbolic.into_parts();
                    let fingerprint = fingerprint::bounded::encode(
                        &constraints.base,
                        &constraints.extension,
                        &constraints.order,
                        fingerprint::bounded::HOST_BYTES,
                    )?;
                    drop(constraints);
                    let fields = prefix_len(&air, &analysis, &fingerprint)?;
                    let cap_fields = 4usize
                        .checked_shl(
                            (program.height().ilog2() as usize + 1 + profile::LOG_BLOWUP)
                                .min(profile::CAP_HEIGHT) as u32,
                        )
                        .ok_or("CPU identity cap overflow")?;
                    let mut state = State::new(
                        DOMAIN,
                        fields
                            .checked_add(cap_fields)
                            .ok_or("CPU identity size overflow")?,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                    for field in identity_stream::Cursor::new(&air, &analysis, &fingerprint) {
                        state.push(field?).map_err(|e| format!("{e:?}"))?;
                    }
                    let token = CompletedIdentityPrefix {
                        authority: Arc::clone(&self.authority),
                        batch: job,
                        job,
                        program: Arc::clone(program),
                        header: identity_stream::header(&air),
                        trailer: identity_stream::trailer(&analysis),
                        fingerprint,
                        cap_fields,
                        state,
                    };
                    if token.retained_host_bytes() > IDENTITY_PREFIX_HOST_BYTES {
                        return Err("CPU identity retained capacity".into());
                    }
                    Ok((
                        token,
                        CpuWorkerReport {
                            job,
                            fields: fields as u64,
                            elapsed_ns: started.elapsed().as_nanos(),
                        },
                    ))
                },
            )
            .map_err(|e| e.to_string())??;
        run.finish(true).map_err(|e| e.to_string())?;
        Ok(output)
    }
}
