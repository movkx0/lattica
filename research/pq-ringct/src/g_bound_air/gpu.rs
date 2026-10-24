//! GPU-generated native trace with bounded immutable periodic metadata.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{
    arithmetic::ArithmeticSpec, GeneratedTrace, PeriodicSource, TraceContext,
};

impl GBoundAir {
    fn gpu_periodic_value(&self, index: usize, row: usize) -> Val {
        let psi = Val::two_adic_generator(9);
        if index < 32 {
            let stage = index % 8;
            let size = D >> stage;
            let half = size / 2;
            let j = row % half;
            let a = (row / half) * size + j;
            match index / 8 {
                0 => Val::from_usize(a),
                1 => Val::from_usize(a + half),
                2 => psi.square().exp_u64((j * D / size) as u64),
                _ => psi.square().inverse().exp_u64((j * D / size) as u64),
            }
        } else {
            match index {
                TWIST_FACTOR => psi.exp_u64(row as u64),
                UNTWIST_FACTOR => psi.inverse().exp_u64(row as u64) * Val::from_usize(D).inverse(),
                ROW_INDEX => Val::from_usize(row),
                HASH_INDEX => Val::from_usize(4 * (row % 64)),
                FIRST_HALF => Val::from_bool(row < 64),
                HASH_END => Val::from_bool(row == 63),
                BLOCK_END => Val::from_bool(row == 127),
                _ => unreachable!(),
            }
        }
    }
    pub fn generate_gpu(
        &self,
        ctx: &TraceContext<'_>,
        f: &[i64; D],
        x: &[i64; D],
    ) -> Result<GeneratedTrace, String> {
        let schedule: Vec<u64> = (0..PERIODIC)
            .flat_map(|column| {
                (0..SCHEDULE_PERIOD)
                    .map(move |row| self.gpu_periodic_value(column, row).as_canonical_u64())
            })
            .collect();
        let psi = Val::two_adic_generator(9);
        let spec = ArithmeticSpec::g_bound(
            self.f_bound,
            self.g_bound,
            &schedule,
            psi.exp_u64(128).as_canonical_u64(),
            psi.inverse().exp_u64(128).as_canonical_u64(),
        )?;
        drop(schedule);
        ctx.admit_arithmetic_raw(&spec)?;
        let raw: Vec<_> = f.iter().chain(x).map(|&v| v as u64).collect();
        ctx.arithmetic_trace(&spec, &raw)
    }
}
impl PeriodicSource for GBoundAir {
    fn column_count(&self) -> usize {
        PERIODIC
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC).then_some(SCHEDULE_PERIOD)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("GBound periodic shape".into());
        }
        for (row, v) in output.iter_mut().enumerate() {
            *v = self.gpu_periodic_value(index, row);
        }
        Ok(())
    }
}

impl join::RegisteredGBoundAir {
    /// Prove from raw inputs entirely on the admitted OpenCL backend, then
    /// independently verify with the unchanged native CPU verifier.
    pub fn prove_gpu(
        &self,
        f: &[i64; D],
        x: &[i64; D],
        host_bytes: usize,
        request: lattica_prover_p3::proving::Request,
    ) -> Result<(join::GBoundArtifact, lattica_prover_p3::proving::Report), crate::crypto_join::Error>
    {
        let backend = |message: String| {
            crate::crypto_join::Error::Compile(
                lattica_prover_p3::block_v2::machine::verifier::CompileError::Backend(message),
            )
        };
        let proved = lattica_prover_p3::block_v2::native_gpu::prove(
            "matrict_g_bound_air_gpu",
            self.air(),
            self.air(),
            HEIGHT,
            host_bytes,
            request,
            |ctx| self.air().generate_gpu(ctx, f, x),
        )
        .map_err(backend)?;
        let artifact = join::GBoundArtifact {
            public_values: proved
                .public_values
                .try_into()
                .map_err(|_| backend("native public width".into()))?,
            proof: proved.proof,
        };
        self.verify(&artifact)?;
        Ok((artifact, proved.report))
    }
}
