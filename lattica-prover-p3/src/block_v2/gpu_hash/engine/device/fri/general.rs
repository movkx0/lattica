//! Quadratic/cubic FRI folds of arity 2..16 and bounded final coefficient egress.
use super::*;

#[cfg(test)]
mod tests;

pub(crate) const KERNEL_SRC: &str = r#"
inline void device_fri_mul(__private ulong *a,__private ulong *b,__private ulong *out,uint degree) {
    if(degree==3) { opening_cubic_mul(a,b,out);return; }
    out[0]=gl_add(gl_mul(a[0],b[0]),gl_mul(7UL,gl_mul(a[1],b[1])));
    out[1]=gl_add(gl_mul(a[0],b[1]),gl_mul(a[1],b[0]));out[2]=0;
}
__kernel void device_fri_fold_general(__global const ulong *input,__global ulong *output,
    uint log_rows,uint log_arity,uint degree,ulong inverse_root,ulong b0,ulong b1,ulong b2) {
    uint row=get_global_id(0),arity=1U<<log_arity;
    if(row>=(1U<<(log_rows-log_arity)))return;
    ulong values[16][3],beta[3]={b0,b1,b2},root=inverse_root;
    for(uint j=0;j<arity;++j)for(uint c=0;c<3;++c)
        values[j][c]=c<degree?input[((ulong)row*arity+j)*degree+c]:0;
    for(uint pass=0;pass<log_arity;++pass) {
        uint count=arity>>(pass+1),bits=log_rows-pass-1;
        for(uint j=0;j<count;++j) {
            uint index=row*count+j,reverse=0;
            for(uint k=0;k<bits;++k){reverse=(reverse<<1)|(index&1);index>>=1;}
            ulong inverse=gl_pow(root,(ulong)reverse),delta[3],product[3];
            for(uint c=0;c<3;++c)delta[c]=gl_sub(values[2*j][c],values[2*j+1][c]);
            device_fri_mul(delta,beta,product,degree);
            for(uint c=0;c<degree;++c)
                values[j][c]=gl_canon(gl_mul(gl_add(gl_add(values[2*j][c],values[2*j+1][c]),
                    gl_mul(product[c],inverse)),9223372034707292161UL));
        }
        ulong square[3];device_fri_mul(beta,beta,square,degree);
        for(uint c=0;c<3;++c)beta[c]=square[c];root=gl_mul(root,root);
    }
    for(uint c=0;c<degree;++c)output[(ulong)row*degree+c]=values[0][c];
}
__kernel void device_fri_mix_general(__global const ulong *folded,__global const ulong *input,
    __global ulong *output,uint rows,uint log_arity,uint degree,ulong b0,ulong b1,ulong b2) {
    uint row=get_global_id(0);if(row>=rows)return;
    ulong beta[3]={b0,b1,b2},value[3]={0,0,0},product[3];
    for(uint k=0;k<log_arity;++k){device_fri_mul(beta,beta,product,degree);for(uint c=0;c<3;++c)beta[c]=product[c];}
    for(uint c=0;c<degree;++c)value[c]=input[(ulong)row*degree+c];
    device_fri_mul(beta,value,product,degree);
    for(uint c=0;c<degree;++c)output[(ulong)row*degree+c]=gl_canon(gl_add(folded[(ulong)row*degree+c],product[c]));
}
"#;

pub(super) fn vector(spec: MatrixSpec) -> Result<(), String> {
    crate::gpu_fri::vector(spec)
}

fn challenge(spec: MatrixSpec, log_arity: usize, beta: &[u64]) -> Result<[u64; 3], String> {
    vector(spec)?;
    if !(1..=4).contains(&log_arity)
        || beta.len() != spec.extension.degree()
        || beta.iter().any(|v| *v >= GOLDILOCKS_MODULUS)
    {
        return Err("FRI arity/challenge encoding does not match the extension".into());
    }
    let mut words = [0; 3];
    words[..beta.len()].copy_from_slice(beta);
    Ok(words)
}

impl DeviceSession {
    pub(crate) fn final_polynomial_with_len(
        &self,
        input: &DeviceMatrix,
        log_blowup: usize,
        log_final_len: usize,
        host_allowance: usize,
    ) -> Result<Vec<u64>, String> {
        self.check_owner(input)?;
        let shape =
            super::storage::FinalShape::new(input.spec, log_blowup, log_final_len, host_allowance)?;
        let spec = shape.output;
        if log_final_len == 0 {
            return self.gather_rows_stage(
                input,
                &[0],
                host_allowance,
                crate::proving::Stage::FinalPolynomial,
            );
        }
        #[cfg(not(feature = "gpu"))]
        {
            Err("final polynomial interpolation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let live = engine.accounting.lock().unwrap().live;
            shape.plan(live, engine.limits.managed_bytes, engine.max_alloc)?;
            let output = self.allocate(engine, spec)?;
            let scratch = self.allocate(engine, spec)?;
            let alloc = |words| {
                allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    words,
                    compute::flags::MEM_READ_WRITE,
                )
            };
            let roots = alloc(log_final_len)?;
            let parameters = alloc(2)?;
            let constants: Vec<_> = (1..=log_final_len as u32)
                .map(super::super::super::fri_fold::inverse_root)
                .collect();
            let fence = engine.fence();
            roots
                .buffer
                .write(&constants)
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: the first 2^log_final_len bit-reversed evaluations are
            // precisely the smaller subgroup required by the upstream IDFT.
            // Both destination matrices have that exact prefix geometry.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_transform_order")
                    .arg(&input.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(spec.extension.degree() as u32)
                    .arg(spec.rows() as u32)
                    .arg(spec.log_rows)
                    .global_work_size(spec.words)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session.record_event(
                engine,
                crate::proving::Stage::FinalPolynomial,
                "device_final_polynomial_order",
                &event,
            )?;
            let mut event = compute::Event::empty();
            // SAFETY: two parameters, one work item; inversion stays on GPU.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_transform_parameters")
                    .arg(&parameters.buffer)
                    .arg(spec.rows() as u32)
                    .arg(1u64)
                    .arg(1u64)
                    .global_work_size(1usize)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session.record_event(
                engine,
                crate::proving::Stage::FinalPolynomial,
                "device_final_polynomial_parameters",
                &event,
            )?;
            self.observe_engine(engine, |engine| {
                engine.lde_ntt(
                    &output.storage.buffer,
                    &scratch.storage.buffer,
                    &roots.buffer,
                    true,
                    spec.rows(),
                    spec.extension.degree(),
                    1,
                    1,
                    false,
                    false,
                    false,
                    None,
                )
            })?;
            let mut event = compute::Event::empty();
            // SAFETY: equal input/output coefficient extents; canonical
            // normalization is the only remaining field operation.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_transform_scale")
                    .arg(&scratch.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(&parameters.buffer)
                    .arg(spec.extension.degree() as u32)
                    .arg(spec.rows() as u32)
                    .arg(spec.rows() as u32)
                    .global_work_size(spec.words)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session.record_event(
                engine,
                crate::proving::Stage::FinalPolynomial,
                "device_final_polynomial_normalize",
                &event,
            )?;
            let mut values = vec![0; spec.words];
            output
                .storage
                .buffer
                .read(&mut values)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += constants.len() as u64 * 8;
            engine.stats.downloaded_bytes += spec.bytes() as u64;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += constants.len() as u64 * 8;
            stats.downloaded_bytes += spec.bytes() as u64;
            stats.gathered_value_bytes += spec.bytes() as u64;
            if values.iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
                return Err("final polynomial returned a noncanonical field value".into());
            }
            Ok(values)
        })
    }

    pub(crate) fn fri_leaves_with_arity(
        &self,
        input: &DeviceMatrix,
        log_arity: usize,
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(input)?;
        let spec = super::storage::leaves(input.spec, log_arity)?;
        Ok(DeviceMatrix {
            storage: input.storage.clone(),
            private_random: input.private_random.clone(),
            session: self.session.clone(),
            spec,
        })
    }

    pub(crate) fn fold_fri(
        &self,
        input: &DeviceMatrix,
        log_arity: usize,
        beta: &[u64],
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(input)?;
        let beta = challenge(input.spec, log_arity, beta)?;
        if log_arity > input.spec.log_rows as usize {
            return Err("FRI fold arity exceeds its input".into());
        }
        if input.spec.extension == Extension::Cubic && log_arity == 1 {
            return self.fold_cubic(input, beta);
        }
        let spec = super::storage::fold_output(input.spec, log_arity)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = spec;
            Err("general FRI folding is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            super::storage::vector_output(
                spec,
                engine.accounting.lock().unwrap().live,
                engine.limits.managed_bytes,
                engine.max_alloc,
            )?;
            let output = self.allocate(engine, spec)?;
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: degree is 2/3, arity <=16, and every row is a disjoint
            // contiguous group of the validated input. The output is fresh.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_fri_fold_general")
                    .arg(&input.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(input.spec.log_rows)
                    .arg(log_arity as u32)
                    .arg(input.spec.extension.degree() as u32)
                    .arg(super::super::super::fri_fold::inverse_root(
                        input.spec.log_rows,
                    ))
                    .arg(beta[0])
                    .arg(beta[1])
                    .arg(beta[2])
                    .global_work_size(spec.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self.session.record_event(
                engine,
                crate::proving::Stage::FriFold,
                "device_fri_fold_general",
                &event,
            )?;
            fence.finish()?;
            let mut stats = self.session.stats.lock().unwrap();
            stats.general_fri_folds += 1;
            stats.fold_device_ns += ns;
            Ok(output)
        })
    }

    pub(crate) fn mix_fri_with_arity(
        &self,
        folded: &DeviceMatrix,
        input: &DeviceMatrix,
        log_arity: usize,
        beta: &[u64],
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(folded)?;
        self.check_owner(input)?;
        let beta = challenge(folded.spec, log_arity, beta)?;
        if folded.spec != input.spec {
            return Err("FRI mixing requires matching vector domains".into());
        }
        if folded.spec.extension == Extension::Cubic && log_arity == 1 {
            return self.mix_fri(folded, input, beta);
        }
        #[cfg(not(feature = "gpu"))]
        {
            Err("general FRI mixing is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            super::storage::vector_output(
                folded.spec,
                engine.accounting.lock().unwrap().live,
                engine.limits.managed_bytes,
                engine.max_alloc,
            )?;
            let output = self.allocate(engine, folded.spec)?;
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: equal canonical vector shapes; arity and extension were
            // checked before allocation. No committed input is modified.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_fri_mix_general")
                    .arg(&folded.storage.buffer)
                    .arg(&input.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(folded.spec.rows() as u32)
                    .arg(log_arity as u32)
                    .arg(folded.spec.extension.degree() as u32)
                    .arg(beta[0])
                    .arg(beta[1])
                    .arg(beta[2])
                    .global_work_size(folded.spec.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self.session.record_event(
                engine,
                crate::proving::Stage::FriFold,
                "device_fri_mix_general",
                &event,
            )?;
            fence.finish()?;
            let mut stats = self.session.stats.lock().unwrap();
            stats.fri_mixes += 1;
            stats.fri_mix_device_ns += ns;
            Ok(output)
        })
    }
}
