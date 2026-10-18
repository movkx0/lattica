//! Reuse only an authenticated immutable program and its input layout. Every
//! call binds fresh completed child proofs; witnesses and randomness are absent
//! from cache entries. This is the legacy counterpart of typed binding_cache.
use super::*;
use crate::proving::{CachedScope, Run};
use programs::{paired_inputs, recursive_inputs};

const RECEIPT_BYTES: usize = 64 << 10;

pub(super) fn enabled() -> Result<bool, Error> {
    #[cfg(feature = "gpu")]
    if crate::block_v2::quotient_pcs::gpu_witness_enabled() {
        return Ok(crate::block_v2::gpu_hash::engine::public_compilation_cache_enabled()?);
    }
    Ok(false)
}

pub(super) struct Binding {
    height: usize,
    profile: [u8; 32],
    caps: Caps,
    mode: u64,
    values: usize,
    layout: Layout,
    compilation: CachedScope,
}

enum Layout {
    Pair(paired_inputs::Shape),
    Merge(recursive_inputs::Shape),
}

#[derive(Clone, Copy)]
pub(super) enum Inputs<'a> {
    Pair([&'a WalletProof; 2]),
    Merge([&'a NodeProof; 2]),
}

impl Inputs<'_> {
    fn mode(self) -> u64 {
        match self {
            Self::Pair(_) => programs::WRAPPER,
            Self::Merge(_) => programs::MERGE,
        }
    }

    fn compile(
        self,
        registry: &Registry,
        prefix: &programs::RegistryPrefix<'_>,
        limit: usize,
    ) -> Result<(Compiled, Layout), Error> {
        match self {
            Self::Pair(wallets) => {
                let shape = paired_inputs::Shape::legacy_pair(prefix, registry.height)?;
                let compiled = programs::wrapper_pair_with_registry(
                    registry.height,
                    &registry.caps,
                    wallets.map(|w| w.public.as_slice()),
                    wallets.map(|w| &w.proof),
                    Some(prefix),
                )?;
                paired_inputs::check_witness(
                    &shape,
                    &registry.caps,
                    wallets.map(|w| (w.public.as_slice(), &w.proof)),
                    &compiled.witness,
                    limit,
                )?;
                Ok((compiled, Layout::Pair(shape)))
            }
            Self::Merge(children) => {
                let shape = recursive_inputs::Shape::from_prefix(prefix, registry.height, 3)?;
                let compiled = programs::merge_with_registry(
                    registry.height,
                    &registry.caps,
                    children.map(|n| &n.public),
                    children.map(|n| &n.proof),
                    Some(prefix),
                )?;
                recursive_inputs::check_witness(
                    &shape,
                    &registry.caps,
                    &children.map(|n| (&n.public, &n.proof)),
                    &compiled.witness,
                    limit,
                )?;
                Ok((compiled, Layout::Merge(shape)))
            }
        }
    }

    fn bind(self, binding: &Binding, registry: &Registry, limit: usize) -> Result<Vec<Val>, Error> {
        Ok(match (self, &binding.layout) {
            (Self::Pair(wallets), Layout::Pair(shape)) => paired_inputs::bind(
                shape,
                &registry.caps,
                wallets.map(|w| (w.public.as_slice(), &w.proof)),
                binding.values,
                limit,
            )?,
            (Self::Merge(children), Layout::Merge(shape)) => recursive_inputs::bind(
                shape,
                &registry.caps,
                &children.map(|n| (&n.public, &n.proof)),
                binding.values,
                limit,
            )?,
            _ => return Err("legacy compilation cache layout mismatch".into()),
        })
    }
}

impl ProverSession {
    pub(super) fn prove_bound(
        &mut self,
        run: &Run,
        inputs: Inputs<'_>,
        public: [Val; PUBLIC_VALUES],
    ) -> Result<NodeProof, Error> {
        let mode = inputs.mode();
        self.check_public(run, mode, &public)?;
        let mut limit = usize::try_from(storage::active_memory_bytes(self.worker_memory_bytes)?)?
            .min(recursive_inputs::MAX_INPUT_BYTES);
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if crate::block_v2::quotient_pcs::gpu_witness_enabled() {
            if let Some(bounds) =
                crate::block_v2::machine::gpu_backend::resources::construction_bounds()?
            {
                limit = limit.min(usize::try_from(
                    bounds
                        .input_values
                        .checked_sub(PUBLIC_VALUES as u64)
                        .and_then(|n| n.checked_mul(8))
                        .ok_or("legacy input allowance overflow")?,
                )?);
            }
        }
        if let Some(entry) = self.cached.as_ref().filter(|entry| entry.mode == mode) {
            if let Some(binding) = &entry.binding {
                if binding.height != self.registry.height
                    || binding.profile != self.expected_profile
                    || binding.caps != self.registry.caps
                    || binding.mode != mode
                    || binding.values != entry.registered.air().program().witness_values()
                {
                    return Err("legacy compilation cache identity mismatch".into());
                }
                let witness = tracing::info_span!(target: "lattica_block_v2_perf", "cached recursive input binding")
                    .in_scope(|| inputs.bind(binding, &self.registry, limit))?;
                run.reuse_registry_compilation(&binding.compilation)?;
                entry.registered.reuse_preprocessing(run)?;
                self.stats.hits = self
                    .stats
                    .hits
                    .checked_add(1)
                    .ok_or("legacy cache hit overflow")?;
                println!("proof_start mode={mode} setup_ms=0 preprocessing_cache_hit=true compilation_cache_hit=true");
                return self.prove_cached(run, mode, public, &witness);
            }
        }
        let ((compiled, layout), report) =
            statements::compile_in_reported(run, self.registry.height, 3, |prefix| {
                inputs.compile(&self.registry, prefix, limit)
            })?;
        if compiled.program.witness_values() != compiled.witness.len() {
            return Err("legacy compilation input count mismatch".into());
        }
        let compilation = CachedScope::registry_compilation(&report)?;
        if compilation.retained_host_bytes()? > RECEIPT_BYTES {
            return Err("legacy compilation receipt allowance".into());
        }
        let binding = Binding {
            height: self.registry.height,
            profile: self.expected_profile,
            caps: self.registry.caps.clone(),
            mode,
            values: compiled.witness.len(),
            layout,
            compilation,
        };
        let proof = self.prove_compiled(run, mode, compiled, public)?;
        self.cached
            .as_mut()
            .ok_or("missing authenticated legacy program")?
            .binding = Some(binding);
        Ok(proof)
    }
}
