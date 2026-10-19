//! Input layouts live and die with their immutable registered programs.
//! Only a cold compilation, checked against its fresh witness and registry cap,
//! can install a layout. No external request can supply a cache identity.
use super::*;
use crate::proving::{CachedScope, Run};
use programs::paired_inputs;
use programs::recursive_inputs::{self, Shape};

pub(super) struct Entry {
    pub(super) mode: u64,
    pub(super) registered: backend::Prepared,
    pub(super) binding: Option<Binding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    height: usize,
    keys: usize,
    mode: u64,
    profile: [u8; 32],
}

pub(super) struct Binding {
    key: Key,
    layout: Layout,
    values: usize,
    compilation: CachedScope,
}
enum Layout {
    Recursive(Shape),
    Pair(paired_inputs::Shape),
}

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Merge,
    Finalize,
}

type Child<'a> = (
    &'a [Val; PUBLIC_VALUES],
    &'a p3_batch_stark::BatchProof<profile::Config>,
);

impl Operation {
    fn mode<const N: usize>(self) -> Result<u64, Error> {
        match (self, N) {
            (Self::Merge, 5 | 6 | 12) => Ok(programs::MERGE),
            (Self::Finalize, 6) => Ok(typed_finalizer::FINALIZE),
            (Self::Finalize, 12) => Ok(typed_pairs::FINALIZE),
            _ => Err("recursive binding operation/registry".into()),
        }
    }

    fn children(self) -> usize {
        match self {
            Self::Merge => 2,
            Self::Finalize => 1,
        }
    }

    fn compile<const N: usize>(
        self,
        registry: &Registry<N>,
        children: &[Child<'_>],
        prefix: &programs::RegistryPrefix<'_>,
    ) -> Result<Compiled, Error> {
        Ok(match self {
            Self::Merge => programs::merge_with_registry(
                registry.height,
                &registry.caps,
                [children[0].0, children[1].0],
                [children[0].1, children[1].1],
                Some(prefix),
            )?,
            Self::Finalize if N == 12 => typed_pairs::finalize_with_registry(
                registry.height,
                registry.caps.as_slice().try_into()?,
                children[0].0,
                children[0].1,
                Some(prefix),
            )?,
            Self::Finalize => typed_finalizer::compile_with_registry(
                registry.height,
                registry.caps.as_slice().try_into()?,
                children[0].0,
                children[0].1,
                Some(prefix),
            )?,
        })
    }
}

// The input reservation includes public values. Reuse the assigned compiler
// ceiling and the active worker allowance before allocating a fresh vector.
fn input_limit(active_bytes: u64, assigned_values: Option<u64>) -> Result<usize, Error> {
    let mut bytes = active_bytes.min(recursive_inputs::MAX_INPUT_BYTES as u64);
    if let Some(values) = assigned_values {
        bytes = bytes.min(
            values
                .checked_sub(PUBLIC_VALUES as u64)
                .and_then(|v| v.checked_mul(core::mem::size_of::<Val>() as u64))
                .ok_or("recursive input reservation overflow")?,
        );
    }
    Ok(usize::try_from(bytes)?)
}

impl Binding {
    fn check_identity(&self, key: Key, values: usize) -> Result<(), Error> {
        if self.key != key || self.values != values {
            return Err("cached recursive input identity changed".into());
        }
        Ok(())
    }
}

impl<const N: usize> Session<N> {
    pub(super) fn prove_recursive(
        &mut self,
        run: &Run,
        operation: Operation,
        children: &[Child<'_>],
        public: [Val; PUBLIC_VALUES],
    ) -> Result<NodeProof, Error> {
        let mode = operation.mode::<N>()?;
        if children.len() != operation.children() {
            return Err("recursive binding child count".into());
        }
        let key = Key {
            height: self.registry.height,
            keys: N,
            mode,
            profile: self.expected_profile,
        };
        let active =
            storage::active_memory_bytes(self.worker_memory_bytes, self.cache_reserve_bytes)?;
        let assigned_values = self.backend.input_values();
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let assigned_values =
            if assigned_values.is_none() && super::super::quotient_pcs::gpu_witness_enabled() {
                super::super::machine::gpu_backend::resources::construction_bounds()?
                    .map(|b| b.input_values)
            } else {
                assigned_values
            };
        let limit = input_limit(active, assigned_values)?;
        let index = self.cached.iter().position(|entry| entry.mode == mode);
        if let Some(index) = index {
            let entry = &self.cached[index];
            if let Some(binding) = &entry.binding {
                binding.check_identity(key, entry.registered.air().program().witness_values())?;
                let Layout::Recursive(shape) = &binding.layout else {
                    return Err("recursive binding layout kind".into());
                };
                self.check_public(run, mode, &public)?;
                let witness = recursive_inputs::bind(
                    shape,
                    &self.registry.caps,
                    children,
                    binding.values,
                    limit,
                )?;
                run.reuse_registry_compilation(&binding.compilation)?;
                entry.registered.reuse_preprocessing(run)?;
                self.touch_cached(index)?;
                return self.prove_cached(run, public, &witness);
            }
        }
        let ((compiled, shape), report) =
            self.compile_in_reported(run, self.registry.height, N, |prefix| {
                let shape = Shape::from_prefix(prefix, self.registry.height, N)?;
                let compiled = operation.compile(&self.registry, children, prefix)?;
                recursive_inputs::check_witness(
                    &shape,
                    &self.registry.caps,
                    children,
                    &compiled.witness,
                    limit,
                )?;
                if compiled.program.witness_values() != compiled.witness.len() {
                    return Err("recursive compiler input count".into());
                }
                Ok((compiled, shape))
            })?;
        let compilation = CachedScope::registry_compilation(&report)?;
        if compilation.retained_host_bytes()? > storage::COMPILATION_RECEIPT_BYTES {
            return Err("cached compilation receipt storage".into());
        }
        let binding = Binding {
            key,
            layout: Layout::Recursive(shape),
            values: compiled.witness.len(),
            compilation,
        };
        // Installation is deferred until preprocessing authenticates the program
        // against the immutable registry. A failed cold setup retains no layout.
        self.prove_compiled(run, mode, compiled, public, Some(binding))
    }

    pub(super) fn prove_pair_bound(
        &mut self,
        run: &crate::proving::Run,
        mode: u64,
        wallets: [&WalletProof; 2],
        public: [Val; PUBLIC_VALUES],
    ) -> Result<NodeProof, Error> {
        if N != typed_pairs::KEY_COUNT {
            return Err("paired binding requires twelve keys".into());
        }
        typed_pairs::leaf_modes(mode)?;
        let key = Key {
            height: self.registry.height,
            keys: N,
            mode,
            profile: self.expected_profile,
        };
        let active =
            storage::active_memory_bytes(self.worker_memory_bytes, self.cache_reserve_bytes)?;
        let assigned_values = self.backend.input_values();
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let assigned_values =
            if assigned_values.is_none() && super::super::quotient_pcs::gpu_witness_enabled() {
                super::super::machine::gpu_backend::resources::construction_bounds()?
                    .map(|b| b.input_values)
            } else {
                assigned_values
            };
        let limit = input_limit(active, assigned_values)?;
        let caps: &typed_pairs::Caps = self.registry.caps.as_slice().try_into()?;
        let inputs = wallets.map(|wallet| (wallet.public.as_slice(), &wallet.proof));
        let index = self.cached.iter().position(|entry| entry.mode == mode);
        if let Some(index) = index {
            let entry = &self.cached[index];
            if let Some(binding) = &entry.binding {
                binding.check_identity(key, entry.registered.air().program().witness_values())?;
                let Layout::Pair(shape) = &binding.layout else {
                    return Err("paired binding layout kind".into());
                };
                self.check_public(run, mode, &public)?;
                let witness = paired_inputs::bind(shape, caps, inputs, binding.values, limit)?;
                run.reuse_registry_compilation(&binding.compilation)?;
                entry.registered.reuse_preprocessing(run)?;
                self.touch_cached(index)?;
                return self.prove_cached(run, public, &witness);
            }
        }
        let ((compiled, shape), report) =
            self.compile_in_reported(run, self.registry.height, N, |prefix| {
                let shape = paired_inputs::Shape::from_prefix(prefix, self.registry.height, mode)?;
                let compiled = typed_pairs::wrapper_pair_with_registry(
                    self.registry.height,
                    caps,
                    mode,
                    wallets.map(|wallet| wallet.public.as_slice()),
                    wallets.map(|wallet| &wallet.proof),
                    Some(prefix),
                )?;
                paired_inputs::check_witness(&shape, caps, inputs, &compiled.witness, limit)?;
                if compiled.program.witness_values() != compiled.witness.len() {
                    return Err("paired compiler input count".into());
                }
                Ok((compiled, shape))
            })?;
        let compilation = CachedScope::registry_compilation(&report)?;
        if compilation.retained_host_bytes()? > storage::COMPILATION_RECEIPT_BYTES {
            return Err("cached paired compilation receipt storage".into());
        }
        let binding = Binding {
            key,
            layout: Layout::Pair(shape),
            values: compiled.witness.len(),
            compilation,
        };
        self.prove_compiled(run, mode, compiled, public, Some(binding))
    }
}

#[cfg(test)]
mod tests;
