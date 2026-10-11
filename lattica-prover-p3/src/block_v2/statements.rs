//! Proving-only statement and public compiler arithmetic. Host acceptance and independent verification
//! continue to call the CPU commitment helpers explicitly.
use super::{
    commitment::{self, Context, Digest, Entry, Kind, NodeSummary},
    machine::programs::PUBLIC_VALUES,
    profile,
    recursive::{self, Error},
};
use crate::proving::{Backend, Report, Request, Run, Stage};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks as Val;

enum HashBackend {
    Cpu,
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    Device(super::gpu_hash::device::DeviceSession),
}

pub(crate) struct Derivation<'a> {
    backend: HashBackend,
    run: &'a Run,
    stage: Stage,
}

/// One recursive job owns all five component slots, even when two components
/// touch the same arithmetic stage. Verification and byte encoding stay outside
/// the proving arithmetic inventory.
pub(crate) fn request<T>(
    entry: &'static str,
    body: impl FnOnce(&Run) -> Result<T, Error>,
) -> Result<T, Error> {
    use crate::proving::CoverageScope as Scope;
    let run = Run::request(
        entry,
        Request::from_env()?,
        profile::recursive_request_capabilities(),
        &[
            ("statement", Scope::Statement),
            ("registry", Scope::RegistryCompilation),
            ("statement_check", Scope::Statement),
            ("preprocessing", Scope::Preprocessing),
            ("proof", Scope::RegisteredProof),
        ],
    )?;
    let result = body(&run);
    run.finish(result.is_ok())?;
    result
}

pub(crate) fn derive_in<T>(
    request: &Run,
    id: &'static str,
    body: impl FnOnce(&mut Derivation<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    let run = request.child(
        id,
        "block_v2_statement",
        profile::public_scope_capabilities(Stage::PublicValues),
    )?;
    operate_in(run, Stage::PublicValues, body)?.0
}

pub(crate) fn compile_in<T>(
    request: &Run,
    height: usize,
    key_count: usize,
    body: impl FnOnce(&super::machine::programs::RegistryPrefix) -> Result<T, Error>,
) -> Result<T, Error> {
    let run = request.child(
        "registry",
        "block_v2_registry_compilation",
        profile::public_scope_capabilities(Stage::Preprocessing),
    )?;
    operate_in(run, Stage::Preprocessing, |hash| {
        let prefix = super::machine::programs::RegistryPrefix::with_backend(
            height,
            key_count,
            &mut |d, f| hash.hash(d, f),
            hash.compiler_constants(),
        )?;
        body(&prefix)
    })?
    .0
}

pub(crate) fn derive<T>(
    body: impl FnOnce(&mut Derivation<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    derive_reported(Request::from_env()?, body)?.0
}

fn derive_reported<T>(
    request: Request,
    body: impl FnOnce(&mut Derivation<'_>) -> Result<T, Error>,
) -> Result<(Result<T, Error>, Report), Error> {
    operate_reported(request, "block_v2_statement", Stage::PublicValues, body)
}

/// Compile with an explicit backend for the AIR fingerprint and public constants.
/// The prefix is not cached, serialized, or accepted as registry approval.
pub(crate) fn compile<T>(
    height: usize,
    key_count: usize,
    body: impl FnOnce(&super::machine::programs::RegistryPrefix) -> Result<T, Error>,
) -> Result<T, Error> {
    compile_reported(Request::from_env()?, height, key_count, body)?.0
}

fn compile_reported<T>(
    request: Request,
    height: usize,
    key_count: usize,
    body: impl FnOnce(&super::machine::programs::RegistryPrefix) -> Result<T, Error>,
) -> Result<(Result<T, Error>, Report), Error> {
    operate_reported(
        request,
        "block_v2_registry_compilation",
        Stage::Preprocessing,
        |hash| {
            let prefix = super::machine::programs::RegistryPrefix::with_backend(
                height,
                key_count,
                &mut |d, f| hash.hash(d, f),
                hash.compiler_constants(),
            )?;
            body(&prefix)
        },
    )
}

fn operate_reported<T>(
    request: Request,
    entry_point: &'static str,
    stage: Stage,
    body: impl FnOnce(&mut Derivation<'_>) -> Result<T, Error>,
) -> Result<(Result<T, Error>, Report), Error> {
    // The caller's whole request is admitted separately. This operation only
    // promises the public arithmetic identified by its explicit scope.
    let run = Run::new(
        entry_point,
        request,
        profile::public_scope_capabilities(stage),
    )?;
    operate_in(run, stage, body)
}

fn operate_in<T>(
    run: Run,
    stage: Stage,
    body: impl FnOnce(&mut Derivation<'_>) -> Result<T, Error>,
) -> Result<(Result<T, Error>, Report), Error> {
    let result = (|| {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        super::machine::gpu_backend::check_selected()?;
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        let backend = if super::quotient_pcs::gpu_witness_enabled() {
            HashBackend::Device(super::gpu_hash::device::DeviceSession::new()?)
        } else {
            HashBackend::Cpu
        };
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let backend = HashBackend::Cpu;
        // One immutable selection and scoped public session per derivation. No
        // device handles escape into a job packet or a subsequent private proof.
        body(&mut Derivation {
            backend,
            run: &run,
            stage,
        })
    })();
    let report = run.finish(result.is_ok())?;
    Ok((result, report))
}

impl Derivation<'_> {
    fn compiler_constants(&self) -> super::machine::compiler_constants::Constants<'_> {
        use super::machine::compiler_constants::Constants;
        match &self.backend {
            HashBackend::Cpu => Constants::cpu_reported(self.run),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            HashBackend::Device(session) => Constants::device(session, self.run),
        }
    }

    fn hash(&self, domain: u64, fields: &[u64]) -> Result<Digest, Error> {
        match &self.backend {
            HashBackend::Cpu => Ok(self.run.measure(self.stage, Backend::Cpu, || {
                commitment::hash_fields(domain, fields)
            })??),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            HashBackend::Device(session) => {
                Ok(session.hash_public_fields_reported(domain, fields, self.run, self.stage)?)
            }
        }
    }

    pub(crate) fn leaf(
        &mut self,
        context: Context,
        kind: Kind,
        public: &[Val],
    ) -> Result<NodeSummary, Error> {
        // Canonical extraction is encoding, not a field reduction or hash.
        let fields: Vec<_> = public.iter().map(PrimeField64::as_canonical_u64).collect();
        let statement_digest =
            commitment::statement_digest_with_hash(kind as u8, &fields, &mut |domain, fields| {
                self.hash(domain, fields)
            })?;
        commitment::leaf_with_hash(
            context,
            Entry {
                kind,
                statement_digest,
            },
            &mut |d, f| self.hash(d, f),
        )
    }

    pub(crate) fn empty(&mut self, context: Context, level: u8) -> Result<NodeSummary, Error> {
        commitment::empty_subtree_with_hash(context, level, &mut |d, f| self.hash(d, f))
    }

    pub(crate) fn merge(
        &mut self,
        left: NodeSummary,
        right: NodeSummary,
    ) -> Result<NodeSummary, Error> {
        // Zero-count child validation also uses this backend.
        commitment::merge_nodes_with_hash(left, right, &mut |d, f| self.hash(d, f))
    }

    pub(crate) fn summary(
        &mut self,
        public: &[Val; PUBLIC_VALUES],
        modes: u64,
    ) -> Result<NodeSummary, Error> {
        let node = match &self.backend {
            HashBackend::Cpu => self.run.measure(self.stage, Backend::Cpu, || {
                recursive::decode_summary(public, modes)
            })??,
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            HashBackend::Device(session) => {
                let words = public.map(|value| value.as_canonical_u64());
                session.validate_public_summary_reported(&words, modes, self.run, self.stage)?;
                recursive::summary_from_validated_words(&words)
            }
        };
        // Structural checks already ran on the selected backend. Empty roots
        // additionally require protocol hashing; nonempty roots are opaque here.
        if node.count == 0 && node.root != self.empty(node.context, node.level)?.root {
            return Err(commitment::CommitmentError::InvalidEmptyRoot.into());
        }
        Ok(node)
    }

    pub(crate) fn finalize(
        &mut self,
        public: &[Val; PUBLIC_VALUES],
        modes: u64,
        finalizer_mode: u64,
    ) -> Result<NodeSummary, Error> {
        let mut node = self.summary(public, modes)?;
        if node.level >= commitment::DEPTH
            || public[super::machine::programs::MODE].as_canonical_u64() == finalizer_mode
        {
            return Err("finalizer child must be an unfinished subtree".into());
        }
        while node.level < commitment::DEPTH {
            let empty = self.empty(node.context, node.level)?;
            node = self.merge(node, empty)?;
        }
        Ok(node)
    }
}

#[cfg(test)]
mod compiler_tests;
#[cfg(test)]
mod folding_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod symbolic_tests;
#[cfg(test)]
mod tests;
