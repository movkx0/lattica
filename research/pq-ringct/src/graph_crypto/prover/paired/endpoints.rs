//! Endpoints are prepared while the original source Session is live. Once
//! closure retires that Session, the immutable plan supplies only fixed data.
use super::*;
use crate::execution::{retained_resources::Bytes, workflow_resources::SourceEndpointAccess};
use crate::graph_crypto::RequestDescriptor;
use std::{cell::OnceCell, time::Instant};
use core::mem::size_of;

// The immutable typed request binding is deliberately outside OnceCell. This
// keeps the plan covariant while the fixed endpoint payload remains one-shot.
// The store is private to this family and remains owned by the retained plan.
pub(super) struct SourceEndpointStore<'request> {
    request: &'request Request,
    pub(super) prepared: OnceCell<PreparedSourceEndpoints>,
}

// No borrowed source occurs inside the interior-mutable payload. Runtime
// outputs use the store's original typed binding after all source checks.
pub(super) struct PreparedSourceEndpoints {
    pub(super) context: GraphContext,
    pub(super) endpoints: crate::component_tree::EndpointContext,
    pub(super) elapsed_ns: u128,
}

// The store constructor's returned value and empty-cell temporary coexist
// with plan assembly. Charge them explicitly in planning_frames as well as
// the actual store layout already present in size_of::<RequestPlan>().
pub(super) const SOURCE_STORE_CONSTRUCTION_FRAME_BYTES: usize = 8 * (
    size_of::<SourceEndpointStore<'static>>()
    + size_of::<OnceCell<PreparedSourceEndpoints>>() + size_of::<&Request>()
);

// Both EndpointAttach and source preparation preclaim these fixed value,
// result, clone-overlap and borrowed-projection frames. No query runs to size
// itself; constant overflow is rejected during compilation.
pub(super) const OUTPUT_COPY_FRAME_BYTES: usize = 8 * (
    size_of::<PairedEndpoints<'static>>() + size_of::<Result<PairedEndpoints<'static>>>()
    + size_of::<&SourceEndpointStore<'static>>() + size_of::<&PreparedSourceEndpoints>()
    + size_of::<Option<&PreparedSourceEndpoints>>() + size_of::<Result<&PreparedSourceEndpoints>>()
    + size_of::<GraphContext>() + size_of::<crate::component_tree::EndpointContext>()
    + size_of::<[&Request; 2]>() + size_of::<[&GraphContext; 2]>()
    + size_of::<Result<()>>() + size_of::<PairedFailure>() + size_of::<u128>()
);

impl<'request> SourceEndpointStore<'request> {
    pub(super) fn new(request: &'request Request) -> Self {
        Self { request, prepared: OnceCell::new() }
    }

    pub(super) fn check_source(&self, request: &Request, context: &GraphContext) -> Result<()> {
        let stored = self.prepared.get().ok_or(PairedFailure::Authority)?;
        if !core::ptr::eq(self.request, request) || &stored.context != context
            || stored.endpoints.context != context.context || stored.endpoints.statement != context.statement {
            return Err(PairedFailure::Authority);
        }
        Ok(())
    }

    fn copy_output(&self, request: &Request, context: &GraphContext) -> Result<PairedEndpoints<'request>> {
        self.check_source(request, context)?;
        let stored = self.prepared.get().ok_or(PairedFailure::Authority)?;
        Ok(PairedEndpoints::prepared(self.request,
            stored.context.clone(), stored.endpoints.clone(), stored.elapsed_ns))
    }
}

const DEVICE_BYTES: u64 = 8 << 30;
const MAX_HOST_BYTES: u64 = 24 << 30;
const MAX_FIELD_WORDS: usize = 1 << 20;

fn backend(host: usize) -> Result<Bytes> {
    let host = u64::try_from(host).map_err(|_| PairedFailure::Overflow)?;
    if host == 0 || host > MAX_HOST_BYTES { return Err(PairedFailure::Resource); }
    Ok(Bytes { host, device: DEVICE_BYTES })
}

// Mirrors native_gpu::{operations_crypto::host_bytes, operations_hash::
// field_chunk_staging_bytes}. These are source bounds, never observed peaks.
fn raw_crypto_host(input: usize, output: usize) -> Result<usize> {
    add(add(source::mul(add(output, 1)?, 16)?, input)?, 80 << 10)
}
fn field_host(words: usize) -> Result<usize> {
    if words > MAX_FIELD_WORDS { return Err(PairedFailure::Resource); }
    source::mul(add(words.max(1), 9)?, 8)
}

pub(super) fn operation_report_requirements() -> Result<Requirements> {
    let report = lattica_prover_p3::proving::operation_storage::RawPreparationReportStorage::new()
        .map_err(|_| PairedFailure::Resource)?;
    combine(&[
        requirement(Category::Report, report.required_host_bytes)?,
        requirement(Category::PhaseScratch, [
            bytes::<PairedEndpoints<'static>>(8)?, bytes::<Bytes>(8)?,
            bytes::<Requirements>(8)?, bytes::<Instant>(8)?,
            bytes::<Result<PairedEndpoints<'static>>>(8)?,
            bytes::<PreparedSourceEndpoints>(8)?,
            bytes::<core::result::Result<(), PreparedSourceEndpoints>>(8)?,
            bytes::<&OnceCell<PreparedSourceEndpoints>>(8)?, bytes::<&Cell<bool>>(8)?,
            OUTPUT_COPY_FRAME_BYTES,
            bytes::<SourceEndpointAccess<'static>>(8)?,
            bytes::<lattica_prover_p3::proving::Report>(8)?,
            bytes::<lattica_prover_p3::proving::operation_storage::RawPreparationReportStorage>(8)?,
            bytes::<String>(8)?, 64 << 10,
        ].into_iter().try_fold(0, add)?)?,
    ])
}

pub(super) fn group_preparation_requirements(request: &Request) -> Result<(Requirements, Bytes)> {
    let words = source::boundary_preparation_words(request)?;
    // Caller fields coexist with core's independently charged staging. Up to
    // two boundary roots per child and two children; count all four backing
    // allocations without borrowing overlap credit.
    let scratch = combine(&[operation_report_requirements()?,
        requirement(Category::PhaseScratch, source::mul(bytes::<u64>(words)?, 4)?)?,
        // Actual owned Runtime startup host and driver/transport frames are
        // additive to raw operations. Device startup remains within backend.
        crate::execution::workflow_resources::group_issuer_scratch_requirements()
            .map_err(|_| PairedFailure::Resource)?,
    ])?;
    Ok((scratch, backend(field_host(words)?)?))
}

impl<'request> PairedRequestPlan<'request> {
    /// Additional original scratch/report and independently charged backend
    /// storage, admitted before calling prepare_endpoints_before_closure.
    pub(crate) fn endpoint_preparation_requirements(&self) -> Result<(Requirements, Bytes)> {
        let RequestDescriptor::Shake(descriptor) = self.request.descriptor() else {
            return Err(PairedFailure::Source);
        };
        let host = raw_crypto_host(descriptor.input_len, descriptor.output_len)?
            .max(field_host(descriptor.input_len.div_ceil(2))?)
            .max(field_host(descriptor.output_len.div_ceil(2))?);
        Ok((combine(&[memory::endpoint_scratch(self.request)?, operation_report_requirements()?])?, backend(host)?))
    }

    pub(crate) fn prepare_endpoints_before_closure(&self, access: &SourceEndpointAccess<'_>) -> Result<()> {
        let (scratch, backend) = self.endpoint_preparation_requirements()?;
        access.require_scratch(scratch).map_err(|_| PairedFailure::Authority)?;
        if self.endpoint_attempted.get() || self.source_endpoints.prepared.get().is_some()
            || !self.belongs_to(access.ledger())
            || self._metadata_original.requirements() != Self::planning_requirements(self.request, self.layout)?
            || access.operation_host_bytes() != backend.host
            || access.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired {
            return Err(PairedFailure::Authority);
        }
        // No retry after entering the source operation, including failure.
        self.endpoint_attempted.set(true);
        #[cfg(not(feature = "opencl"))]
        { Err(PairedFailure::Unsupported) }
        #[cfg(feature = "opencl")]
        {
            let started = Instant::now();
            let host = usize::try_from(backend.host).map_err(|_| PairedFailure::Overflow)?;
            let (endpoints, report) = access.context().with_witness_preparation(host, |operations| {
                self.request.endpoint_context_hint_on_gpu(&self.context, operations)
                    .map_err(|error| error.to_string())
            }).map_err(|_| PairedFailure::Preparation)?;
            // The source gate holds original report and backend claims until
            // this report dies and the actual source cleanup barrier succeeds.
            drop(report);
            if endpoints.context != self.context.context || endpoints.statement != self.context.statement {
                return Err(PairedFailure::Context);
            }
            self.source_endpoints.prepared.set(PreparedSourceEndpoints {
                context: self.context.clone(), endpoints, elapsed_ns: started.elapsed().as_nanos(),
            }).map_err(|_| PairedFailure::Authority)?;
            self.check_prepared_endpoints()
        }
    }

    /// Used by both native and outer preissue before workflow proof0.
    pub(crate) fn check_prepared_endpoints(&self) -> Result<()> {
        if !self.endpoint_attempted.get() { return Err(PairedFailure::Authority); }
        self.source_endpoints.check_source(self.request, &self.context)
    }

    /// Called only by the admitted EndpointAttach operation. Readiness gates
    /// above borrow the payload; they do not reconstruct an output or clone it.
    pub(super) fn prepared_endpoint_output(&self) -> Result<PairedEndpoints<'request>> {
        self.check_prepared_endpoints()?;
        self.source_endpoints.copy_output(self.request, &self.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use p3_field::PrimeCharacteristicRing;

    // Structural fixed-data tests only: no SourceEndpointAccess, workflow case,
    // source GPU operation or successful execution capability is fabricated.
    fn request_fixture() -> Request {
        Request::new([7; 32], 3, 0, RequestDescriptor::Shake(crate::shake_air::Descriptor { input_len: 1, output_len: 32 }),
            crate::graph_crypto::Payload::Shake(vec![0; 1]), crate::graph_crypto::Policy {
                maximum_aes_blocks: 64, maximum_shake_permutations: 8,
                child_memory_budget_bytes: 24 << 30, admission: crate::graph_crypto::Admission::Estimated,
            }).unwrap()
    }
    fn fixed_fixture() -> (GraphContext, crate::component_tree::EndpointContext) {
        let context = GraphContext { context: [11; 32],
            statement: [crate::graph_crypto::Val::ZERO; 4],
            node_manifest: [crate::graph_crypto::Val::ONE; 4] };
        let endpoints = crate::component_tree::EndpointContext { context: context.context,
            statement: context.statement, input: [crate::graph_crypto::Val::ONE; 4],
            output: [crate::graph_crypto::Val::from_u64(2); 4] };
        (context, endpoints)
    }
    fn assert_refused(store: &SourceEndpointStore<'_>, request: &Request, context: &GraphContext) {
        assert!(matches!(store.check_source(request, context), Err(PairedFailure::Authority)));
        assert!(matches!(store.copy_output(request, context), Err(PairedFailure::Authority)));
    }

    #[test]
    fn endpoint_store_copy_preserves_binding_fields_and_first_publication() {
        let request = request_fixture();
        let other = request_fixture();
        let (context, endpoints) = fixed_fixture();
        let store = SourceEndpointStore::new(&request);
        assert_refused(&store, &request, &context);
        assert!(store.prepared.set(PreparedSourceEndpoints {
            context: context.clone(), endpoints: endpoints.clone(), elapsed_ns: 37,
        }).is_ok());
        let output = store.copy_output(&request, &context).unwrap();
        output.assert_fixed_copy(&request, &context, &endpoints, 37);
        // Numerically identical requests never substitute for the bound object.
        assert_refused(&store, &other, &context);
        assert!(matches!(output.check_source(&other, &context), Err(PairedFailure::Authority)));
        for field in 0..3 {
            let mut different = context.clone();
            match field {
                0 => different.context[0] ^= 1,
                1 => different.statement[0] = crate::graph_crypto::Val::ONE,
                _ => different.node_manifest[0] = crate::graph_crypto::Val::ZERO,
            }
            assert_refused(&store, &request, &different);
        }
        let mut changed = endpoints.clone();
        changed.input[0] = crate::graph_crypto::Val::ZERO;
        changed.output[0] = crate::graph_crypto::Val::ZERO;
        assert!(store.prepared.set(PreparedSourceEndpoints {
            context: context.clone(), endpoints: changed, elapsed_ns: 99,
        }).is_err());
        store.copy_output(&request, &context).unwrap()
            .assert_fixed_copy(&request, &context, &endpoints, 37);
    }

    #[test]
    fn endpoint_store_rejects_mismatched_endpoint_context_and_statement() {
        let request = request_fixture();
        let (context, endpoints) = fixed_fixture();
        for field in 0..2 {
            let store = SourceEndpointStore::new(&request);
            let mut different = endpoints.clone();
            if field == 0 { different.context[0] ^= 1; }
            else { different.statement[0] = crate::graph_crypto::Val::ONE; }
            assert!(store.prepared.set(PreparedSourceEndpoints {
                context: context.clone(), endpoints: different, elapsed_ns: 37,
            }).is_ok());
            assert_refused(&store, &request, &context);
        }
    }

    #[test]
    fn raw_and_field_backend_bounds_refuse_overflow_and_oversized_inputs() {
        assert_eq!(raw_crypto_host(3, 0).unwrap(), (80 << 10) + 19);
        assert_eq!(field_host(0).unwrap(), 80);
        assert_eq!(field_host(4).unwrap(), 104);
        assert!(field_host(MAX_FIELD_WORDS).is_ok());
        assert!(field_host(MAX_FIELD_WORDS + 1).is_err());
        assert!(raw_crypto_host(0, usize::MAX).is_err());
        assert!(backend(0).is_err());
        assert!(backend((24usize << 30) + 1).is_err());
    }
}
