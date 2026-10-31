use super::raw_adapters::RawAdapterPlan;
use super::symbolic::{self, SymbolicScratch};
use super::{bounds::Ceilings, inputs, inputs::FixedInputs};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation};
use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};
use crate::rust_verify::committed_backend::*;
use core::mem::size_of;

type Result<T> = core::result::Result<T, &'static str>;
const BUDGET: &str = "source graph payload reservation refused";

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("source graph payload sum overflow")
}
fn requirement(category: Category, bytes: usize) -> Result<Requirements> {
    Ok(Requirements::single(
        category,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| BUDGET)?,
            device: 0,
        },
    ))
}

/// Graph/input payloads and fixed symbolic/raw construction scratch. Native
/// runtime, errors/reports and the compiled stack bound are separate owners.
#[derive(Clone, Copy, Debug)]
struct PayloadPlan {
    inputs: Requirements,
    graph: Requirements,
    growth: Requirements,
    combined: Requirements,
    raw_adapters: RawAdapterPlan,
}
impl PayloadPlan {
    fn fixed() -> Result<Self> {
        if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
            return Err("source graph payload bounds require pinned release x86_64");
        }
        let ceiling = Ceilings::fixed();
        let retained = add(
            ceiling.main_vector_bytes(2)?,
            ceiling.nested_vector_bytes(2)?,
        )?;
        let growth = add(
            ceiling.main_vector_bytes(3)?,
            ceiling.nested_vector_bytes(3)?,
        )?
        .checked_sub(retained)
        .ok_or(BUDGET)?;
        // Inline charging may deliberately overlap parts of the enclosing
        // owners; it cannot be used as a compiled stack high-water estimate.
        let inputs = requirement(
            Category::CompilerInputs,
            add(
                inputs::decoded_retained_bytes()?,
                size_of::<DecodedInputs>(),
            )?,
        )?;
        let graph = requirement(
            Category::SymbolicCompiler,
            add(retained, size_of::<OwnedGraph>())?,
        )?;
        let raw_adapters = RawAdapterPlan::fixed()?;
        let mut growth = requirement(
            Category::PhaseScratch,
            add(
                add(
                    add(growth, inputs::decode_temporary_bytes()?)?,
                    add(
                        SymbolicScratch::fixed()?.requested_bytes,
                        raw_adapters.host_bytes,
                    )?,
                )?,
                add(size_of::<Construction>(), size_of::<PendingGraph>())?,
            )?,
        )?;
        growth
            .add(
                Category::PhaseScratch,
                Bytes {
                    host: 0,
                    device: u64::try_from(raw_adapters.device_bytes).map_err(|_| BUDGET)?,
                },
            )
            .map_err(|_| BUDGET)?;
        let mut combined = Requirements::default();
        for part in [inputs, graph, growth] {
            for category in Category::ALL {
                combined
                    .add(category, part.get(category))
                    .map_err(|_| BUDGET)?;
            }
        }
        Ok(Self {
            inputs,
            graph,
            growth,
            combined,
            raw_adapters,
        })
    }
}

struct DecodedInputs {
    statement: Statement,
    proof: Proof,
    // Last: every decoded Vec drops before its reservation, on all exits.
    reservation: Reservation,
}

/// No Clone, external graph constructor, graph extraction or dispatch method.
/// Original decoded inputs stay immutable and owned alongside the graph for
/// later source/context authentication; this layer does not perform it.
pub(crate) struct OwnedGraph {
    graph: UnprovedRelationGraph,
    inputs: DecodedInputs,
    context: [u8; 32],
    // Last: even the input owner has retired before graph storage is released.
    reservation: Reservation,
}
impl OwnedGraph {
    pub(in crate::rust_verify::committed_backend) fn graph(&self) -> &UnprovedRelationGraph {
        &self.graph
    }
    pub(in crate::rust_verify::committed_backend) fn inputs(&self) -> FixedInputs<'_> {
        // No mutable accessor exists and only the exact decoder constructs it.
        FixedInputs::inspect(&self.inputs.statement, &self.inputs.proof)
            .expect("private source graph decoded dimensions")
    }
    pub(in crate::rust_verify::committed_backend) fn context(&self) -> &[u8; 32] {
        &self.context
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.reservation.belongs_to(ledger) && self.inputs.reservation.belongs_to(ledger)
    }
}

pub(crate) struct Construction {
    inputs: DecodedInputs,
    context: [u8; 32],
    setup_seed: [u8; 32],
    raw_adapters: RawAdapterPlan,
    graph_reservation: Reservation,
    // Graph/decoder growth plus symbolic/raw scratch. Held through imports/backend
    // destruction and callback/report completion, including early failure.
    growth_reservation: Reservation,
}
impl Construction {
    /// A caller owns the borrowed encoded packets before this call. This
    /// constructor reserves decoded backing, graph-vector output and symbolic/raw
    /// scratch before decoding, imports, graph creation or native operations.
    pub(crate) fn new(
        setup_seed: [u8; 32],
        context: [u8; 32],
        statement: &[u8],
        proof: &[u8],
        ledger: &Ledger,
    ) -> Result<Self> {
        if statement.len() != STATEMENT_BYTES || proof.len() != PROOF_BYTES {
            return Err("source graph requires exact encoded input lengths");
        }
        let plan = PayloadPlan::fixed()?;
        let mut all = ledger.admit_phase(plan.combined).map_err(|_| BUDGET)?;
        let graph_reservation = all.split(plan.graph).map_err(|_| BUDGET)?;
        let growth_reservation = all.split(plan.growth).map_err(|_| BUDGET)?;
        let input_reservation = all.split(plan.inputs).map_err(|_| BUDGET)?;
        let statement =
            Statement::decode(statement).map_err(|_| "source graph statement decoding")?;
        let proof = Proof::decode(proof).map_err(|_| "source graph proof decoding")?;
        // This is a drift assertion in addition to the precomputed decoder
        // bound, not after-the-fact admission of arbitrary caller containers.
        let checked = FixedInputs::inspect(&statement, &proof)?;
        if checked.retained_bytes()? > inputs::decoded_retained_bytes()? {
            return Err("source graph decoder capacity differs from its source bound");
        }
        Ok(Self {
            inputs: DecodedInputs {
                statement,
                proof,
                reservation: input_reservation,
            },
            context,
            setup_seed,
            raw_adapters: plan.raw_adapters,
            graph_reservation,
            growth_reservation,
        })
    }

    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.inputs.reservation.belongs_to(ledger)
            && self.graph_reservation.belongs_to(ledger)
            && self.growth_reservation.belongs_to(ledger)
    }

    /// Derived by the private fixed schedule, already contained in the original
    /// growth reservation. It is not a caller-selected numeric admission.
    pub(crate) fn operation_host_allowance(&self) -> usize {
        self.raw_adapters.operation_host_allowance
    }

    #[cfg(feature = "opencl")]
    pub(crate) fn lower_on_gpu(
        self,
        operation: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
    ) -> Result<PendingGraph> {
        let backend = CommittedBackend::with_device(self.setup_seed, operation);
        self.lower(backend)
    }

    // Fixed-purpose constructor only: accepts no caller callback or graph.
    fn lower(self, mut backend: CommittedBackend<'_>) -> Result<PendingGraph> {
        let checked = FixedInputs::inspect(&self.inputs.statement, &self.inputs.proof)?;
        let context = backend.import_bytes(self.context, Source::Context);
        let statement = backend.import_statement(checked.statement());
        let proof = backend.import_proof(checked.proof());
        symbolic::check_imported_storage(&statement, &proof)?;
        let relation = verify_relation(&mut backend, &context, &statement, &proof);
        if backend.failure.is_some() {
            return Err("source graph native lowering failed");
        }
        relation.map_err(|_| "source graph relation lowering failed")?;
        // Imports and all backend memo maps die before a pending output can
        // escape; growth stays reserved until the outer callback also retires.
        drop(proof);
        drop(statement);
        let graph = backend.into_unproved_graph();
        Ok(PendingGraph {
            owned: OwnedGraph {
                graph,
                inputs: self.inputs,
                context: self.context,
                reservation: self.graph_reservation,
            },
            growth_reservation: self.growth_reservation,
        })
    }
}

/// Returned *through* the existing native callback. If report/completion
/// checks fail, normal destruction drops the graph before growth is released.
pub(crate) struct PendingGraph {
    owned: OwnedGraph,
    growth_reservation: Reservation,
}
impl PendingGraph {
    /// The only production-shaped use is the private GPU wrapper, which calls
    /// this after with_witness_preparation has returned and its report dropped.
    pub(crate) fn after_callback(self) -> OwnedGraph {
        let Self {
            owned,
            growth_reservation,
        } = self;
        drop(growth_reservation);
        owned
    }
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
mod tests;

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
mod differential;
