//! Public-only matched inputs. Fresh generation is separate from proof timing.
use super::*;
use crate::{
    graph_crypto::{Admission, Policy},
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree,
    native::{
        cpu_generation::{Configuration, Generator},
        FixtureAmounts,
    },
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PublicInput {
    setup_seed: [u8; 32],
    context: [u8; 32],
    statement: Vec<u8>,
    proof: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
pub struct Fixture {
    schema: String,
    workload: usize,
    transactions: Vec<PublicInput>,
}
pub struct Case {
    pub statement: Vec<u8>,
    pub private_proof: Vec<u8>,
    pub plan: graph_crypto::Plan,
    pub context: graph_tree::GraphContext,
    pub graph: committed_backend::UnprovedRelationGraph,
    pub shape: RegisteredGraphShape,
    pub tree: graph_tree::Plan,
}
fn algebra_limits() -> ResourceLimits {
    ResourceLimits {
        max_batch_count: 64,
        max_ntt_batch_count: 32,
        max_mul_batch_count: 32,
        max_trace_cells: 1 << 27,
        max_estimated_prover_bytes: 24 << 30,
    }
}
impl Case {
    pub fn algebra(&self) -> Result<GraphProofPlan<'_>> {
        GraphProofPlan::new(&self.shape, &self.graph, algebra_limits()).map_err(error)
    }
}
pub fn generate(options: &Options, path: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let (seed, context) = if options.workload == 0 {
        ([0x11; 32], [0x22; 32])
    } else {
        ([0x33; 32], [0x44; 32])
    };
    let mut owner = Generator::new(seed, context, Configuration::default()).map_err(error)?;
    let mut transactions = Vec::new();
    for i in 0..options.transactions {
        let output = owner
            .generate(
                i as u64 + 3,
                FixtureAmounts {
                    input: [17, 23],
                    output: [29, 11],
                },
            )
            .map_err(error)?;
        ensure(
            crate::native::verify(&context, &output.statement, &output.proof).map_err(error)?,
            "input verification",
        )?;
        transactions.push(PublicInput {
            setup_seed: seed,
            context,
            statement: output.statement,
            proof: output.proof,
        });
    }
    drop(owner);
    let fixture = Fixture {
        schema: "ringct-cpu-proof-public-inputs-v1".into(),
        workload: options.workload,
        transactions,
    };
    let bytes = serde_json::to_vec(&fixture).map_err(error)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(error)?;
    file.write_all(&bytes).map_err(error)?;
    file.sync_all().map_err(error)?;
    println!(
        "GPU_AGGREGATION_INPUTS {}",
        serde_json::json!({"transactions": options.transactions,
        "workload": options.workload, "sha3_256": hex(&sha3::Sha3_256::digest(&bytes)),
        "private_entropy":"os-fresh", "secret_keys_exported":false, "verified":true})
    );
    Ok(())
}
pub fn load(options: &Options) -> Result<(Vec<Arc<Case>>, String)> {
    let meta = std::fs::metadata(&options.input).map_err(error)?;
    ensure(meta.is_file() && meta.len() <= 8 << 20, "input file size")?;
    let bytes = std::fs::read(&options.input).map_err(error)?;
    let digest = hex(&sha3::Sha3_256::digest(&bytes));
    let fixture: Fixture = serde_json::from_slice(&bytes).map_err(error)?;
    ensure(
        fixture.schema == "ringct-cpu-proof-public-inputs-v1"
            && fixture.workload == options.workload
            && fixture.transactions.len() == options.transactions,
        "input identity differs from selection",
    )?;
    let mut cases = Vec::new();
    let mut statements = std::collections::BTreeSet::new();
    for input in fixture.transactions {
        ensure(
            statements.insert(hex(&Sha3_256::digest(&input.statement))),
            "duplicate transaction statement in aggregation benchmark",
        )?;
        let (seed, context) = if options.workload == 0 {
            ([0x11; 32], [0x22; 32])
        } else {
            ([0x33; 32], [0x44; 32])
        };
        ensure(
            input.setup_seed == seed && input.context == context,
            "public workload seed/context mismatch",
        )?;
        ensure(
            crate::native::verify(&input.context, &input.statement, &input.proof).map_err(error)?,
            "input proof invalid",
        )?;
        let graph = committed_backend::lower_unproved(
            input.setup_seed,
            &input.context,
            &Statement::decode(&input.statement).map_err(error)?,
            &Proof::decode(&input.proof).map_err(error)?,
        )
        .map_err(error)?;
        let shape = RegisteredGraphShape::from_trusted_graph(&graph).map_err(error)?;
        let algebra = GraphProofPlan::new(&shape, &graph, algebra_limits()).map_err(error)?;
        let tree = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches())
            .map_err(error)?;
        let context = graph_tree::GraphContext {
            context: input.context,
            statement: crate::recursive_aggregation::LeafStatement::from_bytes(
                tree.label(),
                input.context,
                &input.statement,
            )
            .map_err(error)?
            .digest
            .map(Val::from_u64),
            node_manifest: tree.node_manifest_hint(&graph).map_err(error)?,
        };
        let plan = graph_crypto::Plan::new(
            &tree,
            &graph,
            Policy {
                maximum_aes_blocks: 64,
                maximum_shake_permutations: 32,
                child_memory_budget_bytes: 24 << 30,
                admission: Admission::Estimated,
            },
        )
        .map_err(error)?;
        cases.push(Arc::new(Case {
            statement: input.statement,
            private_proof: input.proof,
            plan,
            context,
            graph,
            shape,
            tree,
        }));
    }
    Ok((cases, digest))
}
