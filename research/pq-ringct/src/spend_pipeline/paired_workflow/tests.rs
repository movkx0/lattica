use super::*;
use crate::{
    graph_tree::GraphContext,
    native::FixtureAmounts,
    native_test_fixture::PublicFixture,
    rust_verify::{committed_backend, Proof, Statement},
};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};
use std::{
    fmt::Write as _,
    io::{Read as _, Write as _},
};

const ARCHIVE_SHA256: &str = "b78c234c604cdbc2e44925715f6c900a739e24408223df60ab6a9b1846d5898a";
const ARCHIVE_SHA3: [u8; 32] = [
    0x0f, 0x2a, 0x2e, 0x44, 0xd7, 0xbf, 0xf5, 0x59, 0x7b, 0x3f, 0xc6, 0xf2, 0x1c, 0xe4, 0xdf, 0xb8,
    0x71, 0x62, 0x01, 0xcd, 0xc0, 0xf2, 0xe3, 0x24, 0x71, 0xcc, 0xda, 0x21, 0x3e, 0x2d, 0x08, 0xb2,
];
const STAGES: [&str; 7] = [
    "component-parent",
    "component-wrapper",
    "alpha-uniform-producer",
    "alpha-sparse-producer",
    "hash-x-producer",
    "graph-leaf",
    "graph-parent",
];

/// Existing plan and witness-hint setup belongs to the enclosing guarded
/// diagnostic harness. It is excluded from compiler metadata/time and cannot
/// establish runtime ownership admission. All plans derive from this one graph.
impl<'g> SelectedR4Inputs<'g> {
    fn for_fixture(graph: &'g UnprovedRelationGraph, fixture: &PublicFixture) -> Self {
        let registered =
            committed_backend::source_binding::RegisteredGraphShape::from_trusted_graph(graph)
                .unwrap();
        let algebra = GraphProofPlan::new(&registered, graph, SELECTED_ALGEBRA_LIMITS).unwrap();
        assert_eq!(algebra.resource_limits(), SELECTED_ALGEBRA_LIMITS);
        let tree = Plan::from_trusted_graph(graph, algebra.operation_batches()).unwrap();
        let context = GraphContext {
            context: fixture.context,
            statement: crate::recursive_aggregation::LeafStatement::from_bytes(
                tree.label(),
                fixture.context,
                &fixture.statement,
            )
            .unwrap()
            .digest
            .map(lattica_prover_p3::block_v2::machine::program::Val::from_u64),
            node_manifest: tree.node_manifest_hint(graph).unwrap(),
        };
        let budgets = Budgets {
            native_bytes: 24u64 << 30,
            outer_bytes: 32u64 << 30,
            cache_entry_bytes: 64 << 20,
            crypto_policy: graph_crypto::Policy {
                maximum_aes_blocks: 64,
                maximum_shake_permutations: 32,
                child_memory_budget_bytes: 24u64 << 30,
                admission: graph_crypto::Admission::Estimated,
            },
            transcripts: TranscriptLayout::Serial,
            aes: AesLayout::Serial,
            composites: CompositeLayout::Branches,
        };
        let crypto = graph_crypto::Plan::new(&tree, graph, budgets.crypto_policy).unwrap();
        let auxiliary =
            AuxiliaryFactory::new(&tree, graph, &context, budgets.native_bytes).unwrap();
        Self {
            graph,
            algebra,
            tree,
            crypto,
            auxiliary,
            budgets,
        }
    }
}

fn check_archive_identity(path: &std::path::Path) {
    let mut file = std::fs::File::open(path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 833617);
    let mut buffer = [0u8; 8192];
    let mut digest = Sha3_256::new();
    let mut total = 0usize;
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        total = total.checked_add(count).unwrap();
        assert!(total <= 833617, "diagnostic archive grew");
        digest.update(&buffer[..count]);
    }
    assert_eq!(total, 833617);
    assert_eq!(<[u8; 32]>::from(digest.finalize()), ARCHIVE_SHA3);
}

/// One fixed stack report buffer; no JSON Value tree, BTreeMap or report Vec.
/// The bound is checked before rendering and an overflow never grows storage.
struct ReportBuffer {
    bytes: [u8; REPORT_SCRATCH],
    used: usize,
}
impl core::fmt::Write for ReportBuffer {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(core::fmt::Error)?;
        self.bytes
            .get_mut(self.used..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}
fn render_report(
    buffer: &mut ReportBuffer,
    screen: &SelectedR4Screen<'_, '_>,
    layout: &LayoutScreen,
    seconds: f64,
) -> core::fmt::Result {
    if !seconds.is_finite() || !(0.0..1e12).contains(&seconds) {
        return Err(core::fmt::Error);
    }
    // Seven fixed stages, <= six 20-digit numeric fields each; fixed header,
    // identities/flags and two aggregation arrays fit well within 8192 bytes.
    const LOGICAL_REPORT_BOUND: usize = 8192;
    assert!(LOGICAL_REPORT_BOUND <= REPORT_SCRATCH);
    let mut maxima = [None::<&RowBound>; STAGES.len()];
    for node in &layout.nodes {
        let index = STAGES
            .iter()
            .position(|stage| *stage == node.stage)
            .ok_or(core::fmt::Error)?;
        if maxima[index].is_none_or(|prior| node.active > prior.active) {
            maxima[index] = Some(node);
        }
    }
    let n3 = mul(3, layout.nodes.len())
        .and_then(|n| add(n, layout.n3.len()))
        .map_err(|_| core::fmt::Error)?;
    let n4 = mul(4, layout.nodes.len())
        .and_then(|n| add(n, layout.n4.len()))
        .map_err(|_| core::fmt::Error)?;
    buffer.used = 0;
    write!(buffer, "SELECTED_R4_ROW_SCREEN {{\"layout\":\"{}\",\"scheduled_native_invocations_per_transaction\":{},\"scheduled_recursive_invocations_per_transaction\":{},\"graph_root_rows_upper\":{},\"n3_scheduled_recursive_invocations_fixture_estimate\":{},\"n4_scheduled_recursive_invocations_fixture_estimate\":{},\"n3_aggregate_rows_upper\":[{},{}],\"n4_aggregate_rows_upper\":[{},{},{}],\"stage_maxima\":[",
        layout.layout.name(), screen.native_proofs, layout.nodes.len(), layout.graph_root, n3, n4,
        layout.n3[0].padded, layout.n3[1].padded,
        layout.n4[0].padded, layout.n4[1].padded, layout.n4[2].padded)?;
    let mut separator = "";
    for node in maxima.into_iter().flatten() {
        write!(buffer, "{separator}{{\"stage\":\"{}\",\"ordinal\":{},\"first\":{},\"count\":{},\"active_rows_upper\":{},\"padded_rows_upper\":{}}}",
            node.stage, node.ordinal, node.first, node.count, node.active, node.padded)?;
        separator = ",";
    }
    write!(buffer, "],\"configured_max_rows\":{},\"planner_metadata_reserved_bytes\":{},\"report_stack_reserved_bytes\":{},\"combined_layout_compiler_screen_seconds\":{:.6},\"archive_pinned_sha256\":\"{}\",\"archive_verified_sha3_256\":\"",
        ROWS, screen.metadata_reservation, REPORT_SCRATCH, seconds, ARCHIVE_SHA256)?;
    for byte in ARCHIVE_SHA3 {
        write!(buffer, "{byte:02x}")?;
    }
    write!(buffer, "\",\"diagnostic_context_repeated_byte\":71,\"diagnostic_setup_repeated_byte\":29,\"fixture_graph_plan_setup_excluded\":true,\"real_proofs_produced\":false,\"runtime_ownership_admitted\":false,\"dispatch_authorized\":false,\"fixture_screen_only\":true,\"accepted_n3_n4_fixture\":false,\"fresh_request_identity_required\":true}}\n")?;
    assert!(buffer.used <= LOGICAL_REPORT_BOUND);
    Ok(())
}

#[test]
fn selected_metadata_arithmetic_and_fixed_report_storage_reject_overflow() {
    assert!(add(usize::MAX, 1).is_err());
    assert!(backing::<RowBound>(usize::MAX, 2).is_err());
    let mut report = ReportBuffer {
        bytes: [0; REPORT_SCRATCH],
        used: REPORT_SCRATCH - 1,
    };
    assert!(write!(&mut report, "ab").is_err());
    assert_eq!(report.used, REPORT_SCRATCH - 1);
}

#[test]
#[ignore = "complete selected-R4 compiler row screening; coordinator serialized release guard required"]
fn selected_r4_native_and_descendant_closure() {
    assert!(cfg!(all(not(debug_assertions), target_arch = "x86_64")));
    assert_eq!(
        std::env::var("LATTICA_SELECTED_R4_SHAPE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_REGISTERED_CLOSURE_MAX_ROWS").as_deref(),
        Ok("1048576")
    );
    let path = std::path::PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing persisted public graph fixture required"),
    );
    check_archive_identity(&path);
    let fixture = crate::native_test_fixture::load_or_create(
        &path,
        [71; 32],
        [29; 32],
        3,
        FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
        false,
    )
    .unwrap();
    check_archive_identity(&path);
    let graph = committed_backend::lower_unproved(
        fixture.setup_seed,
        &fixture.context,
        &Statement::decode(&fixture.statement).unwrap(),
        &Proof::decode(&fixture.proof).unwrap(),
    )
    .unwrap();
    let mut inputs = SelectedR4Inputs::for_fixture(&graph, &fixture);
    assert!(screen_selected_r4(&inputs, ROWS * 2).is_err());
    inputs.budgets.transcripts = TranscriptLayout::Wide {
        maximum_permutations: 32,
    };
    assert!(screen_selected_r4(&inputs, ROWS).is_err());
    inputs.budgets.transcripts = TranscriptLayout::Serial;
    inputs.budgets.crypto_policy.maximum_shake_permutations = 16;
    assert!(screen_selected_r4(&inputs, ROWS).is_err());
    inputs.budgets.crypto_policy.maximum_shake_permutations = 32;
    let started = std::time::Instant::now();
    let screen = screen_selected_r4(&inputs, ROWS)
        .unwrap_or_else(|reason| panic!("complete selected-R4 row gate refused: {reason}"));
    let combined_seconds = started.elapsed().as_secs_f64();
    assert!(screen.is_for(&inputs));
    assert_eq!(screen.profile, inputs.tree.label());
    assert!(screen.paired.nodes.len() < screen.singleton.nodes.len());
    let mut report = ReportBuffer {
        bytes: [0; REPORT_SCRATCH],
        used: 0,
    };
    for layout in [&screen.singleton, &screen.paired] {
        render_report(&mut report, &screen, layout, combined_seconds).unwrap();
        std::io::stderr()
            .lock()
            .write_all(&report.bytes[..report.used])
            .unwrap();
    }
    assert!(ShakeWrapperLayout::PairedV1.require_executable().is_err());
}
