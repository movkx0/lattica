//! Fixed native-SHAKE and registered-machine Run/report source storage.
//! The enclosing phase owns this backing before invoking either fixed entry.
//! OpenCL/compiler errors and proof/key/verification payloads have other owners.
use super::*;
use core::mem::size_of;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "block-v2",
    feature = "gpu-bounded-info"
))]
pub mod outer_ocl;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "block-v2",
    feature = "gpu-bounded-info"
))]
pub mod native_shake_ocl;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "block-v2",
    feature = "gpu-bounded-info"
))]
pub mod native_aes_ocl;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_graph_source_ocl;


const INVENTORY: usize = 16;
const STAGES: usize = 19;
const BACKENDS: usize = 6;
const OBSERVATIONS: usize = STAGES * BACKENDS;
const JSON_BYTES: usize = 4096 + INVENTORY * 128 + OBSERVATIONS * 512;
const ERROR_BYTES: usize = 4096 + OBSERVATIONS * 256;

fn stage_slot(stage: Stage) -> usize {
    match stage {
        Stage::PublicValues => 0,
        Stage::WitnessTrace => 1,
        Stage::Preprocessing => 2,
        Stage::Lookup => 3,
        Stage::Transform => 4,
        Stage::Quotient => 5,
        Stage::Randomness => 6,
        Stage::Hiding => 7,
        Stage::Commitment => 8,
        Stage::Opening => 9,
        Stage::FriFold => 10,
        Stage::FriQuery => 11,
        Stage::FinalPolynomial => 12,
        Stage::Scalar => 13,
        Stage::Transcript => 14,
        Stage::Grinding => 15,
        Stage::UpstreamProver => 16,
        Stage::ConstraintAudit => 17,
        Stage::Serialization => 18,
    }
}
fn backend_slot(backend: Backend) -> usize {
    match backend {
        Backend::Cpu => 0,
        Backend::OpenCl => 1,
        Backend::Metal => 2,
        Backend::Cuda => 3,
        Backend::Mixed => 4,
        Backend::Unknown => 5,
    }
}
fn vector<T>(count: usize) -> usize {
    3 * count.next_power_of_two().max(4) * size_of::<T>()
}
fn arc_bytes<T>() -> usize {
    #[repr(C)]
    struct Allocation<T> {
        strong: std::sync::atomic::AtomicUsize,
        weak: std::sync::atomic::AtomicUsize,
        value: T,
    }
    size_of::<Allocation<T>>()
}

#[derive(Clone, Copy, Debug)]
pub struct FixedProofReportStorage {
    required_host_bytes: usize,
}
impl FixedProofReportStorage {
    /// Covers the exact native SHAKE entry, or preprocessing followed by the
    /// consuming registered-machine entry. No composition parent, component
    /// table, caller label or supplied collection is accepted. The registered
    /// path destroys its setup report before starting its proving Run.
    pub fn fixed() -> Result<Self, Error> {
        if Stage::ARITHMETIC.len() != INVENTORY
            || stage_slot(Stage::Serialization) + 1 != STAGES
            || backend_slot(Backend::Unknown) + 1 != BACKENDS
            || JSON_BYTES > 1 << 16
            || ERROR_BYTES > 1 << 16
        {
            return Err(Error::ComponentRejected);
        }
        // profile::{proving,registered_proof,preprocessing}_capabilities uses
        // fixed inventories, one Vec<Stage> and nested temporary capabilities.
        // Sum twelve complete inventory allocations, including clones and
        // Request::admit's gaps; no lifetime-overlap credit is needed.
        let capabilities = 12 * vector::<StageCapability>(INVENTORY) + vector::<Stage>(INVENTORY);
        let observations = vector::<Observation>(OBSERVATIONS);
        let completion = vector::<StageCapability>(INVENTORY)
            + vector::<StageCapability>(OBSERVATIONS)
            + vector::<StageCapability>(INVENTORY);
        // Run errors contain only closed enum entries and integers in these
        // fixed paths. Include original error formatting, not later truncation.
        let publication = 3 * JSON_BYTES.next_power_of_two() + 3 * ERROR_BYTES.next_power_of_two();
        let owners = 2 * size_of::<Run>()
            + 4 * size_of::<Report>()
            + 4 * size_of::<Capabilities>()
            + 2 * size_of::<Error>()
            + 2 * size_of::<Timer<'static>>()
            + 2 * arc_bytes::<Mutex<State>>()
            + size_of::<Self>();
        let required_host_bytes = [capabilities, observations, completion, publication, owners]
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or(Error::ComponentRejected)?;
        Ok(Self {
            required_host_bytes,
        })
    }

    pub fn required_host_bytes(self) -> usize {
        self.required_host_bytes
    }
}

#[cfg(all(test, feature = "block-v2", feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;

    #[test]
    fn fixed_report_planner_allocates_nothing() {
        let (bound, requests) = measure(|| FixedProofReportStorage::fixed().unwrap());
        assert_eq!(
            (requests.calls, requests.bytes, requests.overflow),
            (0, 0, false)
        );
        assert!(bound.required_host_bytes() < 1 << 20);
    }

    #[test]
    fn real_registered_capability_builders_fit_the_inventory_allocation_bound() {
        let (_, requests) = measure(|| {
            let pre = crate::block_v2::profile::preprocessing_capabilities();
            let prove = crate::block_v2::profile::registered_proof_capabilities();
            assert_eq!(pre.scope(), CoverageScope::Preprocessing);
            assert_eq!(prove.scope(), CoverageScope::RegisteredProof);
            assert!(pre.stages().len() <= INVENTORY && prove.stages().len() <= INVENTORY);
        });
        assert!(!requests.overflow);
        assert!(
            requests.bytes
                <= 12 * vector::<StageCapability>(INVENTORY) + vector::<Stage>(INVENTORY)
        );
    }

    const STAGE_KEYS: [Stage; STAGES] = [
        Stage::PublicValues,
        Stage::WitnessTrace,
        Stage::Preprocessing,
        Stage::Lookup,
        Stage::Transform,
        Stage::Quotient,
        Stage::Randomness,
        Stage::Hiding,
        Stage::Commitment,
        Stage::Opening,
        Stage::FriFold,
        Stage::FriQuery,
        Stage::FinalPolynomial,
        Stage::Scalar,
        Stage::Transcript,
        Stage::Grinding,
        Stage::UpstreamProver,
        Stage::ConstraintAudit,
        Stage::Serialization,
    ];
    const BACKEND_KEYS: [Backend; BACKENDS] = [
        Backend::Cpu,
        Backend::OpenCl,
        Backend::Metal,
        Backend::Cuda,
        Backend::Mixed,
        Backend::Unknown,
    ];

    // This deliberately rejected inventory exercises the largest closed Run
    // report and Error collections. It is allocation evidence, not a receipt
    // for any actual GPU work.
    fn maximal_run() -> Run {
        let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
        for stage in Stage::ARITHMETIC {
            capabilities.set(stage, Backend::OpenCl);
        }
        let run = Run::new(
            "block_v2_registered_program",
            Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            },
            capabilities,
        )
        .unwrap();
        let mut state = run.state.lock().unwrap();
        for stage in STAGE_KEYS {
            for backend in BACKEND_KEYS {
                state.observations.push(Observation {
                    stage,
                    backend,
                    calls: u64::MAX,
                    completed_calls: 0,
                    device_calls: u64::MAX,
                    inclusive_ns: u128::MAX,
                    device_ns: u128::MAX,
                });
            }
        }
        state.observation_errors = u64::MAX;
        drop(state);
        run
    }

    #[test]
    fn closed_proof_reports_and_original_errors_fit_before_the_run() {
        let bound = FixedProofReportStorage::fixed().unwrap();
        for (index, stage) in STAGE_KEYS.into_iter().enumerate() {
            assert_eq!(stage_slot(stage), index);
            for (index, backend) in BACKEND_KEYS.into_iter().enumerate() {
                assert_eq!(backend_slot(backend), index);
                assert!(format!("{:?}", StageCapability { stage, backend }).len() < 128);
            }
        }
        for success in [false, true] {
            let (_, requests) = measure(|| match maximal_run().finish(success) {
                Ok(mut report) => {
                    report.elapsed_ns = u128::MAX;
                    let json = serde_json::to_string(&report).unwrap();
                    assert!(json.len() <= JSON_BYTES);
                }
                Err(error) => {
                    let text = error.to_string();
                    assert!(text.len() <= ERROR_BYTES);
                    assert!(matches!(error, Error::IncompleteCoverage { .. }));
                }
            });
            assert!(
                !requests.overflow && requests.bytes <= bound.required_host_bytes(),
                "{requests:?}"
            );
        }
        let unsupported = Error::Unsupported {
            policy: Policy::GpuRequired,
            gaps: Stage::ARITHMETIC
                .into_iter()
                .map(|stage| StageCapability {
                    stage,
                    backend: Backend::Unknown,
                })
                .collect(),
        };
        assert!(unsupported.to_string().len() <= ERROR_BYTES);
    }
}

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_uniform_ocl;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_transcript_ocl;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_affine_ocl;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_sparse_ocl;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_ntt_ocl;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_mul_ocl;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_g_bound_ocl;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_permutation_ocl;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "block-v2", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod native_linear_map_ocl;
