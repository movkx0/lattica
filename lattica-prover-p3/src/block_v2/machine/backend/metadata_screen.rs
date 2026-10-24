//! CPU-only component measurements, with no verifier or key escaping this module.
//!
//! The public widths come from RingCT component (46), graph (28), and batch (25)
//! statements. Heights are the complete set observed in the accepted RTX 5080
//! run. Cap values and lookup identities are reconstructed, not authenticated
//! transaction artifacts. No proof is generated or numerically verified.
use super::*;
use serde::Serialize;
use std::{collections::VecDeque, hint::black_box, sync::Arc, time::Instant};

const HEIGHTS: [usize; 4] = [4096, 65536, 131072, 262144];
const PUBLIC_WIDTHS: [usize; 3] = [25, 28, 46];
const PAIRS: usize = 3;
const CONSTRUCTIONS: usize = 32;
const LOOKUPS: usize = 4096;
const PUBLIC_BYTES: usize = 64 << 20;
const CAP_BYTES: usize = 64 << 10;
const REPORT_BYTES: usize = 1 << 20;
pub const MAX_HOST_BYTES: usize = 1 << 30;
pub const MIN_HOST_BYTES: usize =
    NATIVE_VERIFIER_COMPONENT_BYTES as usize + PUBLIC_BYTES + CAP_BYTES + REPORT_BYTES;

#[derive(Serialize)]
pub struct ScreenReport {
    pub schema: &'static str,
    pub scope: &'static str,
    pub profile: [u8; 32],
    pub log_blowup: usize,
    pub num_queries: usize,
    pub cap_height: usize,
    pub cpu_only: bool,
    pub gpu_operations: usize,
    pub proofs_generated: usize,
    pub proofs_verified: usize,
    pub workflow_qualified: bool,
    pub identities: &'static str,
    pub lookup_model: &'static str,
    pub caller_host_allowance_bytes: usize,
    pub reserved_component_bytes: usize,
    pub public_cache_allowance_bytes: usize,
    pub cap_allowance_bytes: usize,
    pub report_allowance_bytes: usize,
    pub allocation_scope: &'static str,
    pub shapes: Vec<ShapeReport>,
}

#[derive(Serialize)]
pub struct ShapeReport {
    pub publics: usize,
    pub height: usize,
    pub cap_roots: usize,
    pub constructor_reservation_bytes: usize,
    pub retained_verifier_bytes: usize,
    pub models: Vec<ModelReport>,
}

#[derive(Serialize)]
pub struct ModelReport {
    pub maximum_entries: usize,
    pub synthetic_entries: usize,
    pub cache_admitted: bool,
    pub conservative_cache_reservation_bytes: usize,
    pub pairs: Vec<PairReport>,
}

#[derive(Serialize)]
pub struct PairReport {
    pub index: usize,
    pub order: [&'static str; 2],
    pub constructor_calls: usize,
    pub constructor_total_ns: u128,
    pub constructor_mean_ns: f64,
    pub validated_lookup_calls: usize,
    pub validated_lookup_total_ns: u128,
    pub validated_lookup_mean_ns: Option<f64>,
}

struct Entry {
    identity: [u64; 8],
    cap: Vec<[Val; 4]>,
    verifier: Arc<RegisteredVerifier>,
}

struct LookupModel {
    entries: VecDeque<Entry>,
}

fn identity(publics: usize, height: usize, index: usize) -> [u64; 8] {
    [
        0x6d65746164617461,
        publics as u64,
        height as u64,
        index as u64,
        0,
        0,
        0,
        1,
    ]
}

fn cache_reservation(
    entries: usize,
    capacity: usize,
    cap: &[[Val; 4]],
    payload: usize,
) -> Option<usize> {
    capacity
        .checked_mul(std::mem::size_of::<Entry>())?
        .checked_add(
            entries.checked_mul(
                payload
                    .checked_add(cap.len().checked_mul(std::mem::size_of::<[Val; 4]>())?)?
                    .checked_add(
                        2 * std::mem::size_of::<usize>()
                            + std::mem::align_of::<RegisteredVerifier>(),
                    )?,
            )?,
        )
}

impl LookupModel {
    fn new(
        publics: usize,
        height: usize,
        count: usize,
        capacity: usize,
        cap: &[[Val; 4]],
        verifier: &Arc<RegisteredVerifier>,
    ) -> Result<Self, String> {
        let reservation = cache_reservation(count, capacity, cap, verifier.cached_metadata_bytes())
            .ok_or("screen cache reservation overflow")?;
        if count > capacity || reservation > PUBLIC_BYTES {
            return Err("screen cache not admitted".into());
        }
        let mut entries = VecDeque::with_capacity(capacity);
        if entries.capacity() != capacity {
            return Err("screen cache unexpected backing capacity".into());
        }
        for index in 0..count {
            let copy = cap.to_vec();
            if copy.capacity() != cap.len() {
                return Err("screen cap unexpected backing capacity".into());
            }
            entries.push_back(Entry {
                identity: identity(publics, height, index),
                cap: copy,
                verifier: Arc::clone(verifier),
            });
        }
        Ok(Self { entries })
    }

    fn lookup(
        &mut self,
        identity: [u64; 8],
        cap: &[[Val; 4]],
    ) -> Result<Arc<RegisteredVerifier>, String> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.identity == identity)
            .ok_or("synthetic exact identity absent")?;
        let entry = self
            .entries
            .remove(index)
            .ok_or("synthetic LRU inconsistency")?;
        if entry.cap != cap {
            return Err("synthetic cap mismatch".into());
        }
        let verifier = Arc::clone(&entry.verifier);
        self.entries.push_back(entry);
        Ok(verifier)
    }
}

fn validate_request(host_bytes: usize) -> Result<(), String> {
    if !(MIN_HOST_BYTES..=MAX_HOST_BYTES).contains(&host_bytes) {
        return Err(format!(
            "metadata screen host allowance must be in {MIN_HOST_BYTES}..={MAX_HOST_BYTES}"
        ));
    }
    if !cfg!(all(
        not(debug_assertions),
        target_arch = "x86_64",
        feature = "block-v2-wide-lanes"
    )) {
        return Err("metadata screen requires the qualified release x86_64 wide profile".into());
    }
    if profile::LOG_BLOWUP != 4 || profile::NUM_QUERIES != 128 || profile::CAP_HEIGHT != 6 {
        return Err("metadata screen profile differs from accepted workload".into());
    }
    Ok(())
}

/// Measure the production CPU metadata constructor. No cap, verifier, key,
/// proof, or verification function is exposed by this research entry point.
pub fn run(host_bytes: usize) -> Result<ScreenReport, String> {
    validate_request(host_bytes)?;
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    {
        run_admitted(host_bytes)
    }
    #[cfg(not(all(not(debug_assertions), target_arch = "x86_64")))]
    {
        Err("unsupported metadata screen platform".into())
    }
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
fn run_admitted(host_bytes: usize) -> Result<ScreenReport, String> {
    // All report, cap and cache payload reservations precede allocation. The
    // existing 257 MiB lifecycle ceiling covers one constructor/output while
    // the independently reserved public cache retains its immutable verifier.
    let mut shapes = Vec::with_capacity(HEIGHTS.len() * PUBLIC_WIDTHS.len());
    for height in HEIGHTS {
        for publics in PUBLIC_WIDTHS {
            let roots = 1usize
                .checked_shl(
                    ((height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT))
                        as u32,
                )
                .ok_or("screen cap geometry overflow")?;
            if roots * std::mem::size_of::<[Val; 4]>() > CAP_BYTES {
                return Err("screen cap exceeds reservation".into());
            }
            let cap = p3_batch_stark::Commitment::<Config>::new(vec![[Val::ONE; 4]; roots]);
            let plan = verification_lifetimes::Plan::new(
                publics,
                height,
                &cap,
                super::super::symbolic::verifier::Limits::default(),
            )
            .map_err(|e| format!("{e:?}"))?;
            if plan.peak_bytes > NATIVE_VERIFIER_COMPONENT_BYTES as usize {
                return Err("constructor exceeds reserved lifecycle".into());
            }
            let seed = Arc::new(
                RegisteredVerifier::from_trusted_cap(publics, height, cap.clone())
                    .map_err(|e| format!("{e:?}"))?,
            );
            if seed.cached_metadata_bytes() > PUBLIC_BYTES {
                return Err("seed verifier exceeds public reservation".into());
            }
            let mut models = Vec::with_capacity(2);
            for capacity in [256, 512] {
                let count = capacity.min(450);
                let reservation =
                    cache_reservation(count, capacity, cap.roots(), seed.cached_metadata_bytes())
                        .ok_or("screen cache reservation overflow")?;
                let mut model = if reservation <= PUBLIC_BYTES {
                    Some(LookupModel::new(
                        publics,
                        height,
                        count,
                        capacity,
                        cap.roots(),
                        &seed,
                    )?)
                } else {
                    None
                };
                let mut pairs = Vec::with_capacity(PAIRS);
                for index in 0..PAIRS {
                    let construction = || -> Result<u128, String> {
                        let mut elapsed = 0;
                        for _ in 0..CONSTRUCTIONS {
                            let started = Instant::now();
                            let verifier = Arc::new(
                                RegisteredVerifier::from_trusted_cap(publics, height, cap.clone())
                                    .map_err(|e| format!("{e:?}"))?,
                            );
                            elapsed += started.elapsed().as_nanos();
                            black_box(&verifier);
                            // Destruction is outside constructor timing; no two
                            // newly constructed output owners coexist.
                            drop(verifier);
                        }
                        Ok(elapsed)
                    };
                    let mut lookup = || -> Result<(usize, u128), String> {
                        let Some(model) = model.as_mut() else {
                            return Ok((0, 0));
                        };
                        let started = Instant::now();
                        for sample in 0..LOOKUPS {
                            let value = model
                                .lookup(identity(publics, height, sample % count), cap.roots())?;
                            black_box(&value);
                            drop(value);
                        }
                        Ok((LOOKUPS, started.elapsed().as_nanos()))
                    };
                    let (constructor_ns, (lookup_calls, lookup_ns)) = if index % 2 == 0 {
                        (construction()?, lookup()?)
                    } else {
                        let lookup = lookup()?;
                        (construction()?, lookup)
                    };
                    pairs.push(PairReport {
                        index,
                        order: if index % 2 == 0 {
                            ["construct", "lookup"]
                        } else {
                            ["lookup", "construct"]
                        },
                        constructor_calls: CONSTRUCTIONS,
                        constructor_total_ns: constructor_ns,
                        constructor_mean_ns: constructor_ns as f64 / CONSTRUCTIONS as f64,
                        validated_lookup_calls: lookup_calls,
                        validated_lookup_total_ns: lookup_ns,
                        validated_lookup_mean_ns: (lookup_calls != 0)
                            .then_some(lookup_ns as f64 / lookup_calls.max(1) as f64),
                    });
                }
                models.push(ModelReport {
                    maximum_entries: capacity,
                    synthetic_entries: count,
                    cache_admitted: model.is_some(),
                    conservative_cache_reservation_bytes: reservation,
                    pairs,
                });
                drop(model);
            }
            shapes.push(ShapeReport {
                publics,
                height,
                cap_roots: roots,
                constructor_reservation_bytes: plan.peak_bytes,
                retained_verifier_bytes: seed.cached_metadata_bytes(),
                models,
            });
        }
    }
    Ok(ScreenReport {
        schema: "pq-verifier-metadata-component-screen-v1", scope: "production constructor and isolated synthetic lookup timings; not workflow throughput",
        profile: profile::CANDIDATE_PROFILE_ID, log_blowup: profile::LOG_BLOWUP, num_queries: profile::NUM_QUERIES, cap_height: profile::CAP_HEIGHT,
        cpu_only: true, gpu_operations: 0, proofs_generated: 0, proofs_verified: 0, workflow_qualified: false,
        identities: "reconstructed shape/counter identities and fixed public caps; no observed registration sequence",
        lookup_model: "isolated VecDeque exact-identity and cap-check/Arc-promotion model; cyclic exact hits find the oldest LRU entry; synthetic entries share one verifier; not the research Registry, observed reuse distances, or a 256-vs-512 workload hit measurement",
        caller_host_allowance_bytes: host_bytes, reserved_component_bytes: NATIVE_VERIFIER_COMPONENT_BYTES as usize,
        public_cache_allowance_bytes: PUBLIC_BYTES, cap_allowance_bytes: CAP_BYTES, report_allowance_bytes: REPORT_BYTES,
        allocation_scope: "requested payload reservations; excludes allocator/OS overhead covered by the external process guard",
        shapes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_and_model_budgets_reject_before_construction() {
        assert!(validate_request(MIN_HOST_BYTES - 1).is_err());
        assert!(validate_request(MAX_HOST_BYTES + 1).is_err());
        assert_eq!(cache_reservation(1, 1, &[[Val::ONE; 4]], usize::MAX), None);
        assert_eq!(HEIGHTS.len() * PUBLIC_WIDTHS.len(), 12);
    }
}
