//! Degree-contract checks retain the old no-hint symbolic inference and use
//! a CPU-only PCS oracle, independent of process-global GPU selection.
use super::*;
use crate::block_v2::profile::{self, Challenge};

use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks, get_max_constraint_degree};

use p3_lookup::{LogUpGadget, Lookups};

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct Observed<'a> {
    air: &'a MachineAir,
    hint: Option<usize>,
    calls: Arc<AtomicUsize>,
}

impl<'a> Observed<'a> {
    fn new(air: &'a MachineAir, hinted: bool) -> Self {
        Self {
            air,
            hint: hinted.then(|| air.max_constraint_degree().unwrap()),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn reset(&self) {
        self.calls.store(0, Ordering::SeqCst);
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl BaseAir<Val> for Observed<'_> {
    fn width(&self) -> usize {
        self.air.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.air.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.air.preprocessed_trace()
    }
    fn num_public_values(&self) -> usize {
        self.air.num_public_values()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.air.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.air.preprocessed_next_row_columns()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.hint
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for Observed<'_> {
    fn eval(&self, builder: &mut AB) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.air.eval(builder);
    }
}

fn shape(publics: usize, height: usize) -> MachineAir {
    MachineAir::new(
        ProgramBuilder::new(publics)
            .unwrap()
            .finish(Some(height))
            .unwrap(),
    )
}

#[test]
fn exact_base_degree_matches_original_graph_for_all_public_counts() {
    for publics in 0..=MAX_PUBLIC_VALUES {
        for height in [8, 1 << 19] {
            let air = shape(publics, height);
            let original = Observed::new(&air, false);
            let degree = get_max_constraint_degree::<Val, Challenge, _, _>(
                &original,
                AirLayout::from_air::<Val>(&original),
                &[],
                &LogUpGadget::new(),
            );
            assert_eq!(
                degree, MAX_CONSTRAINT_DEGREE,
                "publics={publics} height={height}"
            );
            assert_eq!(air.max_constraint_degree(), Some(degree));
            assert_eq!(original.calls(), 1);
        }
    }
    eprintln!(
        "machine_degree_base publics=65 heights=2 degree=8 original_graphs=130 wide={}",
        cfg!(feature = "block-v2-wide-lanes")
    );
}

#[test]
fn packed_and_unpacked_lookup_quotient_geometry_matches_original() {
    let gadget = LogUpGadget::new();
    for publics in [0, 1, 23, 32, 33, MAX_PUBLIC_VALUES] {
        for height in [8, 2048] {
            let air = shape(publics, height);
            let original = Observed::new(&air, false);
            let unpacked = Lookups::from_air::<Challenge, _>(&original);
            let layout = AirLayout::from_air::<Val>(&original);
            for zk in [0, 1] {
                let original_chunks = get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                    &original, layout, &unpacked, zk, &gadget,
                );
                assert_eq!(original_chunks, 3);
                let packed = unpacked
                    .clone()
                    .pack_same_bus(&gadget, 1 << original_chunks);
                for lookups in [&unpacked, &packed] {
                    let old = get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                        &original, layout, lookups, zk, &gadget,
                    );
                    let new = get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                        &air, layout, lookups, zk, &gadget,
                    );
                    assert_eq!(new, old);
                    assert_eq!(new, 3);
                }
            }
        }
    }
    eprintln!(
        "machine_degree_lookup comparisons=48 log_chunks=3 wide={}",
        cfg!(feature = "block-v2-wide-lanes")
    );
}

#[test]
fn release_degree_inference_skips_symbolic_callbacks() {
    let air = shape(33, 64);
    let old = Observed::new(&air, false);
    let new = Observed::new(&air, true);
    let gadget = LogUpGadget::new();
    let unpacked = Lookups::from_air::<Challenge, _>(&old);
    let packed = unpacked.clone().pack_same_bus(&gadget, 8);
    for lookups in [&unpacked, &packed] {
        old.reset();
        new.reset();
        let layout = AirLayout::from_air::<Val>(&air);
        let expected =
            get_log_num_quotient_chunks::<Val, Challenge, _, _>(&old, layout, lookups, 1, &gadget);
        assert_eq!(
            get_log_num_quotient_chunks::<Val, Challenge, _, _>(&new, layout, lookups, 1, &gadget),
            expected
        );
        assert_eq!(old.calls(), 1);
        assert_eq!(new.calls(), usize::from(cfg!(debug_assertions)));
        eprintln!(
            "machine_degree_callbacks original={} selected={} debug={}",
            old.calls(),
            new.calls(),
            cfg!(debug_assertions)
        );
    }
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
mod proof {
    use super::*;
    use crate::config::{MyCompress, MyHash, ValMmcs};
    use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
    use p3_commit::ExtensionMmcs;
    use p3_fri::HidingFriPcs;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    type CpuPcs = HidingFriPcs<
        Val,
        crate::config::Dft,
        ValMmcs,
        ExtensionMmcs<Val, Challenge, ValMmcs>,
        ChaCha20Rng,
    >;
    type CpuConfig = p3_uni_stark::StarkConfig<CpuPcs, Challenge, crate::config::Challenger>;

    // Fixed seeds exist only in this conformance fixture. Match every production
    // proof parameter, including hiding, query count, blowup and cap geometry.
    fn cpu_config() -> CpuConfig {
        let perm = default_goldilocks_poseidon2_8();
        let mmcs = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([73; 32]),
        );
        CpuConfig::new(
            CpuPcs::new(
                Default::default(),
                mmcs.clone(),
                profile::fri(ExtensionMmcs::new(mmcs)),
                profile::NUM_RANDOM_CODEWORDS,
                ChaCha20Rng::from_seed([79; 32]),
            ),
            crate::config::Challenger::new(perm),
        )
    }

    #[test]
    fn native_proof_bytes_and_tamper_decisions_match_original_air() {
        let mut builder = ProgramBuilder::new(1).unwrap();
        let x = builder.input();
        let square = builder.mul(x, x);
        let public = builder.public(0).unwrap();
        builder.assert_equal(square, public);
        let _ = builder.poseidon([x; 8]);
        let air = MachineAir::new(builder.finish(Some(32)).unwrap());
        let old = Observed::new(&air, false);
        let new = Observed::new(&air, true);
        let public = vec![Val::from_u64(49)];
        let trace = air.trace(&public, &[Val::from_u64(7)]).unwrap();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let (old_config, old_data, old_proof) = pool.install(|| {
            let config = cpu_config();
            let data =
                ProverData::from_airs_and_degrees(&config, core::slice::from_ref(&old), &[6]);
            let proof = prove_batch(
                &config,
                &[StarkInstance {
                    air: &old,
                    trace: &trace,
                    public_values: public.clone(),
                }],
                &data,
            );
            (config, data, proof)
        });
        let (new_config, new_data, mut new_proof) = pool.install(|| {
            let config = cpu_config();
            let data =
                ProverData::from_airs_and_degrees(&config, core::slice::from_ref(&new), &[6]);
            let proof = prove_batch(
                &config,
                &[StarkInstance {
                    air: &new,
                    trace: &trace,
                    public_values: public.clone(),
                }],
                &data,
            );
            (config, data, proof)
        });
        assert_eq!(
            postcard::to_allocvec(&old_proof).unwrap(),
            postcard::to_allocvec(&new_proof).unwrap()
        );
        for (observed, config, data) in [
            (&old, &old_config, &old_data),
            (&new, &new_config, &new_data),
        ] {
            observed.reset();
            verify_batch(
                config,
                core::slice::from_ref(observed),
                &new_proof,
                &[public.clone()],
                &data.common,
            )
            .unwrap();
            let expected = if observed.hint.is_some() {
                1 + usize::from(cfg!(debug_assertions))
            } else {
                2
            };
            assert_eq!(
                observed.calls(),
                expected,
                "only numerical AIR evaluation remains in release verification"
            );
            eprintln!(
                "machine_degree_verifier hinted={} callbacks={} debug={}",
                observed.hint.is_some(),
                observed.calls(),
                cfg!(debug_assertions)
            );
            assert!(verify_batch(
                config,
                core::slice::from_ref(observed),
                &new_proof,
                &[vec![public[0] + Val::ONE]],
                &data.common
            )
            .is_err());
        }
        eprintln!(
            "machine_degree_proof_parity bytes={} wide={}",
            postcard::to_allocvec(&new_proof).unwrap().len(),
            cfg!(feature = "block-v2-wide-lanes")
        );
        new_proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += Challenge::ONE;
        for (observed, config, data) in [
            (&old, &old_config, &old_data),
            (&new, &new_config, &new_data),
        ] {
            assert!(verify_batch(
                config,
                core::slice::from_ref(observed),
                &new_proof,
                &[public.clone()],
                &data.common
            )
            .is_err());
        }
    }
}
