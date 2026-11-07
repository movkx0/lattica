//! Public synthetic matrix component screen, not a RingCT workflow benchmark.
use lattica_prover_p3::{
    block_v2::cpu_commitment::{CpuMmcs, Variant},
    config::{MyCompress, MyHash, Val},
};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;
fn main() {
    assert!(!cfg!(debug_assertions));
    let mut args = std::env::args().skip(1);
    let variant = Variant::parse(&args.next().expect("variant")).unwrap();
    let tile: usize = args.next().expect("tile").parse().unwrap();
    assert!(args.next().is_none());
    rayon::ThreadPoolBuilder::new().num_threads(16).build().unwrap().install(|| {
        for width in [94,200] { for repetition in 0..3 {
            let matrix=RowMajorMatrix::new((0..(1<<18)*width).map(|v|Val::from_usize(v)).collect(),width);
            let dimensions=[matrix.dimensions()];
            let perm=default_goldilocks_poseidon2_8();
            let mmcs=CpuMmcs::new(MyHash::new(perm.clone()),MyCompress::new(perm),0,ChaCha20Rng::from_seed([29;32])).with_variant(variant).with_tile_rows(tile);
            let start=Instant::now(); let (cap,data)=mmcs.commit_matrix(matrix);
            let commit_ns=start.elapsed().as_nanos();
            let opening=mmcs.open_batch(1023,&data);
            mmcs.verify_batch(&cap,&dimensions,1023,BatchOpeningRef::new(&opening.opened_values,&opening.opening_proof)).unwrap();
            println!("CPU_COMMITMENT_SCREEN {}",serde_json::json!({"variant":variant,"tile_rows":tile,"width":width,"height":1<<18,"repetition":repetition,"threads":16,"commit_ns":commit_ns,"verified":true}));
        }}
    });
}
