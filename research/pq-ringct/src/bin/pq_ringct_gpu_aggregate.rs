fn main() {
    if std::env::args().any(|arg| arg == "--help") {
        println!("pq-ringct-gpu-aggregate prepare-inputs|plan|screen|run --case n3|n4 --input-bundle PATH [--input PUBLIC_INPUTS] [--profile legacy|grouped-v2] [--group-width 1|2|4|8] [--pipeline serial|lookahead] [--identity cpu|gpu-batched] [--timeout-seconds 1..600] [--max-components N] [--request INDEX] [--repetitions 1..4] [--screen-family shake|graph] [--first-leaf INDEX] [--leaves 1..8] [--selection JSON] [--output NEW_ARTIFACT]\nUse the exclusive resource guard. Run never creates missing native proofs. Grouped-v2 is unqualified research.");
        return;
    }
    if let Err(error) =
        lattica_pq_ringct_research::gpu_aggregation::run_cli(std::env::args().skip(1))
    {
        eprintln!("GPU_AGGREGATION_FAILURE {error}");
        std::process::exit(1);
    }
}
