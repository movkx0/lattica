fn main() {
    if let Err(error) = lattica_pq_ringct_research::cpu_proof::main(std::env::args().skip(1)) {
        eprintln!("CPU_PROOF_ERROR {error}");
        std::process::exit(1);
    }
}
