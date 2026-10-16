//! Export public AIR bytecode for isolated quotient workgroup experiments.
use super::*;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[test]
#[ignore = "CPU-only export of public machine AIR bytecode for GPU kernel experiments"]
fn export_machine_quotient_program() {
    assert!(!crate::block_v2::gpu_hash::is_enabled());
    let (air, lookups) = fixture();
    let program = Program::compile(
        &air,
        AirLayout::from_air::<Val>(&air),
        &lookups,
        &LogUpGadget::new(),
    )
    .unwrap();
    let path = PathBuf::from(std::env::var_os("LATTICA_QUOTIENT_BENCH_OUTPUT").unwrap());
    let value = serde_json::json!({
        "public_air_only": true,
        "native_transaction_fixture": false,
        "extension_degree": program.extension.degree(),
        "instructions": program.instructions,
        "registers": program.registers,
        "constraints": program.constraints,
        "row_words": program.row_words,
        "parameter_words": program.parameter_words,
        "main_width": program.layout.main_width,
        "preprocessed_width": program.layout.preprocessed_width,
        "permutation_width": program.layout.permutation_width,
    });
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    assert!(bytes.len() <= 16 << 20);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    assert!(!crate::block_v2::gpu_hash::is_enabled());
}
