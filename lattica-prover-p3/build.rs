use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/cpu_sme2/goldilocks.c");
    if env::var_os("CARGO_FEATURE_CPU_SME2").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64")
    {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join("goldilocks_sme2.o");
    // Apple supports streaming SVE through SME, without ordinary SVE. A generic
    // armv9 target emits non-streaming CNTD in the function prologue and traps.
    // The M4 target is the conservative Apple SME2 baseline, also valid on M5.
    let status = Command::new("xcrun")
        .args([
            "clang",
            "-c",
            "-std=c11",
            "-O3",
            "-fno-fast-math",
            "-mcpu=apple-m4",
            "src/cpu_sme2/goldilocks.c",
            "-o",
        ])
        .arg(&object)
        .status()
        .expect("cpu-sme2 requires Apple's command-line tools");
    assert!(status.success(), "SME2 component compilation failed");
    let status = Command::new("xcrun")
        .args(["ar", "crs"])
        .arg(out.join("liblattica_sme2.a"))
        .arg(object)
        .status()
        .expect("run ar");
    assert!(status.success(), "SME2 component archive failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=lattica_sme2");
}
