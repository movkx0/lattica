use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=native/reference.c");
    if env::var_os("CARGO_FEATURE_NATIVE_REFERENCE").is_none() {
        return;
    }
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        "x86_64",
        "reference is x86_64 only"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        "linux",
        "reference is Linux only"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join("reference.o");
    let status = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args([
            "-std=gnu11",
            "-O2",
            "-fPIC",
            "-mavx2",
            "-maes",
            "-mfma",
            "-fwrapv",
            "-Wall",
            "-Wextra",
            "-I",
            "../pq-ringct/vendor/matrict-plus/n10",
            "-c",
            "native/reference.c",
            "-o",
        ])
        .arg(&object)
        .status()
        .expect("C reference compiler");
    assert!(status.success(), "C reference compiler failed");
    let status = Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
        .arg("crs")
        .arg(out.join("libdirect_spend_reference.a"))
        .arg(object)
        .status()
        .expect("reference archiver");
    assert!(status.success(), "reference archive failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=direct_spend_reference");
}
