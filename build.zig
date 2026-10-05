const std = @import("std");

// Lattica — quantum-safe shielded payments (Zig port).
//
// A single-package build: every module is a plain `.zig` file under `src/` that imports its
// dependencies by relative path, so no inter-module wiring is needed here. The `wallet`
// executable is the CLI entry point; the `test` step compiles `src/tests.zig`, which pulls in
// every module's unit tests into one binary.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "lattica-wallet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wallet.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the wallet CLI (e.g. `zig build run -- demo`)");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run all unit + integration tests");
    test_step.dependOn(&run_tests.step);

    // Opt-in research statement calculator: native Zig only, no Rust linkage
    // or recursive-proof acceptance. The caller supplies the trusted context.
    const commitment_mod = b.createModule(.{
        .root_source_file = b.path("src/block_v2.zig"),
        .target = target,
        .optimize = optimize,
    });
    const expected_root_mod = b.createModule(.{
        .root_source_file = b.path("src/block_v2_expected_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    expected_root_mod.addImport("commitment", commitment_mod);
    const expected_root = b.addExecutable(.{
        .name = "block-v2-expected-root",
        .root_module = expected_root_mod,
    });
    const install_expected_root = b.addInstallArtifact(expected_root, .{});
    b.step("block-v2-expected-root", "Build the research grouped-eight statement calculator")
        .dependOn(&install_expected_root.step);
    const expected_root_tests = b.addTest(.{ .root_module = expected_root_mod });
    const run_expected_root_tests = b.addRunArtifact(expected_root_tests);
    b.step("test-block-v2-expected-root", "Test native grouped-eight statement derivation")
        .dependOn(&run_expected_root_tests.step);

    // Production-mode compile probe (audit M-09/M-10): builds the consensus surface with
    // `lattica_production = true`, so `node.bootstrapMint` and `node.mock` are compiled out — a
    // successful compile proves the live path uses no genesis/test-only helpers. Compiling is the test.
    const prod_probe = b.addExecutable(.{
        .name = "lattica-production-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/production_probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const check_prod = b.step("check-production", "Compile the production-mode probe (test-only APIs gated out)");
    check_prod.dependOn(&prod_probe.step);
    test_step.dependOn(&prod_probe.step); // always exercised by `zig build test`

    // End-to-end FFI integration test: links the prebuilt Rust prover staticlib.
    // Build it first: `cd lattica-prover-p3 && cargo build --release`.
    const ffi_it_mod = b.createModule(.{
        .root_source_file = b.path("src/ffi_integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ffi_it_mod.addObjectFile(b.path("lattica-prover-p3/target/release/liblattica_prover_p3.a"));
    const ffi_it = b.addTest(.{ .root_module = ffi_it_mod });
    if (target.result.os.tag == .linux) {
        ffi_it_mod.linkSystemLibrary("unwind", .{});
        // The self-hosted ELF linker can't handle crt1.o's .sframe (gcc 16).
        // Zig's LLD mode does not support Mach-O; keep macOS on its default linker.
        ffi_it.use_lld = true;
    }
    const run_ffi_it = b.addRunArtifact(ffi_it);
    const ffi_step = b.step("test-ffi", "FFI integration test (run cargo build --release in lattica-prover-p3 first)");
    ffi_step.dependOn(&run_ffi_it.step);
}
