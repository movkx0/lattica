const std = @import("std");
const GpuBackend = enum { opencl, cuda };

// Lattica — quantum-safe shielded payments (Zig port).
//
// A single-package build: every module is a plain `.zig` file under `src/` that imports its
// dependencies by relative path, so no inter-module wiring is needed here. The `wallet`
// executable is the CLI entry point; the `test` step compiles `src/tests.zig`, which pulls in
// every module's unit tests into one binary.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const block_capacity = b.option(u16, "block-capacity", "Research block capacity (64 or 128; must match the Rust library)") orelse 64;
    if (block_capacity != 64 and block_capacity != 128) @panic("supported block capacities are 64 and 128");
    const selected_gpu_backend = b.option(GpuBackend, "gpu-backend", "Native GPU backend (enables GPU proving; must match the Rust library)");
    const gpu_prover = b.option(bool, "gpu-prover", "Use native GPU prover for wallet demos and FFI tests (defaults to OpenCL)") orelse (selected_gpu_backend != null);
    if (selected_gpu_backend != null and !gpu_prover) @panic("gpu-backend requires gpu-prover=true");
    const gpu_backend = selected_gpu_backend orelse .opencl;
    if (gpu_prover and gpu_backend == .cuda and target.result.os.tag != .linux) @panic("the CUDA prover currently requires Linux");
    const prover_library = b.option([]const u8, "prover-library", "Path to the prebuilt Rust prover static library") orelse
        "lattica-prover-p3/target/release/liblattica_prover_p3.a";
    const prover_options = b.addOptions();
    prover_options.addOption(bool, "gpu_prover", gpu_prover);
    prover_options.addOption(GpuBackend, "gpu_backend", gpu_backend);
    prover_options.addOption(u16, "block_capacity", block_capacity);

    const exe = b.addExecutable(.{
        .name = "lattica-wallet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wallet.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addOptions("prover_options", prover_options);
    if (gpu_prover) {
        exe.stack_size = 8 << 20;
        exe.root_module.link_libc = true;
        exe.root_module.addObjectFile(.{ .cwd_relative = prover_library });
        if (gpu_backend == .opencl) exe.root_module.linkSystemLibrary("OpenCL", .{});
        if (target.result.os.tag == .linux) {
            exe.root_module.linkSystemLibrary("unwind", .{});
            exe.use_lld = true;
        }
    }
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the wallet CLI (e.g. `zig build run -- demo`)");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(if (block_capacity == 128) "src/tests_128.zig" else "src/tests.zig"),
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
        .root_source_file = b.path(if (block_capacity == 128) "src/block_v2_expected_root_128.zig" else "src/block_v2_expected_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    expected_root_mod.addImport("commitment", commitment_mod);
    const expected_root = b.addExecutable(.{
        .name = "block-v2-expected-root",
        .root_module = expected_root_mod,
    });
    const install_expected_root = b.addInstallArtifact(expected_root, .{});
    b.step("block-v2-expected-root", "Build the research ordered statement calculator")
        .dependOn(&install_expected_root.step);
    const expected_root_tests = b.addTest(.{ .root_module = expected_root_mod });
    const run_expected_root_tests = b.addRunArtifact(expected_root_tests);
    b.step("test-block-v2-expected-root", "Test native ordered statement derivation")
        .dependOn(&run_expected_root_tests.step);

    // Production-mode compile probe (audit M-09/M-10): builds the consensus surface with
    // `lattica_production = true`, so `node.bootstrapMint` and `node.mock` are compiled out — a
    // successful compile proves the live path uses no genesis/test-only helpers. Compiling is the test.
    const prod_probe = b.addExecutable(.{
        .name = "lattica-production-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path(if (block_capacity == 128) "src/production_probe_128.zig" else "src/production_probe.zig"),
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
    ffi_it_mod.addOptions("prover_options", prover_options);
    ffi_it_mod.addObjectFile(.{ .cwd_relative = prover_library });
    if (gpu_prover and gpu_backend == .opencl) ffi_it_mod.linkSystemLibrary("OpenCL", .{});
    if (gpu_prover) {
        // Wrap this toolchain's runner so allocator/leak checks and error-log
        // handling stay identical, while the process obeys native stack admission.
        ffi_it_mod.addImport("standard_test_runner", b.createModule(.{
            .root_source_file = .{ .cwd_relative = b.graph.zig_lib_directory.join(b.allocator, &.{ "compiler", "test_runner.zig" }) catch @panic("out of memory") },
            .target = target,
            .optimize = optimize,
        }));
    }
    const ffi_it = b.addTest(.{
        .name = "lattica-ffi-tests",
        .root_module = ffi_it_mod,
        .test_runner = if (gpu_prover) .{ .path = b.path("src/gpu_test_runner.zig"), .mode = .simple } else null,
    });
    if (gpu_prover) ffi_it.stack_size = 8 << 20;
    if (target.result.os.tag == .linux) {
        ffi_it_mod.linkSystemLibrary("unwind", .{});
        // The self-hosted ELF linker can't handle crt1.o's .sframe (gcc 16).
        // Zig's LLD mode does not support Mach-O; keep macOS on its default linker.
        ffi_it.use_lld = true;
    }
    // Foreign libraries write directly to process stdio. Run the FFI tests as a
    // standalone process; the server-protocol runner stalled on the GPU path.
    const run_ffi_it = std.Build.Step.Run.create(b, "run native FFI tests");
    run_ffi_it.addArtifactArg(ffi_it);
    run_ffi_it.stdio = .inherit;
    const ffi_step = b.step("test-ffi", "FFI integration test (run cargo build --release in lattica-prover-p3 first)");
    ffi_step.dependOn(&run_ffi_it.step);
    const install_ffi = b.addInstallFileWithDir(ffi_it.getEmittedBin(), .bin, "lattica-ffi-tests");
    ffi_step.dependOn(&install_ffi.step);
    b.step("build-ffi", "Build FFI tests for execution in a separately admitted worker")
        .dependOn(&install_ffi.step);
}
