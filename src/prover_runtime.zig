//! Process startup/teardown for the native GPU wallet prover.
//!
//! Configure the environment before initialization and join all proving work
//! before shutdown. This control-plane API owns the process's five wallet/tree
//! proving registrations; call it from one startup/teardown thread. Rust admits
//! wallet-owned local assignments. Recursive delivery and network tree-format
//! selection remain separate; startup does not register a tree verifier.
const std = @import("std");
const abi = @import("prover_abi.zig");
const ffi = @import("ffi.zig");

const Native = struct {
    extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

    fn policy() ?[]const u8 {
        const value = getenv("LATTICA_PROVING_POLICY") orelse return null;
        return std.mem.span(value);
    }

    const initialize = abi.lattica_gpu_initialize_from_env;
    const drain = abi.lattica_gpu_drain;
    const shutdown = abi.lattica_gpu_shutdown;

    fn install() void {
        ffi.setJoinSplitProveBackend(&abi.lattica_joinsplit_prove);
        ffi.setJoinSplitBackend(&abi.lattica_joinsplit_verify);
        ffi.setHtlcProveBackend(&abi.lattica_htlc_prove);
        ffi.setHtlcBackend(&abi.lattica_htlc_verify);
        ffi.setBatchProveBackend(&abi.lattica_batch_prove);
        ffi.setBatchBackend(&abi.lattica_batch_verify);
        ffi.setHtlcBatchProveBackend(&abi.lattica_htlc_batch_prove);
        ffi.setHtlcBatchBackend(&abi.lattica_htlc_batch_verify);
        ffi.setJoinSplitTreeProveBackend(&abi.lattica_joinsplit_tree_prove);
    }

    fn clearProvers() void {
        ffi.clearJoinSplitProveBackend();
        ffi.clearHtlcProveBackend();
        ffi.clearBatchProveBackend();
        ffi.clearHtlcBatchProveBackend();
        ffi.clearJoinSplitTreeProveBackend();
        // CPU verifiers remain available for already serialized proofs.
    }
};

pub const Gpu = Lifecycle(Native);

// A public worker initializes only the backend. Its pinned protocol/session
// supplies public proof jobs; startup installs no wallet or verifier callbacks.
const PublicNative = struct {
    const policy = Native.policy;
    const initialize = abi.lattica_gpu_public_worker_initialize_from_env;
    const drain = abi.lattica_gpu_drain;
    const shutdown = abi.lattica_gpu_shutdown;

    fn install() void {}
    fn clearProvers() void {}
};

pub const PublicGpuWorker = Lifecycle(PublicNative);

/// Blocking public service in a fresh process; do not initialize first. Uses
/// the existing typed worker protocol and a trusted, independently pinned
/// bootstrap. Keeps the caller's socket descriptor; grants no wallet/registry
/// authority. The caller must exit after return so the supervisor can release
/// reservations. No concurrent socket I/O or bootstrap mutation is permitted.
pub fn servePublicGpuWorker(socket_fd: i32, bootstrap: []const u8) !u64 {
    var completed: u64 = 0;
    try status(abi.lattica_gpu_public_worker_serve(socket_fd, bootstrap.ptr, bootstrap.len, &completed));
    return completed;
}

/// Only the transfer demo proves. Scanning, key generation and hashing need no
/// GPU. A strict proving request must never run the default mock transfer demo.
pub fn gpuForCommand(linked: bool, command: []const u8, policy: ?[]const u8) !bool {
    if (!std.mem.eql(u8, command, "demo")) return false;
    if (!linked) {
        if (policy) |value| {
            if (!std.mem.eql(u8, value, "compatible")) return error.NativeProverNotLinked;
        }
        return false;
    }
    const value = policy orelse return error.GpuPolicyRequired;
    if (!std.mem.eql(u8, value, "gpu-required")) return error.GpuPolicyRequired;
    return true;
}

pub fn gpuRequiredFromEnv() bool {
    const policy = Native.policy() orelse return false;
    return std.mem.eql(u8, policy, "gpu-required");
}

fn status(code: i32) !void {
    return switch (code) {
        abi.GPU_OK => {},
        abi.GPU_REJECTED => error.GpuRejected,
        abi.GPU_UNAVAILABLE => error.GpuUnavailable,
        else => error.GpuLifecycleProtocol,
    };
}

fn Lifecycle(comptime Backend: type) type {
    return struct {
        var initialized = false;

        pub fn initialize() !void {
            if (initialized) return error.GpuAlreadyInitialized;
            const policy = Backend.policy() orelse return error.GpuPolicyRequired;
            if (!std.mem.eql(u8, policy, "gpu-required")) return error.GpuPolicyRequired;
            try status(Backend.initialize());
            Backend.install();
            initialized = true;
        }

        pub fn drain() !void {
            if (!initialized) return error.GpuNotInitialized;
            try status(Backend.drain());
        }

        pub fn shutdown() !void {
            if (!initialized) return;
            // A refused shutdown leaves the live engine and registrations usable.
            try status(Backend.shutdown());
            Backend.clearProvers();
            initialized = false;
        }
    };
}

test "strict wallet proving never selects mocks and non-proving commands need no GPU" {
    try std.testing.expectError(error.NativeProverNotLinked, gpuForCommand(false, "demo", "gpu-required"));
    try std.testing.expectError(error.NativeProverNotLinked, gpuForCommand(false, "demo", "cpu-required"));
    try std.testing.expectError(error.NativeProverNotLinked, gpuForCommand(false, "demo", "gpu_required"));
    try std.testing.expect(!(try gpuForCommand(false, "demo", null)));
    try std.testing.expect(!(try gpuForCommand(false, "demo", "compatible")));
    try std.testing.expectError(error.GpuPolicyRequired, gpuForCommand(true, "demo", null));
    try std.testing.expectError(error.GpuPolicyRequired, gpuForCommand(true, "demo", "compatible"));
    try std.testing.expectError(error.GpuPolicyRequired, gpuForCommand(true, "demo", "cpu-required"));
    try std.testing.expect(try gpuForCommand(true, "demo", "gpu-required"));
    for ([_][]const u8{ "exchange", "keygen", "bench" }) |command| {
        try std.testing.expect(!(try gpuForCommand(true, command, null)));
        try std.testing.expect(!(try gpuForCommand(false, command, "gpu-required")));
    }
}

test "GPU runtime installs only after strict policy and successful initialization" {
    const Fake = struct {
        var policy_value: ?[]const u8 = null;
        var result: i32 = abi.GPU_OK;
        var initializations: usize = 0;
        var installs: usize = 0;
        var clears: usize = 0;
        fn policy() ?[]const u8 {
            return policy_value;
        }
        fn initialize() i32 {
            initializations += 1;
            return result;
        }
        fn shutdown() i32 {
            return abi.GPU_OK;
        }
        fn install() void {
            installs += 1;
        }
        fn clearProvers() void {
            clears += 1;
        }
    };
    const Runtime = Lifecycle(Fake);
    try std.testing.expectError(error.GpuPolicyRequired, Runtime.initialize());
    for ([_][]const u8{ "compatible", "cpu-required", "gpu_required", "" }) |policy| {
        Fake.policy_value = policy;
        try std.testing.expectError(error.GpuPolicyRequired, Runtime.initialize());
    }
    try std.testing.expectEqual(@as(usize, 0), Fake.initializations);
    Fake.policy_value = "gpu-required";
    Fake.result = abi.GPU_UNAVAILABLE;
    try std.testing.expectError(error.GpuUnavailable, Runtime.initialize());
    Fake.result = abi.GPU_REJECTED;
    try std.testing.expectError(error.GpuRejected, Runtime.initialize());
    Fake.result = 99;
    try std.testing.expectError(error.GpuLifecycleProtocol, Runtime.initialize());
    try Runtime.shutdown();
    try std.testing.expectEqual(@as(usize, 0), Fake.installs);
    try std.testing.expectEqual(@as(usize, 0), Fake.clears);
    Fake.result = abi.GPU_OK;
    try Runtime.initialize();
    try std.testing.expectError(error.GpuAlreadyInitialized, Runtime.initialize());
    try std.testing.expectEqual(@as(usize, 4), Fake.initializations);
    try Runtime.shutdown();
    try std.testing.expectEqual(@as(usize, 1), Fake.installs);
    try std.testing.expectEqual(@as(usize, 1), Fake.clears);
}

test "GPU runtime retains registrations on failed drain or shutdown and permits reinitialization" {
    const Fake = struct {
        var result: i32 = abi.GPU_OK;
        var clears: usize = 0;
        var drains: usize = 0;
        var shutdowns: usize = 0;
        fn policy() ?[]const u8 {
            return "gpu-required";
        }
        fn initialize() i32 {
            return abi.GPU_OK;
        }
        fn drain() i32 {
            drains += 1;
            return result;
        }
        fn shutdown() i32 {
            shutdowns += 1;
            return result;
        }
        fn install() void {}
        fn clearProvers() void {
            clears += 1;
        }
    };
    const Runtime = Lifecycle(Fake);
    try std.testing.expectError(error.GpuNotInitialized, Runtime.drain());
    try std.testing.expectEqual(@as(usize, 0), Fake.drains);
    try Runtime.initialize();
    Fake.result = abi.GPU_REJECTED;
    try std.testing.expectError(error.GpuRejected, Runtime.drain());
    try std.testing.expectError(error.GpuRejected, Runtime.shutdown());
    try std.testing.expectEqual(@as(usize, 0), Fake.clears);
    try std.testing.expectError(error.GpuAlreadyInitialized, Runtime.initialize());
    Fake.result = abi.GPU_OK;
    try Runtime.drain();
    try Runtime.shutdown();
    try Runtime.shutdown();
    try std.testing.expectEqual(@as(usize, 2), Fake.shutdowns);
    try std.testing.expectEqual(@as(usize, 1), Fake.clears);
    try std.testing.expectError(error.GpuNotInitialized, Runtime.drain());
    try Runtime.initialize();
    try Runtime.shutdown();
    try std.testing.expectEqual(@as(usize, 2), Fake.clears);
}
