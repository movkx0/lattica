const std = @import("std");
const runtime = @import("prover_runtime");

test "native public worker lifecycle is separate from wallet registration" {
    try std.testing.expectError(error.GpuRejected, runtime.Gpu.initialize());
    try runtime.PublicGpuWorker.initialize();
    errdefer runtime.PublicGpuWorker.shutdown() catch {};
    try std.testing.expectError(error.GpuAlreadyInitialized, runtime.PublicGpuWorker.initialize());
    try std.testing.expectError(error.GpuNotInitialized, runtime.Gpu.drain());
    try runtime.PublicGpuWorker.drain();
    try runtime.PublicGpuWorker.shutdown();
    try std.testing.expectError(error.GpuNotInitialized, runtime.PublicGpuWorker.drain());
    // A subsequent worker needs a fresh process and its own resource admission.
    try std.testing.expectError(error.GpuRejected, runtime.PublicGpuWorker.initialize());
}
