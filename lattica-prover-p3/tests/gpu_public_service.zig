const std = @import("std");
const runtime = @import("prover_runtime");

test "native public service rejects invalid descriptor and empty bootstrap" {
    try std.testing.expectError(error.GpuRejected, runtime.servePublicGpuWorker(-1, "{}"));
    try std.testing.expectError(error.GpuRejected, runtime.servePublicGpuWorker(0, ""));
}
