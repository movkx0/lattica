//! GPU process root for the native integration harness.
//! Keep CPU integration on its existing root and standard Zig options.
pub const std_options = @import("gpu_process_options.zig").std_options;

comptime {
    _ = @import("integration_node.zig");
}
