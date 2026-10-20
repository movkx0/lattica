//! Process-root options shared by native GPU executables and their test runner.
const std = @import("std");

// The admitted native caller reserves at most 64 KiB for its alternate signal
// stack. Zig's default stack-tracing signal handler needs a larger stack, so GPU
// hosts use the OS fatal-signal behavior while retaining ordinary panic reports
// and runtime safety checks. CPU hosts keep the standard Zig configuration.
pub const std_options: std.Options = .{
    .signal_stack_size = 64 << 10,
    .enable_segfault_handler = false,
};
