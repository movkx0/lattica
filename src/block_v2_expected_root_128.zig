//! Depth-seven ordered-root calculator; pair with a 128-transaction Rust profile.
pub const lattica_block_capacity: usize = 128;
pub const main = @import("block_v2_expected_root.zig").main;
test {
    _ = @import("block_v2_expected_root.zig");
}
