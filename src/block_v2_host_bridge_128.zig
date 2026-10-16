//! Native host for the separate Rust block-v2-capacity-128 research profile.
pub const lattica_block_capacity: usize = 128;
comptime {
    _ = @import("block_v2_host_bridge.zig");
}
