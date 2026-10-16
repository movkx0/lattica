//! Compile-time block profile, shared by native commitment and host validation.
//! Roots without an explicit selection retain the historical 64-entry profile.
const root = @import("root");
pub const CAPACITY: usize = if (@hasDecl(root, "lattica_block_capacity")) root.lattica_block_capacity else 64;
pub const DEPTH: u8 = @intCast(@ctz(CAPACITY));
pub const PLANNED_CAPACITIES = [_]usize{ 256, 512 };
comptime {
    if (CAPACITY != 64 and CAPACITY != 128)
        @compileError("supported block capacities are 64 and 128; 256/512 require count-codec and profile qualification");
}
