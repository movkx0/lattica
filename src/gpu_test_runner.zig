//! Use Zig's complete runner with the native GPU worker's bounded signal stack.
//! A test module's std_options do not configure the runner's process root.
const std = @import("std");
const runner = @import("standard_test_runner");

pub const std_options: std.Options = options: {
    var value = @import("gpu_process_options.zig").std_options;
    value.logFn = runner.log;
    break :options value;
};

pub const main = runner.main;
pub const fuzz = runner.fuzz;
