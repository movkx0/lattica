//! Research ordered-selection and grouped-eight expected-statement calculator.
//! Pure native Zig commitment arithmetic; no Rust linking, proof verification,
//! key registration, private witnesses, aggregate proof or job-directory reads.
//! The caller supplies the approved profile, chain, and ordered public inputs.
const std = @import("std");
const commitment = @import("commitment");

const FIELD_COUNT: usize = 26;
const COUNT: usize = 8;
const MODULUS: u64 = 0xffff_ffff_0000_0001;
const Public = [FIELD_COUNT]u64;
const Publics = [COUNT]Public;
const HexError = error{ InvalidLength, InvalidHex, NonCanonicalField };

fn nibble(c: u8) HexError!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHex,
    };
}

fn parseHex(comptime size: usize, text: []const u8) HexError![size]u8 {
    if (text.len != size * 2) return error.InvalidLength;
    var bytes: [size]u8 = undefined;
    for (&bytes, 0..) |*byte, index| {
        byte.* = ((try nibble(text[2 * index])) << 4) | try nibble(text[2 * index + 1]);
    }
    return bytes;
}

fn hex(comptime size: usize, bytes: [size]u8) [size * 2]u8 {
    const digits = "0123456789abcdef";
    var out: [size * 2]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        out[2 * index] = digits[byte >> 4];
        out[2 * index + 1] = digits[byte & 15];
    }
    return out;
}

fn parsePublic(text: []const u8) HexError!Public {
    const bytes = try parseHex(FIELD_COUNT * 8, text);
    var values: Public = undefined;
    for (&values, 0..) |*value, index| {
        value.* = std.mem.readInt(u64, bytes[index * 8 ..][0..8], .little);
        if (value.* >= MODULUS) return error.NonCanonicalField;
    }
    return values;
}

fn derive(context: commitment.Context, public: Publics) !commitment.NodeSummary {
    var nodes: [COUNT]commitment.NodeSummary = undefined;
    for (public, 0..) |row, index| {
        nodes[index] = try commitment.leaf(context, .{
            .kind = .join_split,
            .statement_digest = try commitment.statementDigest(1, &row),
        });
    }
    var width: usize = COUNT;
    while (width > 1) : (width /= 2) {
        for (0..width / 2) |index| {
            nodes[index] = try commitment.mergeNodes(nodes[2 * index], nodes[2 * index + 1]);
        }
    }
    // Deliberately do NOT call commitment.root(), which pads to level six.
    if (nodes[0].level != 3 or nodes[0].count != 8) return error.UnexpectedSubtree;
    return nodes[0];
}

const RootKind = enum { subtree_eight, padded_eight };

fn derivePadded(context: commitment.Context, public: Publics) !commitment.NodeSummary {
    var entries: [COUNT]commitment.Entry = undefined;
    for (public, 0..) |row, index| entries[index] = .{
        .kind = .join_split,
        .statement_digest = try commitment.statementDigest(1, &row),
    };
    return .{ .context = context, .level = commitment.DEPTH, .count = COUNT, .root = try commitment.root(context, &entries) };
}

fn arguments(args: []const []const u8) !struct { kind: RootKind, context: commitment.Context, public: Publics } {
    if (args.len != 12) return error.InvalidArguments;
    const kind: RootKind = if (std.mem.eql(u8, args[1], "root-eight"))
        .subtree_eight
    else if (std.mem.eql(u8, args[1], "root-padded-eight"))
        .padded_eight
    else
        return error.InvalidArguments;
    const context = commitment.Context{
        .profile_id = try parseHex(32, args[2]),
        .chain_id = try parseHex(32, args[3]),
    };
    var public: Publics = undefined;
    for (&public, 0..) |*row, index| row.* = try parsePublic(args[4 + index]);
    return .{ .kind = kind, .context = context, .public = public };
}

/// Generic dense-prefix research selection. The host supplies the exact order.
fn deriveSelection(context: commitment.Context, public: []const Public) !commitment.NodeSummary {
    if (public.len == 0 or public.len > commitment.CAPACITY) return error.InvalidCount;
    var entries: [commitment.CAPACITY]commitment.Entry = undefined;
    for (public, 0..) |row, index| {
        entries[index] = .{ .kind = .join_split, .statement_digest = try commitment.statementDigest(1, &row) };
    }
    return .{ .context = context, .level = commitment.DEPTH, .count = @intCast(public.len), .root = try commitment.root(context, entries[0..public.len]) };
}

fn selectionArguments(args: []const []const u8) !commitment.NodeSummary {
    if (args.len < 5 or args.len > commitment.CAPACITY + 4 or !std.mem.eql(u8, args[1], "root-padded"))
        return error.InvalidArguments;
    const context = commitment.Context{ .profile_id = try parseHex(32, args[2]), .chain_id = try parseHex(32, args[3]) };
    var public: [commitment.CAPACITY]Public = undefined;
    for (args[4..], 0..) |value, index| public[index] = try parsePublic(value);
    return deriveSelection(context, public[0 .. args.len - 4]);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const node = if (args.len >= 2 and std.mem.eql(u8, args[1], "root-padded"))
        try selectionArguments(args)
    else legacy: {
        const input = try arguments(args);
        break :legacy switch (input.kind) {
            .subtree_eight => try derive(input.context, input.public),
            .padded_eight => try derivePadded(input.context, input.public),
        };
    };
    const root_hex = hex(32, try commitment.digestBytes(node.root));
    const profile_hex = hex(32, node.context.profile_id);
    const chain_hex = hex(32, node.context.chain_id);
    var buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    try output.interface.print(
        "grouped_expected_statement mode=3 level={d} count={d} profile={s} chain={s} root={s} native_zig=true proof_verified=false registry_approved=false level6_qualified=false production_ready=false\n",
        .{ node.level, node.count, profile_hex, chain_hex, root_hex },
    );
    try output.interface.flush();
}

// Native arithmetic/codec tests. None creates or verifies a wallet/recursive proof.
fn fixture() Publics {
    var values: Publics = undefined;
    for (&values, 0..) |*row, index| {
        for (row, 0..) |*value, slot| value.* = @intCast(index * FIELD_COUNT + slot + 1);
    }
    return values;
}

fn contextFixture() commitment.Context {
    return .{ .profile_id = [_]u8{0x11} ** 32, .chain_id = [_]u8{0x22} ** 32 };
}

test "identifiers require exact ASCII hex and preserve arbitrary bytes" {
    try std.testing.expectEqual([_]u8{0xff} ** 32, try parseHex(32, &([_]u8{'f'} ** 64)));
    try std.testing.expectError(error.InvalidLength, parseHex(32, "00"));
    try std.testing.expectError(error.InvalidHex, parseHex(1, "z0"));
    try std.testing.expectError(error.InvalidHex, parseHex(1, "é"));
}

test "public fields are exactly 26 canonical LE u64 values" {
    var bytes = [_]u8{0} ** (FIELD_COUNT * 8);
    std.mem.writeInt(u64, bytes[0..8], 1, .little);
    std.mem.writeInt(u64, bytes[200..208], MODULUS - 1, .little);
    const fields = try parsePublic(&hex(FIELD_COUNT * 8, bytes));
    try std.testing.expectEqual(@as(u64, 1), fields[0]);
    try std.testing.expectEqual(MODULUS - 1, fields[25]);
    std.mem.writeInt(u64, bytes[8..16], MODULUS, .little);
    try std.testing.expectError(error.NonCanonicalField, parsePublic(&hex(FIELD_COUNT * 8, bytes)));
    try std.testing.expectError(error.InvalidLength, parsePublic("00"));
}

test "root codec is canonical little endian" {
    const root = commitment.Digest{ 1, 2, 3, 4 };
    const encoded = hex(32, try commitment.digestBytes(root));
    try std.testing.expectEqualStrings("0100000000000000020000000000000003000000000000000400000000000000", &encoded);
}

test "expected subtree is level three not a padded production block" {
    const values = fixture();
    const context = contextFixture();
    const node = try derive(context, values);
    try std.testing.expectEqual(@as(u8, 3), node.level);
    try std.testing.expectEqual(@as(u8, 8), node.count);
    var entries: [COUNT]commitment.Entry = undefined;
    for (&entries, 0..) |*entry, index| entry.* = .{
        .kind = .join_split,
        .statement_digest = try commitment.statementDigest(1, &values[index]),
    };
    const padded = try commitment.root(context, &entries);
    try std.testing.expect(!std.mem.eql(u64, &node.root, &padded));
}

test "all eight public statements their order and both context IDs bind the root" {
    const context = contextFixture();
    const values = fixture();
    const original = (try derive(context, values)).root;
    for (0..COUNT) |index| {
        var changed = values;
        changed[index][25] += 1;
        const root = (try derive(context, changed)).root;
        try std.testing.expect(!std.mem.eql(u64, &original, &root));
    }
    var swapped = values;
    std.mem.swap(Public, &swapped[0], &swapped[1]);
    const reordered = (try derive(context, swapped)).root;
    try std.testing.expect(!std.mem.eql(u64, &original, &reordered));
    var other = context;
    other.profile_id[0] ^= 1;
    const profile_root = (try derive(other, values)).root;
    try std.testing.expect(!std.mem.eql(u64, &original, &profile_root));
    other = context;
    other.chain_id[0] ^= 1;
    const chain_root = (try derive(other, values)).root;
    try std.testing.expect(!std.mem.eql(u64, &original, &chain_root));
}

test "missing or extra arguments cannot default the expected context" {
    try std.testing.expectError(error.InvalidArguments, arguments(&.{}));
    try std.testing.expectError(error.InvalidArguments, arguments(&.{ "tool", "root-eight" }));
    const extra = [_][]const u8{"tool"} ** 13;
    try std.testing.expectError(error.InvalidArguments, arguments(&extra));
}

test "padded-eight is level six and matches ordered empty-subtree extension" {
    const context = contextFixture();
    const values = fixture();
    var extended = try derive(context, values);
    while (extended.level < commitment.DEPTH) {
        extended = try commitment.mergeNodes(extended, try commitment.emptySubtree(context, extended.level));
    }
    const padded = try derivePadded(context, values);
    try std.testing.expectEqual(@as(u8, 6), padded.level);
    try std.testing.expectEqual(@as(u8, 8), padded.count);
    try std.testing.expectEqualDeep(extended, padded);
    const left_empty = try commitment.emptySubtree(context, 3);
    try std.testing.expectError(error.NonDensePrefix, commitment.mergeNodes(left_empty, try derive(context, values)));
}

test "both explicit root commands bind all eight canonical public inputs" {
    const public_hex = hex(FIELD_COUNT * 8, [_]u8{0} ** (FIELD_COUNT * 8));
    const id = "11" ** 32;
    var args = [_][]const u8{ "tool", "root-padded-eight", id, id, &public_hex, &public_hex, &public_hex, &public_hex, &public_hex, &public_hex, &public_hex, &public_hex };
    try std.testing.expectEqual(RootKind.padded_eight, (try arguments(&args)).kind);
    args[1] = "root-eight";
    try std.testing.expectEqual(RootKind.subtree_eight, (try arguments(&args)).kind);
    args[1] = "root";
    try std.testing.expectError(error.InvalidArguments, arguments(&args));
    args[1] = "root-padded-eight";
    args[11] = "00";
    try std.testing.expectError(error.InvalidLength, arguments(&args));
}

test "generic padded selection covers every count without changing eight alias" {
    var rows: [commitment.CAPACITY]Public = undefined;
    for (&rows, 0..) |*row, index| {
        for (row, 0..) |*field, field_index| field.* = @intCast(index * FIELD_COUNT + field_index + 1);
    }
    for (1..commitment.CAPACITY + 1) |count| {
        const node = try deriveSelection(contextFixture(), rows[0..count]);
        try std.testing.expectEqual(@as(u8, 6), node.level);
        try std.testing.expectEqual(@as(u8, @intCast(count)), node.count);
        if (count == COUNT) try std.testing.expectEqualDeep(try derivePadded(contextFixture(), rows[0..COUNT].*), node);
    }
    try std.testing.expectError(error.InvalidCount, deriveSelection(contextFixture(), &.{}));
    const oversized = [_]Public{rows[0]} ** (commitment.CAPACITY + 1);
    try std.testing.expectError(error.InvalidCount, deriveSelection(contextFixture(), &oversized));
    const before = try deriveSelection(contextFixture(), rows[0..3]);
    std.mem.swap(Public, &rows[0], &rows[1]);
    const after = try deriveSelection(contextFixture(), rows[0..3]);
    try std.testing.expect(!std.mem.eql(u64, &before.root, &after.root));
}

test "generic selection arguments require one to 64 canonical public statements" {
    const zero = hex(FIELD_COUNT * 8, [_]u8{0} ** (FIELD_COUNT * 8));
    const id = "11" ** 32;
    try std.testing.expectError(error.InvalidArguments, selectionArguments(&.{}));
    try std.testing.expectError(error.InvalidArguments, selectionArguments(&.{ "tool", "root-padded", id, id }));
    try std.testing.expectEqual(@as(u8, 1), (try selectionArguments(&.{ "tool", "root-padded", id, id, &zero })).count);
    try std.testing.expectError(error.InvalidLength, selectionArguments(&.{ "tool", "root-padded", id, id, "00" }));
    const too_many = [_][]const u8{"tool"} ** (commitment.CAPACITY + 5);
    try std.testing.expectError(error.InvalidArguments, selectionArguments(&too_many));
}
