//! Candidate v2 ordered transaction commitment; NOT recursive proof verification.
//!
//! Matches lattica-prover-p3/src/block_v2/commitment.rs. This is a native hashing/
//! codec foundation, not a block wire format or a production-ready proof path.
//! Statements must be derived/verified by the caller. NodeSummary helpers check
//! structure, not proof authority: a nonempty root does not authenticate its
//! claimed count or context without its leaves (or a future constrained proof).

const std = @import("std");
const field = @import("field.zig");
const poseidon2 = @import("poseidon2.zig");

pub const Digest = [4]u64;
pub const CAPACITY: usize = 64;
pub const DEPTH: u8 = 6;
pub const LEAF: u64 = 0x4c42563201;
pub const EMPTY: u64 = 0x4c42563202;
pub const NODE: u64 = 0x4c42563203;
pub const STATEMENT: u64 = 0x4c42563204;

pub const Error = error{
    InvalidLength,
    InvalidKind,
    NonCanonicalField,
    EmptyBlock,
    TooManyEntries,
    InvalidLevel,
    InvalidCount,
    ContextMismatch,
    LevelMismatch,
    NonDensePrefix,
    InvalidEmptyRoot,
};

pub const Context = struct {
    /// Caller-supplied profile bytes; this module does not register or approve
    /// a consensus profile identity (a candidate label is only a label).
    profile_id: [32]u8,
    chain_id: [32]u8,

    /// Injective encoding: profile's eight LE u32 limbs, then chain's eight.
    /// Arbitrary identifiers are NOT reduced modulo Goldilocks.
    pub fn toFields(self: Context) [16]u64 {
        var fields: [16]u64 = undefined;
        inline for (0..8) |i| {
            fields[i] = std.mem.readInt(u32, self.profile_id[i * 4 ..][0..4], .little);
            fields[8 + i] = std.mem.readInt(u32, self.chain_id[i * 4 ..][0..4], .little);
        }
        return fields;
    }

    pub fn eql(self: Context, other: Context) bool {
        return std.mem.eql(u8, &self.profile_id, &other.profile_id) and
            std.mem.eql(u8, &self.chain_id, &other.chain_id);
    }
};

pub const Kind = enum(u8) {
    join_split = 1,
    htlc = 2,
    coinbase = 3,

    pub fn fromCode(code: u8) Error!Kind {
        return switch (code) {
            1 => .join_split,
            2 => .htlc,
            3 => .coinbase,
            else => error.InvalidKind,
        };
    }
};

pub const Entry = struct {
    kind: Kind,
    statement_digest: Digest,

    pub fn init(kind: u8, statement_digest: Digest) Error!Entry {
        const parsed = try Kind.fromCode(kind);
        try validateFields(&statement_digest);
        return .{ .kind = parsed, .statement_digest = statement_digest };
    }

    /// Local fixed-width codec: one kind byte followed by four LE u64 limbs.
    /// Not a transaction/block encoding. Rejects short and trailing data.
    pub fn fromBytes(bytes: []const u8) Error!Entry {
        if (bytes.len != 33) return error.InvalidLength;
        const kind = try Kind.fromCode(bytes[0]);
        return .{ .kind = kind, .statement_digest = try digestFromBytes(bytes[1..]) };
    }

    pub fn toBytes(self: Entry) Error![33]u8 {
        var bytes: [33]u8 = undefined;
        bytes[0] = @intFromEnum(self.kind);
        bytes[1..].* = try digestBytes(self.statement_digest);
        return bytes;
    }
};

/// Reject, never reduce, noncanonical statement/root limbs.
pub fn digestFromBytes(bytes: []const u8) Error!Digest {
    if (bytes.len != 32) return error.InvalidLength;
    var digest: Digest = undefined;
    inline for (0..4) |i| digest[i] = std.mem.readInt(u64, bytes[i * 8 ..][0..8], .little);
    try validateFields(&digest);
    return digest;
}

pub fn digestBytes(digest: Digest) Error![32]u8 {
    try validateFields(&digest);
    return poseidon2.digestBytes(digest);
}

fn validateFields(fields: []const u64) Error!void {
    for (fields) |x| if (x >= field.P) return error.NonCanonicalField;
}

/// Initialize [domain, len, 0, 0], then compress each zero-padded four-field
/// chunk with native Poseidon2(state || chunk)[0..4]. An empty input performs
/// no permutations; the length lane distinguishes trailing zero fields.
pub fn hashFields(domain: u64, fields: []const u64) Error!Digest {
    if (domain >= field.P) return error.NonCanonicalField;
    if (@as(u128, fields.len) >= field.P) return error.InvalidLength;
    try validateFields(fields);
    var state = Digest{ domain, @intCast(fields.len), 0, 0 };
    var offset: usize = 0;
    while (offset < fields.len) {
        var chunk = Digest{ 0, 0, 0, 0 };
        const n = @min(4, fields.len - offset);
        @memcpy(chunk[0..n], fields[offset..][0..n]);
        state = poseidon2.merge(state, chunk);
        offset += n;
    }
    return state;
}

/// Native summary only, NOT evidence of valid transactions or child proofs.
/// Merge checks all supplied metadata. In-range nonempty counts cannot be
/// authenticated from opaque roots: future AIR must constrain their derivation.
/// Hashes canonical public fields; does not validate the type schema or proof.
pub fn statementDigest(kind_code: u8, public_fields: []const u64) Error!Digest {
    const kind = try Kind.fromCode(kind_code);
    return hashFields(STATEMENT + @intFromEnum(kind), public_fields);
}

test "block v2: canonical statement digest Rust known answer" {
    const fields = [_]u64{ 0, 1, field.P - 1, 7, 99 };
    const digest = try statementDigest(1, &fields);
    try std.testing.expectEqual(Digest{ 12972822681639718207, 2119591620538778127, 17220032490829815117, 9009558452664936917 }, digest);
    try std.testing.expect(!std.mem.eql(u64, &digest, &(try statementDigest(2, &fields))));
    try std.testing.expect(!std.mem.eql(u64, &digest, &(try statementDigest(1, fields[0..4]))));
    try std.testing.expectError(error.InvalidKind, statementDigest(0, &fields));
    try std.testing.expectError(error.NonCanonicalField, statementDigest(1, &.{field.P}));
}

pub const NodeSummary = struct {
    context: Context,
    level: u8, // leaf = 0, block root = 6
    count: u8,
    root: Digest,
};

pub fn leaf(context: Context, entry: Entry) Error!NodeSummary {
    try validateFields(&entry.statement_digest);
    var fields: [21]u64 = undefined;
    fields[0..16].* = context.toFields();
    fields[16] = @intFromEnum(entry.kind);
    fields[17..21].* = entry.statement_digest;
    return .{ .context = context, .level = 0, .count = 1, .root = try hashFields(LEAF, &fields) };
}

fn levelCapacity(level: u8) Error!u8 {
    if (level > DEPTH) return error.InvalidLevel;
    return @as(u8, 1) << @as(u3, @intCast(level));
}

/// Only called for locally constructed or validated compatible children.
fn parent(left: NodeSummary, right: NodeSummary) Error!NodeSummary {
    const level = left.level + 1;
    const fields = [_]u64{
        level,         left.count,    right.count,
        left.root[0],  left.root[1],  left.root[2],
        left.root[3],  right.root[0], right.root[1],
        right.root[2], right.root[3],
    };
    return .{
        .context = left.context,
        .level = level,
        .count = left.count + right.count,
        .root = try hashFields(NODE, &fields),
    };
}

/// Canonical padding ONLY. Even level 6 is not an accepted transaction block.
pub fn emptySubtree(context: Context, level: u8) Error!NodeSummary {
    _ = try levelCapacity(level);
    const fields = context.toFields();
    var node = NodeSummary{ .context = context, .level = 0, .count = 0, .root = try hashFields(EMPTY, &fields) };
    for (0..level) |_| node = try parent(node, node);
    return node;
}

/// Structural validation, not proof verification. Also authenticates the
/// canonical empty root when count == 0; no arbitrary padding is accepted.
pub fn validateSummary(node: NodeSummary) Error!void {
    const capacity = try levelCapacity(node.level);
    if (node.count > capacity) return error.InvalidCount;
    try validateFields(&node.root);
    if (node.count == 0) {
        const expected = try emptySubtree(node.context, node.level);
        if (!std.mem.eql(u64, &node.root, &expected.root)) return error.InvalidEmptyRoot;
    }
}

/// Validates child metadata and derives the parent count; no caller-supplied
/// parent count. A nonempty right child requires a completely full left child.
/// This native helper MUST NOT be used as recursive proof authority.
pub fn mergeNodes(left: NodeSummary, right: NodeSummary) Error!NodeSummary {
    try validateSummary(left);
    try validateSummary(right);
    if (!left.context.eql(right.context)) return error.ContextMismatch;
    if (left.level != right.level) return error.LevelMismatch;
    if (left.level == DEPTH) return error.InvalidLevel;
    if (right.count > 0 and left.count != try levelCapacity(left.level)) return error.NonDensePrefix;
    return parent(left, right);
}

/// Pure fixed-depth ordered root, derived solely from 1..64 actual entries.
/// Entries occupy a dense left prefix; all remaining leaves are canonical empty
/// padding. Does not validate the transactions represented by the statements.
pub fn root(context: Context, entries: []const Entry) Error!Digest {
    if (entries.len == 0) return error.EmptyBlock;
    if (entries.len > CAPACITY) return error.TooManyEntries;
    const empty = try emptySubtree(context, 0);
    var nodes: [CAPACITY]NodeSummary = undefined;
    for (entries, 0..) |entry, i| nodes[i] = try leaf(context, entry);
    @memset(nodes[entries.len..], empty);
    var width: usize = CAPACITY;
    while (width > 1) : (width /= 2) {
        for (0..width / 2) |i| nodes[i] = try mergeNodes(nodes[2 * i], nodes[2 * i + 1]);
    }
    return nodes[0].root;
}

// Shared cross-language fixtures: profile bytes 0..31, chain bytes 32..63;
// entry i has kind 1 + i % 3 and statement [4*i+1, 4*i+2, 4*i+3, 4*i+4].
fn testContext() Context {
    var context: Context = undefined;
    for (0..32) |i| {
        context.profile_id[i] = @intCast(i);
        context.chain_id[i] = @intCast(i + 32);
    }
    return context;
}

fn testEntries() [CAPACITY]Entry {
    var entries: [CAPACITY]Entry = undefined;
    for (&entries, 0..) |*entry, i| {
        entry.* = .{
            .kind = Kind.fromCode(@intCast(1 + i % 3)) catch unreachable,
            .statement_digest = .{ 4 * i + 1, 4 * i + 2, 4 * i + 3, 4 * i + 4 },
        };
    }
    return entries;
}

const testing = std.testing;

test "block v2: injective context and strict statement codecs" {
    const fields = testContext().toFields();
    for (fields, 0..) |x, i| {
        const b: u64 = @intCast(4 * i);
        try testing.expectEqual(b | ((b + 1) << 8) | ((b + 2) << 16) | ((b + 3) << 24), x);
    }
    const max_context = Context{ .profile_id = @splat(255), .chain_id = @splat(255) };
    for (max_context.toFields()) |x| try testing.expectEqual(@as(u64, 0xffff_ffff), x);
    const digest = Digest{ 0, 1, field.P - 1, 0x0102030405060708 };
    const bytes = try digestBytes(digest);
    try testing.expectEqual(digest, try digestFromBytes(&bytes));
    try testing.expectEqualSlices(u8, &.{ 8, 7, 6, 5, 4, 3, 2, 1 }, bytes[24..]);
    for ([_]u8{ 1, 2, 3 }) |kind| {
        const entry = try Entry.init(kind, digest);
        const encoded = try entry.toBytes();
        try testing.expectEqual(kind, encoded[0]);
        try testing.expectEqualDeep(entry, try Entry.fromBytes(&encoded));
        _ = try root(testContext(), &.{entry});
    }
    for ([_]u8{ 0, 4, 255 }) |kind| {
        try testing.expectError(error.InvalidKind, Entry.init(kind, digest));
        var encoded = [_]u8{0} ** 33;
        encoded[0] = kind;
        try testing.expectError(error.InvalidKind, Entry.fromBytes(&encoded));
    }
    try testing.expectError(error.InvalidLength, digestFromBytes(bytes[0..31]));
    try testing.expectError(error.InvalidLength, digestFromBytes(&([_]u8{0} ** 33)));
    try testing.expectError(error.InvalidLength, Entry.fromBytes(&bytes));
    try testing.expectError(error.InvalidLength, Entry.fromBytes(&([_]u8{0} ** 34)));
    for (0..4) |lane| {
        for ([_]u64{ field.P, field.P + 1, std.math.maxInt(u64) }) |invalid| {
            var bad = digest;
            bad[lane] = invalid;
            var encoded = bytes;
            std.mem.writeInt(u64, encoded[lane * 8 ..][0..8], invalid, .little);
            try testing.expectError(error.NonCanonicalField, digestFromBytes(&encoded));
            var encoded_entry: [33]u8 = undefined;
            encoded_entry[0] = 1;
            encoded_entry[1..].* = encoded;
            try testing.expectError(error.NonCanonicalField, Entry.fromBytes(&encoded_entry));
            try testing.expectError(error.NonCanonicalField, digestBytes(bad));
            try testing.expectError(error.NonCanonicalField, Entry.init(1, bad));
            const entry = Entry{ .kind = .join_split, .statement_digest = bad };
            try testing.expectError(error.NonCanonicalField, entry.toBytes());
            try testing.expectError(error.NonCanonicalField, root(testContext(), &.{entry}));
        }
    }
}

test "block v2: hash domain length and canonicality" {
    try testing.expectEqual(Digest{ LEAF, 0, 0, 0 }, try hashFields(LEAF, &.{}));
    const a = try hashFields(LEAF, &.{1});
    try testing.expect(!std.mem.eql(u64, &a, &(try hashFields(EMPTY, &.{1}))));
    try testing.expect(!std.mem.eql(u64, &a, &(try hashFields(LEAF, &.{ 1, 0 }))));
    try testing.expect(!std.mem.eql(u64, &a, &(try hashFields(LEAF, &.{ 1, 0, 0, 0 }))));
    try testing.expect(!std.mem.eql(u64, &a, &(try hashFields(LEAF, &.{ 1, 0, 0, 0, 0 }))));
    try testing.expectError(error.NonCanonicalField, hashFields(field.P, &.{}));
    try testing.expectError(error.NonCanonicalField, hashFields(LEAF, &.{ 0, 0, 0, 0, field.P }));
}

test "block v2: ordering type digest and both context identifiers bind root" {
    const context = testContext();
    var entries = testEntries();
    const base = try root(context, entries[0..3]);
    std.mem.swap(Entry, &entries[0], &entries[1]);
    try testing.expect(!std.mem.eql(u64, &base, &(try root(context, entries[0..3]))));
    entries = testEntries();
    entries[0].kind = .htlc;
    try testing.expect(!std.mem.eql(u64, &base, &(try root(context, entries[0..3]))));
    entries[0].kind = .coinbase;
    try testing.expect(!std.mem.eql(u64, &base, &(try root(context, entries[0..3]))));
    entries = testEntries();
    entries[0].statement_digest[3] += 1;
    try testing.expect(!std.mem.eql(u64, &base, &(try root(context, entries[0..3]))));
    entries = testEntries();
    for (0..32) |i| {
        var changed = context;
        changed.profile_id[i] ^= 1;
        try testing.expect(!std.mem.eql(u64, &base, &(try root(changed, entries[0..3]))));
        changed = context;
        changed.chain_id[i] ^= 1;
        try testing.expect(!std.mem.eql(u64, &base, &(try root(changed, entries[0..3]))));
    }
    try testing.expect(!std.mem.eql(u64, &base, &(try root(context, entries[0..2]))));
}

test "block v2: padding dense prefix and validated summary metadata" {
    const context = testContext();
    const entries = testEntries();
    const a = try leaf(context, entries[0]);
    const b = try leaf(context, entries[1]);
    const empty = try emptySubtree(context, 0);
    try testing.expect(!std.mem.eql(u64, &empty.root, &(try leaf(context, .{ .kind = .join_split, .statement_digest = @splat(0) })).root));
    var padding = empty;
    for (0..DEPTH) |i| {
        padding = try mergeNodes(padding, padding);
        try testing.expectEqualDeep(try emptySubtree(context, @intCast(i + 1)), padding);
    }
    try testing.expectError(error.NonDensePrefix, mergeNodes(empty, a));
    const partial = try mergeNodes(a, empty);
    try testing.expectError(error.NonDensePrefix, mergeNodes(partial, partial));
    const full = try mergeNodes(a, b);
    const three = try mergeNodes(full, partial);
    try testing.expectEqual(@as(u8, 3), three.count);
    try testing.expectEqual(@as(u8, 2), three.level);
    try testing.expectError(error.LevelMismatch, mergeNodes(a, full));
    var changed = context;
    changed.chain_id[0] ^= 1;
    try testing.expectError(error.ContextMismatch, mergeNodes(a, try leaf(changed, entries[1])));
    try testing.expectError(error.InvalidLevel, mergeNodes(padding, padding));
    try testing.expectError(error.InvalidLevel, emptySubtree(context, 7));
    try testing.expectError(error.InvalidLevel, emptySubtree(context, 255));
    var malformed = a;
    malformed.count = 2;
    try testing.expectError(error.InvalidCount, mergeNodes(malformed, b));
    malformed.count = 255;
    try testing.expectError(error.InvalidCount, validateSummary(malformed));
    malformed = padding;
    malformed.count = 65;
    try testing.expectError(error.InvalidCount, validateSummary(malformed));
    malformed = a;
    malformed.level = 255;
    try testing.expectError(error.InvalidLevel, validateSummary(malformed));
    malformed = a;
    malformed.root[2] = field.P;
    try testing.expectError(error.NonCanonicalField, mergeNodes(b, malformed));
    malformed = empty;
    malformed.root[0] ^= 1;
    try testing.expectError(error.InvalidEmptyRoot, mergeNodes(a, malformed));
    malformed = a;
    malformed.count = 0;
    try testing.expectError(error.InvalidEmptyRoot, validateSummary(malformed));
    malformed = padding;
    malformed.context = changed;
    try testing.expectError(error.InvalidEmptyRoot, validateSummary(malformed));
}

fn referenceTree(context: Context, entries: []const Entry, level: u8) Error!NodeSummary {
    if (entries.len == 0) return emptySubtree(context, level);
    if (level == 0) return leaf(context, entries[0]);
    const split = @min(entries.len, try levelCapacity(level - 1));
    return mergeNodes(try referenceTree(context, entries[0..split], level - 1), try referenceTree(context, entries[split..], level - 1));
}

test "block v2: fixed depth all supported counts and block bounds" {
    const context = testContext();
    const entries = testEntries();
    for (1..CAPACITY + 1) |count| {
        const reference = try referenceTree(context, entries[0..count], DEPTH);
        try testing.expectEqual(@as(u8, @intCast(count)), reference.count);
        try testing.expectEqual(DEPTH, reference.level);
        try testing.expectEqual(reference.root, try root(context, entries[0..count]));
    }
    try testing.expectError(error.EmptyBlock, root(context, &.{}));
    const too_many = [_]Entry{entries[0]} ** (CAPACITY + 1);
    try testing.expectError(error.TooManyEntries, root(context, &too_many));
    try testing.expect(!std.mem.eql(u64, &(try leaf(context, entries[0])).root, &(try root(context, entries[0..1]))));
}

test "block v2: cross-language known answers" {
    const context = testContext();
    const entries = testEntries();
    const counts = [_]usize{ 1, 3, 64 };
    const expected = [_]Digest{
        .{ 17302586004775321400, 14060252879667703226, 4653393007796374416, 4872023104817232206 },
        .{ 4814516697696595194, 16120349432758846240, 10073192216511493316, 3373496859766494287 },
        .{ 10210199181207880258, 12592273171222783804, 5412254068206525201, 9204339462543883831 },
    };
    for (counts, expected) |count, want| try testing.expectEqual(want, try root(context, entries[0..count]));
    try testing.expectEqual(Digest{ 336848228289249662, 7767320990335710777, 1138699809743786389, 7731264857985018234 }, (try emptySubtree(context, 0)).root);
    try testing.expectEqual(Digest{ 2271525178863671688, 10306419023861907142, 11839189680640350544, 1606716923507119681 }, (try emptySubtree(context, 6)).root);
    try testing.expectEqual(Digest{ 2387791423884938754, 18063362552844145910, 7285074225670006941, 10663012433430753868 }, (try leaf(context, entries[0])).root);
    try testing.expectEqual(Digest{ 4396680036629166094, 15904754847456670127, 9218176674975975282, 16593340716784826968 }, (try mergeNodes(try leaf(context, entries[0]), try leaf(context, entries[1]))).root);
}
