//! Incremental Merkle commitment tree.
//!
//! Note commitments are appended as leaves; the root (the "anchor") is published with each
//! block. A spend proves its note's commitment is a leaf under some past anchor — without
//! revealing which leaf. Internal nodes use the circuit's Poseidon2 merge.
//!
//! Cached internal nodes make append and authentication-path work proportional to depth,
//! with constant-time root access. Empty subtrees use precomputed roots. Only nodes covering
//! an appended leaf are retained; the additional node count is less than leaves + depth.

const std = @import("std");
const Allocator = std.mem.Allocator;
const p = @import("primitives.zig");
const poseidon2 = @import("poseidon2.zig");
const Hash32 = p.Hash32;

/// Hash of an unfilled leaf (the empty-note sentinel).
pub const EMPTY_LEAF: Hash32 = [_]u8{0} ** 32;

/// Internal-node hash: `H(left, right)` — the in-circuit Poseidon2 2-to-1 merge (C-03), so on-chain
/// anchors equal the join-split circuit's membership root.
pub fn merkleHash(left: *const Hash32, right: *const Hash32) Hash32 {
    return poseidon2.digestBytes(poseidon2.merge(poseidon2.digestFromBytes(left.*), poseidon2.digestFromBytes(right.*)));
}

/// An authentication path: the sibling at each level from the leaf up to (but excluding) the
/// root, plus the leaf's position. Length equals the tree depth. `siblings` is owned by the
/// allocator passed to `authenticationPath`.
pub const MerklePath = struct {
    position: u64,
    siblings: []Hash32,
};

/// A fixed-depth incremental Merkle tree.
pub const MerkleTree = struct {
    allocator: Allocator,
    depth: usize,
    /// Append through this tree's methods; callers may inspect but must not mutate leaves.
    leaves: std.ArrayList(Hash32),
    /// `parents[l]` holds the populated nodes at height `l + 1`.
    parents: []std.ArrayList(Hash32),
    /// `empty[l]` is the root of a completely empty subtree of height `l`.
    empty: []Hash32,

    /// Create an empty tree of the given depth (capacity `2^depth` leaves).
    pub fn init(allocator: Allocator, depth: usize) !MerkleTree {
        if (depth >= 128) return error.InvalidDepth;
        const empty = try allocator.alloc(Hash32, depth + 1);
        errdefer allocator.free(empty);
        const parents = try allocator.alloc(std.ArrayList(Hash32), depth);
        for (parents) |*level| level.* = .empty;
        empty[0] = EMPTY_LEAF;
        var l: usize = 1;
        while (l <= depth) : (l += 1) empty[l] = merkleHash(&empty[l - 1], &empty[l - 1]);
        return .{ .allocator = allocator, .depth = depth, .leaves = .empty, .parents = parents, .empty = empty };
    }

    pub fn deinit(self: *MerkleTree) void {
        self.leaves.deinit(self.allocator);
        for (self.parents) |*level| level.deinit(self.allocator);
        self.allocator.free(self.parents);
        self.allocator.free(self.empty);
    }

    /// Number of leaves appended so far.
    pub fn len(self: MerkleTree) u64 {
        return @intCast(self.leaves.items.len);
    }

    /// Maximum number of leaves this tree can hold.
    pub fn capacity(self: MerkleTree) u128 {
        return @as(u128, 1) << @intCast(self.depth);
    }

    /// Append a leaf, returning its position.
    pub fn append(self: *MerkleTree, leaf: Hash32) !u64 {
        try self.ensureUnusedCapacity(1);
        return self.appendAssumeCapacity(leaf);
    }

    /// Reserve room for `n` more leaves so a subsequent `appendAssumeCapacity` cannot fail — used for
    /// atomic state commit (audit H-03). Returns `error.TreeFull` if `n` exceeds remaining capacity.
    pub fn ensureUnusedCapacity(self: *MerkleTree, n: usize) !void {
        if (@as(u128, self.leaves.items.len) + n > self.capacity()) return error.TreeFull;
        var count = std.math.add(usize, self.leaves.items.len, n) catch return error.TreeFull;
        // A failed allocation can grow capacity, but cannot change any leaf,
        // cached node, root or path. Reserve every level before commit starts.
        try self.leaves.ensureTotalCapacity(self.allocator, count);
        for (self.parents) |*level| {
            count = count / 2 + count % 2;
            try level.ensureTotalCapacity(self.allocator, count);
        }
    }

    /// Append a leaf using capacity reserved by `ensureUnusedCapacity` (infallible). Returns its position.
    pub fn appendAssumeCapacity(self: *MerkleTree, leaf: Hash32) u64 {
        std.debug.assert(@as(u128, self.leaves.items.len) < self.capacity());
        const pos: u64 = @intCast(self.leaves.items.len);
        self.leaves.appendAssumeCapacity(leaf);
        var index = pos;
        var current = leaf;
        for (self.parents, 0..) |*level, height| {
            const left = if (index & 1 == 0) current else self.node(height, index - 1);
            const right = if (index & 1 == 0) self.empty[height] else current;
            current = merkleHash(&left, &right);
            index >>= 1;
            if (index == level.items.len) {
                level.appendAssumeCapacity(current);
            } else {
                std.debug.assert(index < level.items.len);
                level.items[@intCast(index)] = current;
            }
        }
        return pos;
    }

    /// The current root (anchor).
    pub fn root(self: MerkleTree) Hash32 {
        return self.node(self.depth, 0);
    }

    /// Authentication path for the leaf at `position`.
    pub fn authenticationPath(self: MerkleTree, allocator: Allocator, position: u64) !MerklePath {
        if (position >= self.len()) return error.BadPosition;
        const siblings = try allocator.alloc(Hash32, self.depth);
        var idx = position;
        var level: usize = 0;
        while (level < self.depth) : (level += 1) {
            siblings[level] = self.node(level, idx ^ 1);
            idx >>= 1;
        }
        return .{ .position = position, .siblings = siblings };
    }

    /// Hash of the node at (`level`, `index`), or its canonical empty root.
    fn node(self: MerkleTree, level: usize, index: u64) Hash32 {
        const nodes = if (level == 0) self.leaves.items else self.parents[level - 1].items;
        if (index < nodes.len) return nodes[@intCast(index)];
        return self.empty[level];
    }
};

/// Recompute the root implied by a leaf and an authentication path, and compare to `root`.
/// This is exactly the check the zero-knowledge circuit performs in-circuit.
pub fn verifyPath(root: *const Hash32, leaf: *const Hash32, path: MerklePath) bool {
    var cur = leaf.*;
    var idx = path.position;
    for (path.siblings) |sib| {
        const s = sib;
        cur = if (idx & 1 == 0) merkleHash(&cur, &s) else merkleHash(&s, &cur);
        idx >>= 1;
    }
    return std.mem.eql(u8, &cur, root);
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

const testing = std.testing;

fn mkLeaf(n: u8) Hash32 {
    return [_]u8{n} ** 32;
}

test "empty root is stable" {
    const a = testing.allocator;
    var t1 = try MerkleTree.init(a, 8);
    defer t1.deinit();
    var t2 = try MerkleTree.init(a, 8);
    defer t2.deinit();
    try testing.expectEqualSlices(u8, &t1.root(), &t2.root());
}

test "root changes on append" {
    const a = testing.allocator;
    var t = try MerkleTree.init(a, 8);
    defer t.deinit();
    const r0 = t.root();
    _ = try t.append(mkLeaf(1));
    try testing.expect(!std.mem.eql(u8, &r0, &t.root()));
}

test "paths verify for all leaves" {
    const a = testing.allocator;
    var t = try MerkleTree.init(a, 10);
    defer t.deinit();
    var i: u8 = 0;
    while (i < 50) : (i += 1) _ = try t.append(mkLeaf(i));
    const root = t.root();
    var j: u64 = 0;
    while (j < 50) : (j += 1) {
        const path = try t.authenticationPath(a, j);
        defer a.free(path.siblings);
        try testing.expectEqual(@as(usize, 10), path.siblings.len);
        try testing.expect(verifyPath(&root, &mkLeaf(@intCast(j)), path));
    }
}

test "wrong leaf fails verification" {
    const a = testing.allocator;
    var t = try MerkleTree.init(a, 10);
    defer t.deinit();
    var i: u8 = 0;
    while (i < 8) : (i += 1) _ = try t.append(mkLeaf(i));
    const root = t.root();
    const path = try t.authenticationPath(a, 3);
    defer a.free(path.siblings);
    try testing.expect(verifyPath(&root, &mkLeaf(3), path));
    try testing.expect(!verifyPath(&root, &mkLeaf(99), path));
}

test "stale root fails after growth" {
    const a = testing.allocator;
    var t = try MerkleTree.init(a, 10);
    defer t.deinit();
    var i: u8 = 0;
    while (i < 8) : (i += 1) _ = try t.append(mkLeaf(i));
    const path = try t.authenticationPath(a, 3);
    defer a.free(path.siblings);
    const old_root = t.root();
    try testing.expect(verifyPath(&old_root, &mkLeaf(3), path));
    _ = try t.append(mkLeaf(50));
    const new_root = t.root();
    try testing.expect(!verifyPath(&new_root, &mkLeaf(3), path));
}

test "deep tree is cheap" {
    const a = testing.allocator;
    var t = try MerkleTree.init(a, 32);
    defer t.deinit();
    const p0 = try t.append(mkLeaf(1));
    const p1 = try t.append(mkLeaf(2));
    try testing.expectEqual(@as(u64, 0), p0);
    try testing.expectEqual(@as(u64, 1), p1);
    const root = t.root();
    const path = try t.authenticationPath(a, 1);
    defer a.free(path.siblings);
    try testing.expectEqual(@as(usize, 32), path.siblings.len);
    try testing.expect(verifyPath(&root, &mkLeaf(2), path));
}

// Independent recursive oracle: this is the previous leaf-only tree algorithm.
// It never reads the incremental cache.
fn referenceNode(leaves: []const Hash32, empty: []const Hash32, level: usize, index: u64) Hash32 {
    if (level == 0) return if (index < leaves.len) leaves[@intCast(index)] else empty[0];
    if (index << @intCast(level) >= leaves.len) return empty[level];
    const left = referenceNode(leaves, empty, level - 1, index * 2);
    const right = referenceNode(leaves, empty, level - 1, index * 2 + 1);
    return merkleHash(&left, &right);
}

fn distinctLeaf(index: usize) Hash32 {
    var leaf: Hash32 = @splat(0);
    std.mem.writeInt(u64, leaf[0..8], @intCast(index + 1), .little);
    std.mem.writeInt(u64, leaf[8..16], @intCast(index * 17 + 3), .little);
    return leaf;
}

test "cached roots and paths match leaf-only reference across carries and depths" {
    const a = testing.allocator;
    for ([_]usize{ 0, 1, 2, 4, 8, 32 }) |depth| {
        var t = try MerkleTree.init(a, depth);
        defer t.deinit();
        const count: usize = @intCast(@min(t.capacity(), 257));
        try testing.expectEqual(referenceNode(t.leaves.items, t.empty, depth, 0), t.root());
        for (0..count) |index| {
            try testing.expectEqual(@as(u64, @intCast(index)), try t.append(distinctLeaf(index)));
            const expected = referenceNode(t.leaves.items, t.empty, depth, 0);
            try testing.expectEqual(expected, t.root());
            for ([_]usize{ 0, index / 2, index }) |position| {
                const path = try t.authenticationPath(a, @intCast(position));
                defer a.free(path.siblings);
                for (path.siblings, 0..) |sibling, level| {
                    const sibling_index = (@as(u64, @intCast(position)) >> @intCast(level)) ^ 1;
                    try testing.expectEqual(referenceNode(t.leaves.items, t.empty, level, sibling_index), sibling);
                }
                try testing.expect(verifyPath(&expected, &distinctLeaf(position), path));
            }
            var retained_nodes: usize = 0;
            var nodes = t.leaves.items.len;
            for (t.parents) |level| {
                nodes = nodes / 2 + nodes % 2;
                try testing.expectEqual(nodes, level.items.len);
                retained_nodes += nodes;
            }
            try testing.expect(retained_nodes <= t.leaves.items.len + depth);
        }
    }
}

test "batch reservation makes every append infallible at all cache levels" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var t = try MerkleTree.init(allocator.allocator(), 32);
    defer t.deinit();
    _ = try t.append(distinctLeaf(0));
    const before = t.root();
    try t.ensureUnusedCapacity(256);
    try testing.expectEqual(before, t.root());
    try testing.expectEqual(@as(u64, 1), t.len());
    const allocations = allocator.alloc_index;
    const resizes = allocator.resize_index;
    allocator.fail_index = allocations;
    allocator.resize_fail_index = resizes;
    for (1..257) |index| {
        try testing.expectEqual(@as(u64, @intCast(index)), t.appendAssumeCapacity(distinctLeaf(index)));
    }
    try testing.expectEqual(allocations, allocator.alloc_index);
    try testing.expectEqual(resizes, allocator.resize_index);
    try testing.expectEqual(referenceNode(t.leaves.items, t.empty, t.depth, 0), t.root());
    const path = try t.authenticationPath(testing.allocator, 128);
    defer testing.allocator.free(path.siblings);
    try testing.expect(verifyPath(&t.root(), &distinctLeaf(128), path));
}

fn appendWithAllocationFailures(allocator: Allocator) !void {
    var t = try MerkleTree.init(allocator, 8);
    defer t.deinit();
    for (0..33) |index| {
        const root = t.root();
        const length = t.len();
        _ = t.append(distinctLeaf(index)) catch |err| {
            try testing.expectEqual(length, t.len());
            try testing.expectEqual(root, t.root());
            try testing.expectEqual(referenceNode(t.leaves.items, t.empty, t.depth, 0), t.root());
            for (t.leaves.items, 0..) |leaf, i| try testing.expectEqual(distinctLeaf(i), leaf);
            return err;
        };
    }
}

test "allocation failures leave committed leaves cache and roots unchanged" {
    try testing.checkAllAllocationFailures(testing.allocator, appendWithAllocationFailures, .{});
}

test "full trees invalid depths and overflowing reservations reject before mutation" {
    try testing.expectError(error.InvalidDepth, MerkleTree.init(testing.allocator, 128));
    for ([_]usize{ 0, 3 }) |depth| {
        var t = try MerkleTree.init(testing.allocator, depth);
        defer t.deinit();
        for (0..@as(usize, @intCast(t.capacity()))) |index| _ = try t.append(distinctLeaf(index));
        const root = t.root();
        try testing.expectError(error.TreeFull, t.append(distinctLeaf(99)));
        try testing.expectError(error.TreeFull, t.ensureUnusedCapacity(std.math.maxInt(usize)));
        try testing.expectEqual(root, t.root());
        try testing.expectError(error.BadPosition, t.authenticationPath(testing.allocator, t.len()));
    }
    var deep = try MerkleTree.init(testing.allocator, 127);
    defer deep.deinit();
    _ = try deep.append(distinctLeaf(0));
    const root = deep.root();
    try testing.expectError(error.TreeFull, deep.ensureUnusedCapacity(std.math.maxInt(usize)));
    try testing.expectEqual(root, deep.root());
    const path = try deep.authenticationPath(testing.allocator, 0);
    defer testing.allocator.free(path.siblings);
    try testing.expect(verifyPath(&root, &distinctLeaf(0), path));
}
