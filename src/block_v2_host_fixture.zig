//! Deterministic synthetic four-wallet fixture construction. No real funds.
//! Private keys and raw native witnesses stay in memory. Public ciphertexts,
//! statements and fresh research leaf proofs are the only exported artifacts.
const std = @import("std");
const node = @import("node.zig");
const body = @import("block_v2_host_body.zig");
const commitment = @import("block_v2.zig");
const p = @import("primitives.zig");
const poseidon = @import("poseidon2.zig");
const tx = @import("tx.zig");

pub const CHAIN = [_]u8{0x6d} ** 32;
pub const HEIGHT: u64 = 10;
pub const MINT: u64 = 7;
pub const MAX_DELIVERY_SLOTS: usize = 2048;
// Covers all heights of the bounded 128-block research journal.
pub const DELIVERY_REDEEM_TIMEOUT: u64 = HEIGHT + 128;
const Flavor = enum { legacy, delivery };
fn ownerIndex(index: usize, flavor: Flavor) usize {
    // All four participants rotate through all user transaction kinds.
    return (if (flavor == .delivery) index / 4 else index) % 4;
}
pub const MAX_LEAF_EXPORT_BYTES: usize = 2 * 1024 * 1024 + 264;
pub const MAX_EXPORT_BYTES: usize = 16 + body.MAX_BODY_BYTES + MAX_LEAF_EXPORT_BYTES;

extern fn lattica_v2_research_wallet_prove_v1(
    [*]const u8,
    usize,
    [*]const u8,
    usize,
    [*]u8,
    usize,
    *usize,
) callconv(.c) i32;

fn seed(index: usize, slot: u64) [32]u8 {
    var index_bytes: [8]u8 = undefined;
    var slot_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &index_bytes, @intCast(index), .little);
    std.mem.writeInt(u64, &slot_bytes, slot, .little);
    return p.hashDomain("lattica:research:complete-fixture:v1", &.{ &index_bytes, &slot_bytes });
}

const Terms = struct {
    redeem_tag: [32]u8,
    refund_tag: [32]u8,
    hashlock: [32]u8,
    preimage: [32]u8,
    timeout: u64,
};

fn terms(index: usize, keys: *const [4]tx.FullKey, flavor: Flavor) Terms {
    const redeem = index % 4 == 1;
    const owner = ownerIndex(index, flavor);
    const other = (owner + 1) % 4;
    const preimage = seed(index, 10);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&preimage, &hash, .{});
    return .{ .redeem_tag = keys[if (redeem) owner else other].address().recipientId(), .refund_tag = keys[if (redeem) other else owner].address().recipientId(), .hashlock = poseidon.digestBytes(poseidon.digestFromBytes(hash)), .preimage = preimage, .timeout = if (redeem) (if (flavor == .delivery) DELIVERY_REDEEM_TIMEOUT else HEIGHT + 10) else HEIGHT };
}

const Fixture = struct {
    chain: node.Chain,
    keys: [4]tx.FullKey,
    inputs: [][2]node.Minted,

    fn init(allocator: std.mem.Allocator) !Fixture {
        return initSlots(allocator, 64, .legacy);
    }
    fn initSlots(allocator: std.mem.Allocator, slots: usize, flavor: Flavor) !Fixture {
        if (slots == 0 or slots > MAX_DELIVERY_SLOTS) return error.InvalidFixtureCapacity;
        var fixture: Fixture = .{ .chain = try node.Chain.init(allocator), .keys = undefined, .inputs = undefined };
        errdefer fixture.chain.deinit();
        fixture.inputs = try allocator.alloc([2]node.Minted, slots);
        errdefer allocator.free(fixture.inputs);
        for (&fixture.keys, 0..) |*key, index| key.* = try tx.FullKey.fromSeed(seed(index, 100));
        for (fixture.inputs, 0..) |*inputs, index| {
            const key = fixture.keys[ownerIndex(index, flavor)];
            if (index % 4 == 1 or index % 4 == 2) {
                const t = terms(index, &fixture.keys, flavor);
                const owner = poseidon.digestBytes(poseidon.htlcRoot(poseidon.digestFromBytes(t.redeem_tag), poseidon.digestFromBytes(t.refund_tag), poseidon.digestFromBytes(t.hashlock), t.timeout));
                inputs[0] = try fixture.chain.bootstrapNote(.{ .value = 1000, .recipient = owner, .div = 0, .note_type = poseidon.NOTE_HTLC, .rho = seed(index, 1), .rcm = seed(index, 2) });
            } else {
                inputs[0] = try fixture.chain.bootstrapMint(key.address(), 1000, seed(index, 1));
            }
            inputs[1] = try fixture.chain.bootstrapMint(key.address(), 0, seed(index, 3));
        }
        return fixture;
    }
};

pub fn genesis(output: []u8) !usize {
    return genesisSlots(64, .legacy, output);
}

pub fn deliveryGenesis(slots: usize, output: []u8) !usize {
    return genesisSlots(slots, .delivery, output);
}

fn genesisSlots(slots: usize, flavor: Flavor, output: []u8) !usize {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var fixture = try Fixture.initSlots(arena.allocator(), slots, flavor);
    defer fixture.chain.deinit();
    var writer = body.Writer{ .bytes = output };
    try writer.put("LBV2GN01");
    try writer.uint(u64, HEIGHT - 1);
    try writer.uint(u128, fixture.chain.supply.issued);
    try writer.uint(u32, @intCast(fixture.chain.transmitted.items.len));
    try writer.digest(fixture.chain.anchor());
    for (fixture.chain.transmitted.items) |note| {
        try writer.digest(note.cm);
        try writer.put(&note.kem_ct);
        try writer.uint(u16, @intCast(note.ciphertext.len));
        try writer.put(note.ciphertext);
    }
    return writer.offset;
}

pub fn wallet(index: usize, output: []u8) !usize {
    if (index >= 64) return error.InvalidFixtureIndex;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try Fixture.init(allocator);
    defer fixture.chain.deinit();
    return walletOnChain(allocator, index, &fixture.chain, &fixture.keys, fixture.inputs[index], HEIGHT, .legacy, output);
}

/// Funded synthetic slots are found in the independently verified history.
/// No real keys or witnesses leave native memory.
pub fn deliveryWallet(index: usize, chain: *const node.Chain, height: u64, output: []u8) !usize {
    if (index >= MAX_DELIVERY_SLOTS or height < HEIGHT or height >= DELIVERY_REDEEM_TIMEOUT) return error.InvalidFixtureIndex;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var keys: [4]tx.FullKey = undefined;
    for (&keys, 0..) |*key, key_index| key.* = try tx.FullKey.fromSeed(seed(key_index, 100));
    var scratch = try node.Chain.init(allocator);
    defer scratch.deinit();
    const owner = keys[ownerIndex(index, .delivery)];
    const t = terms(index, &keys, .delivery);
    var inputs: [2]node.Minted = undefined;
    if (index % 4 == 1 or index % 4 == 2) {
        const recipient = poseidon.digestBytes(poseidon.htlcRoot(poseidon.digestFromBytes(t.redeem_tag), poseidon.digestFromBytes(t.refund_tag), poseidon.digestFromBytes(t.hashlock), t.timeout));
        inputs[0] = try scratch.bootstrapNote(.{ .value = 1000, .recipient = recipient, .div = 0, .note_type = poseidon.NOTE_HTLC, .rho = seed(index, 1), .rcm = seed(index, 2) });
    } else {
        inputs[0] = try scratch.bootstrapMint(owner.address(), 1000, seed(index, 1));
    }
    inputs[1] = try scratch.bootstrapMint(owner.address(), 0, seed(index, 3));
    for (&inputs, 0..) |*input, offset| {
        input.pos = chain.cm_index.get(input.note.commitment()) orelse return error.UnfundedFixtureSlot;
        if (input.pos != index * 2 + offset) return error.InvalidFixturePosition;
    }
    return walletOnChain(allocator, index, chain, &keys, inputs, height, .delivery, output);
}

fn walletOnChain(allocator: std.mem.Allocator, index: usize, chain: *const node.Chain, keys: *const [4]tx.FullKey, inputs: [2]node.Minted, height: u64, flavor: Flavor, output: []u8) !usize {
    const owner = keys[ownerIndex(index, flavor)];
    const recipient = keys[(ownerIndex(index, flavor) + 1) % 4];
    const path0 = try chain.merklePath(allocator, inputs[0].pos);
    const path1 = try chain.merklePath(allocator, inputs[1].pos);
    const mint: u64 = if (index % 4 == 3) MINT else 0;
    const outputs = [_]node.OutputReq{.{ .recipient = recipient.address(), .value = 1000 + mint }};
    var transaction: body.Transaction = undefined;
    var witness: []const u8 = undefined;
    if (index % 4 == 1 or index % 4 == 2) {
        const t = terms(index, keys, flavor);
        const built = try node.buildHtlcSpendWitness(allocator, owner, .{ .note = inputs[0].note, .position = inputs[0].pos, .path = path0, .claim_div = owner.address().div, .mode = if (index % 4 == 1) 1 else 0, .redeem_tag = t.redeem_tag, .refund_tag = t.refund_tag, .hashlock = t.hashlock, .timeout = t.timeout, .preimage = if (index % 4 == 1) t.preimage else null }, .{ .note = inputs[1].note, .position = inputs[1].pos, .path = path1 }, &outputs, 0, height, chain.anchor());
        transaction = .{ .htlc = built.tx };
        witness = built.witness;
    } else {
        const spends = [_]node.InputSpend{
            .{ .note = inputs[0].note, .position = inputs[0].pos, .path = path0 },
            .{ .note = inputs[1].note, .position = inputs[1].pos, .path = path1 },
        };
        const built = try node.buildTransferWitness(allocator, owner, &spends, &outputs, 0, mint, chain.anchor());
        transaction = if (mint == 0) .{ .joinsplit = built.tx } else .{ .issuance = built.tx };
        witness = built.witness;
    }
    // Check that these are usable encrypted notes for the four synthetic wallets,
    // not arbitrary ciphertext bytes attached to a statement-only fixture.
    const common = transaction.common();
    for (common.nullifiers) |nf| {
        if (chain.nullifiers.contains(nf)) return error.FixtureSlotAlreadySpent;
    }
    const received = tx.tryDecrypt(allocator, recipient, common.outputs[0]) orelse return error.RecipientCannotDecrypt;
    const change = tx.tryDecrypt(allocator, owner, common.outputs[1]) orelse return error.OwnerCannotDecrypt;
    if (received.value != 1000 + mint or change.value != 0 or
        !std.mem.eql(u8, &received.commitment(), &common.outputs[0].cm) or
        !std.mem.eql(u8, &change.commitment(), &common.outputs[1].cm)) return error.InvalidRecipientNote;

    var request: [64]u8 = undefined;
    var request_writer = body.Writer{ .bytes = &request };
    try request_writer.put("LBV2LW01");
    try request_writer.put(&CHAIN);
    try request_writer.uint(u64, @intFromEnum(transaction.kind()));
    try request_writer.uint(u64, if (transaction == .htlc) height else 0);
    try request_writer.uint(u64, mint);
    const leaf = try allocator.alloc(u8, MAX_LEAF_EXPORT_BYTES);
    var leaf_len: usize = 0;
    if (lattica_v2_research_wallet_prove_v1(&request, request.len, witness.ptr, witness.len, leaf.ptr, leaf.len, &leaf_len) != 0) return error.ResearchLeafProvingFailed;
    if (leaf_len < 16 or leaf_len > leaf.len or !std.mem.eql(u8, leaf[0..8], "LBV2WP01")) return error.InvalidLeafExport;
    const wallet_len = std.mem.readInt(u32, leaf[8..12], .little);
    const public_count = std.mem.readInt(u32, leaf[12..16], .little);
    const expected_public_count: u32 = if (transaction == .htlc) 31 else 26;
    if (public_count != expected_public_count or 16 + @as(usize, wallet_len) + public_count * 8 != leaf_len)
        return error.InvalidLeafStatement;
    var public: [31]u64 = undefined;
    for (public[0..public_count], 0..) |*value, i| {
        value.* = std.mem.readInt(u64, leaf[16 + @as(usize, wallet_len) + i * 8 ..][0..8], .little);
    }
    const leaf_digest = try commitment.statementDigest(@intFromEnum(transaction.kind()), public[0..public_count]);
    const native_entry = try transaction.entry();
    if (!std.mem.eql(u64, &leaf_digest, &native_entry.statement_digest)) return error.LeafBodyBindingMismatch;
    const encoded_body = try body.encode(&.{transaction}, try allocator.alloc(u8, body.MAX_BODY_BYTES));
    var writer = body.Writer{ .bytes = output };
    try writer.put("LBV2FX01");
    try writer.uint(u32, @intCast(encoded_body.len));
    try writer.uint(u32, @intCast(leaf_len));
    try writer.put(encoded_body);
    try writer.put(leaf[0..leaf_len]);
    return writer.offset;
}

test "research fixture: public genesis is deterministic and fully bounded" {
    const a = std.testing.allocator;
    const first = try a.alloc(u8, 1024 * 1024);
    defer a.free(first);
    const second = try a.alloc(u8, 1024 * 1024);
    defer a.free(second);
    const first_len = try genesis(first);
    const second_len = try genesis(second);
    try std.testing.expectEqualSlices(u8, first[0..first_len], second[0..second_len]);
    var reader = body.Reader{ .bytes = first[0..first_len] };
    try std.testing.expectEqualSlices(u8, "LBV2GN01", try reader.take(8));
    try std.testing.expectEqual(@as(u64, 9), try reader.uint(u64));
    try std.testing.expectEqual(@as(u128, 64000), try reader.uint(u128));
    try std.testing.expectEqual(@as(u32, 128), try reader.uint(u32));
    _ = try reader.digest();
    for (0..128) |_| {
        _ = try reader.digest();
        _ = try reader.take(p.CT_LEN);
        const size = try reader.uint(u16);
        try std.testing.expect(size <= node.MAX_NOTE_CIPHERTEXT_LEN);
        _ = try reader.take(size);
    }
    try std.testing.expectEqual(first_len, reader.offset);
}

test "research fixture: delivery funds the pilot and rotates four participants" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidFixtureCapacity, Fixture.initSlots(a, 0, .delivery));
    try std.testing.expectError(error.InvalidFixtureCapacity, Fixture.initSlots(a, MAX_DELIVERY_SLOTS + 1, .delivery));
    var fixture = try Fixture.initSlots(a, 704, .delivery);
    defer fixture.chain.deinit();
    defer a.free(fixture.inputs);
    try std.testing.expectEqual(@as(usize, 1408), fixture.chain.transmitted.items.len);
    try std.testing.expectEqual(@as(u128, 704000), fixture.chain.supply.issued);
    for (0..4) |participant| {
        for (0..4) |kind| try std.testing.expectEqual(participant, ownerIndex(participant * 4 + kind, .delivery));
    }
    for (fixture.inputs, 0..) |inputs, index| {
        const owner = fixture.keys[ownerIndex(index, .delivery)];
        for (inputs, 0..) |input, offset| {
            try std.testing.expectEqual(index * 2 + offset, input.pos);
            try std.testing.expectEqual(input.pos, fixture.chain.cm_index.get(input.note.commitment()).?);
        }
        const dummy = tx.tryDecrypt(a, owner, fixture.chain.transmitted.items[index * 2 + 1]).?;
        try std.testing.expectEqual(@as(u64, 0), dummy.value);
        if (index % 4 == 1 or index % 4 == 2) {
            const t = terms(index, &fixture.keys, .delivery);
            try std.testing.expectEqual(if (index % 4 == 1) DELIVERY_REDEEM_TIMEOUT else HEIGHT, t.timeout);
        }
    }
}
