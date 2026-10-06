//! Native state/application checks. The local verifier stub only tests the
//! boundary and must never be reported as cryptographic root qualification.
const std = @import("std");
const node = @import("node.zig");
const ffi = @import("ffi.zig");
const commitment = @import("block_v2.zig");
const tx = @import("tx.zig");
const p = @import("primitives.zig");
const testing = std.testing;
const Transaction = node.BlockV2ResearchTransaction;
const context = commitment.Context{ .profile_id = [_]u8{11} ** 32, .chain_id = [_]u8{22} ** 32 };
const registry = "LBV2RG01synthetic-boundary-test";

// These snapshots cover the auxiliary indexes and event log as well as the
// consensus roots. Capacity may grow on a failed reservation; contents may not.
const State = struct {
    state: [32]u8,
    events: [32]u8,
    anchor: [32]u8,
    nullifiers: usize,
    anchors: usize,
    outputs: usize,
    event_count: usize,
    positions: usize,
    supply: @import("protocol.zig").SupplyState,

    fn capture(chain: node.Chain) State {
        return .{
            .state = chain.stateRoot(),
            .events = chain.eventRoot(),
            .anchor = chain.anchor(),
            .nullifiers = chain.nullifiers.count(),
            .anchors = chain.anchors.count(),
            .outputs = chain.transmitted.items.len,
            .event_count = chain.redeemEvents().len,
            .positions = chain.cm_index.count(),
            .supply = chain.supply,
        };
    }

    fn expectUnchanged(self: State, chain: node.Chain) !void {
        try testing.expectEqualDeep(self, capture(chain));
    }
};

fn initializeAndRelease(allocator: std.mem.Allocator) !void {
    var chain = try node.Chain.init(allocator);
    defer chain.deinit();
}

test "candidate host: initialization releases allocations on failure" {
    try testing.checkAllAllocationFailures(testing.allocator, initializeAndRelease, .{});
}

test "candidate host: allocation failures preserve all state and permit retry" {
    BoundaryVerifier.install();
    defer ffi.clearBlockV2ResearchBackend();
    var failures: usize = 0;
    for (0..128) |offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        {
            var chain = try node.Chain.init(failing.allocator());
            defer chain.deinit();
            const transactions = mixed(chain.anchor());
            const proof = (try node.blockV2ResearchExpected(context, &transactions)).encode();
            const before = State.capture(chain);
            failing.fail_index = failing.alloc_index + offset;
            // Make growth use the deterministic allocation-failure path rather
            // than depending on the backing allocator's in-place resizing.
            failing.resize_fail_index = failing.resize_index;
            if (chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 })) |_| {
                try testing.expect(!failing.has_induced_failure);
                try testing.expectEqual(@as(usize, 8), chain.transmitted.items.len);
            } else |err| {
                try testing.expect(failing.has_induced_failure);
                try testing.expect(err == error.Internal or err == error.TreeFull);
                try before.expectUnchanged(chain);
                failures += 1;
                failing.fail_index = std.math.maxInt(usize);
                failing.resize_fail_index = std.math.maxInt(usize);
                try chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 });
                try testing.expectEqual(@as(usize, 8), chain.nullifiers.count());
                try testing.expectEqual(@as(usize, 8), chain.transmitted.items.len);
                try testing.expectEqual(@as(usize, 1), chain.redeemEvents().len);
                try testing.expect(chain.supply.invariantHolds());
            }
        }
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (!failing.has_induced_failure) break;
    } else return error.AllocationFailureCoverageIncomplete;
    // Exercise at least the eight ciphertext copies and seen-set reservation.
    try testing.expect(failures >= 9);
}

test "candidate host: trusted context, registry and canonical fields are enforced" {
    BoundaryVerifier.install();
    defer ffi.clearBlockV2ResearchBackend();
    var chain = try node.Chain.init(testing.allocator);
    defer chain.deinit();
    const transactions = mixed(chain.anchor());
    const proof = (try node.blockV2ResearchExpected(context, &transactions)).encode();
    const before = State.capture(chain);

    var other_context = context;
    other_context.chain_id[0] ^= 1;
    try testing.expectError(error.BadAuthProof, chain.applyBlockV2Research(other_context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 }));
    other_context = context;
    other_context.profile_id[0] ^= 1;
    try testing.expectError(error.BadAuthProof, chain.applyBlockV2Research(other_context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 }));
    try testing.expectError(error.BadAuthProof, chain.applyBlockV2Research(context, "LBV2RG01different-trusted-registry", &transactions, &proof, 10, &.{ 0, 0, 0, 7 }));

    var changed = transactions;
    changed[3].issuance.outputs[1].cm = [_]u8{255} ** 32;
    try testing.expectError(error.NonCanonicalField, chain.applyBlockV2Research(context, registry, &changed, &proof, 10, &.{ 0, 0, 0, 7 }));
    changed = transactions;
    changed[2].htlc.fee = node.MAX_RANGE_VALUE;
    try testing.expectError(error.OversizeFee, chain.applyBlockV2Research(context, registry, &changed, &proof, 10, &.{ 0, 0, 0, 7 }));
    const oversize = [_]u8{0} ** (node.MAX_NOTE_CIPHERTEXT_LEN + 1);
    changed = transactions;
    changed[0].joinsplit.outputs[0].ciphertext = &oversize;
    try testing.expectError(error.OversizeOutput, chain.applyBlockV2Research(context, registry, &changed, &proof, 10, &.{ 0, 0, 0, 7 }));
    try before.expectUnchanged(chain);
}

fn digest(n: u64) [32]u8 {
    var bytes = [_]u8{0} ** 32;
    std.mem.writeInt(u64, bytes[0..8], n, .little);
    return bytes;
}

fn plain(anchor: [32]u8, offset: u64) node.ShieldedTx {
    return .{ .anchor = anchor, .nullifiers = .{ digest(offset), digest(offset + 1) }, .fee = 0, .mint = 0, .proof = &.{}, .outputs = .{
        tx.TransmittedNote{ .cm = digest(offset + 2), .kem_ct = [_]u8{0} ** p.CT_LEN, .ciphertext = "first" },
        tx.TransmittedNote{ .cm = digest(offset + 3), .kem_ct = [_]u8{0} ** p.CT_LEN, .ciphertext = "second" },
    } };
}

fn htlc(anchor: [32]u8, offset: u64, preimage: ?[32]u8) node.ShieldedHtlcTx {
    const t = plain(anchor, offset);
    return .{ .anchor = t.anchor, .nullifiers = t.nullifiers, .fee = 0, .mint = 0, .current_height = 10, .redeem_preimage = preimage, .proof = &.{}, .outputs = t.outputs };
}

test "candidate host: preflight checks state and policy without applying or trusting a proof" {
    ffi.clearBlockV2ResearchBackend();
    var chain = try node.Chain.init(testing.allocator);
    defer chain.deinit();
    const before = State.capture(chain);
    const transactions = mixed(chain.anchor());
    const checked = try chain.validateBlockV2Research(context, &transactions, 10, &.{ 0, 0, 0, 7 });
    try testing.expectEqualDeep(try node.blockV2ResearchExpected(context, &transactions), checked.expected);
    try testing.expectEqual(@as(u128, 7), checked.supply.issued);
    try testing.expectEqual(@as(usize, 1), checked.events);
    try before.expectUnchanged(chain);
    try testing.expectError(node.TxError.IllegalIssuance, chain.validateBlockV2Research(context, &transactions, 10, &.{ 0, 0, 0, 8 }));
    try testing.expectError(node.TxError.HeightMismatch, chain.validateBlockV2Research(context, &transactions, 11, &.{ 0, 0, 0, 7 }));
    var changed = transactions;
    changed[3].issuance.nullifiers[0] = changed[0].joinsplit.nullifiers[0];
    try testing.expectError(node.TxError.DoubleSpend, chain.validateBlockV2Research(context, &changed, 10, &.{ 0, 0, 0, 7 }));
    changed = transactions;
    changed[3].issuance.anchor = digest(999);
    try testing.expectError(node.TxError.UnknownAnchor, chain.validateBlockV2Research(context, &changed, 10, &.{ 0, 0, 0, 7 }));
    try before.expectUnchanged(chain);
}

fn mixed(anchor: [32]u8) [4]Transaction {
    var issuance = plain(anchor, 40);
    issuance.mint = 7;
    return .{ .{ .joinsplit = plain(anchor, 10) }, .{ .htlc = htlc(anchor, 20, [_]u8{23} ** 32) }, .{ .htlc = htlc(anchor, 30, null) }, .{ .issuance = issuance } };
}

const BoundaryVerifier = struct {
    var calls: usize = 0;

    fn verify(proof: [*]const u8, proof_len: usize, expected: [*]const u8, expected_len: usize, keys: [*]const u8, keys_len: usize) callconv(.c) c_int {
        calls += 1;
        if (!std.mem.eql(u8, keys[0..keys_len], registry)) return -1;
        return if (std.mem.eql(u8, proof[0..proof_len], expected[0..expected_len])) 0 else -1;
    }

    fn install() void {
        calls = 0;
        ffi.setBlockV2ResearchBackend(verify);
    }
};

test "candidate host: complete bodies bind ciphertexts, preimages, types and order" {
    var chain = try node.Chain.init(testing.allocator);
    defer chain.deinit();
    const transactions = mixed(chain.anchor());
    const expected = try node.blockV2ResearchExpected(context, &transactions);
    var changed = transactions;
    changed[0].joinsplit.outputs[0].ciphertext = "changed";
    try testing.expect(!std.mem.eql(u8, &expected.root, &(try node.blockV2ResearchExpected(context, &changed)).root));
    changed = transactions;
    changed[1].htlc.redeem_preimage = [_]u8{24} ** 32;
    try testing.expect(!std.mem.eql(u8, &expected.root, &(try node.blockV2ResearchExpected(context, &changed)).root));
    changed = transactions;
    std.mem.swap(Transaction, &changed[0], &changed[1]);
    try testing.expect(!std.mem.eql(u8, &expected.root, &(try node.blockV2ResearchExpected(context, &changed)).root));
    changed = transactions;
    changed[3] = .{ .joinsplit = transactions[3].issuance };
    try testing.expect(!std.mem.eql(u8, &expected.root, &(try node.blockV2ResearchExpected(context, &changed)).root));
}

test "candidate host: mixed apply owns outputs and preserves public supply and events" {
    BoundaryVerifier.install();
    defer ffi.clearBlockV2ResearchBackend();
    var chain = try node.Chain.init(testing.allocator);
    defer chain.deinit();
    var transactions = mixed(chain.anchor());
    var ciphertext = [_]u8{ 1, 2, 3, 4 };
    transactions[0].joinsplit.outputs[0].ciphertext = &ciphertext;
    const proof = (try node.blockV2ResearchExpected(context, &transactions)).encode();
    try chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 });
    try testing.expectEqual(@as(usize, 1), BoundaryVerifier.calls);
    try testing.expectEqual(@as(usize, 8), chain.nullifiers.count());
    try testing.expectEqual(@as(usize, 8), chain.transmitted.items.len);
    try testing.expectEqual(@as(usize, 1), chain.redeemEvents().len);
    try testing.expectEqual(@as(u128, 7), chain.supply.issued);
    try testing.expectEqual(@as(u128, 7), chain.supply.shielded_pool);
    try testing.expect(chain.supply.invariantHolds());
    ciphertext[0] = 99;
    try testing.expectEqual(@as(u8, 1), chain.transmitted.items[0].ciphertext[0]);
    try testing.expectError(node.TxError.DoubleSpend, chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 }));
}

test "candidate host: whole block rejected before state changes for stale state and policy" {
    BoundaryVerifier.install();
    defer ffi.clearBlockV2ResearchBackend();
    var chain = try node.Chain.init(testing.allocator);
    defer chain.deinit();
    const transactions = mixed(chain.anchor());
    const proof = (try node.blockV2ResearchExpected(context, &transactions)).encode();
    const state = chain.stateRoot();
    try testing.expectError(node.TxError.IllegalIssuance, chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 8 }));
    try testing.expectError(node.TxError.IllegalIssuance, chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 7, 0, 0, 7 }));
    try testing.expectError(node.TxError.HeightMismatch, chain.applyBlockV2Research(context, registry, &transactions, &proof, 11, &.{ 0, 0, 0, 7 }));
    var changed = transactions;
    changed[3].issuance.anchor = digest(999);
    try testing.expectError(node.TxError.UnknownAnchor, chain.applyBlockV2Research(context, registry, &changed, &proof, 10, &.{ 0, 0, 0, 7 }));
    changed = transactions;
    changed[3].issuance.nullifiers[0] = changed[0].joinsplit.nullifiers[0];
    try testing.expectError(node.TxError.DoubleSpend, chain.applyBlockV2Research(context, registry, &changed, &proof, 10, &.{ 0, 0, 0, 7 }));
    try testing.expectEqual(@as(usize, 0), BoundaryVerifier.calls);
    try testing.expectEqualSlices(u8, &state, &chain.stateRoot());
    try testing.expectEqual(@as(usize, 0), chain.nullifiers.count());
    try testing.expectEqual(@as(usize, 0), chain.transmitted.items.len);
}

test "candidate host: missing verifier and altered binding fail without fallback" {
    ffi.clearBlockV2ResearchBackend();
    defer ffi.clearBlockV2ResearchBackend();
    var chain = try node.Chain.init(testing.allocator);
    defer chain.deinit();
    var transactions = mixed(chain.anchor());
    const proof = (try node.blockV2ResearchExpected(context, &transactions)).encode();
    const state = chain.stateRoot();
    try testing.expectError(node.TxError.BadAuthProof, chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 }));
    BoundaryVerifier.install();
    transactions[0].joinsplit.outputs[0].kem_ct[0] ^= 1;
    try testing.expectError(node.TxError.BadAuthProof, chain.applyBlockV2Research(context, registry, &transactions, &proof, 10, &.{ 0, 0, 0, 7 }));
    try testing.expectEqualSlices(u8, &state, &chain.stateRoot());
    try testing.expectEqual(@as(usize, 0), chain.transmitted.items.len);
}
