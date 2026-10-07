//! Stateless native replay for the research durable adapter.
//! Build this opt-in bridge with the block-v2-host Rust static library. It
//! applies complete bodies using node.Chain and the separate real CPU verifier.
//! Trusted genesis, registry, context and per-height issuance grants come from
//! the host; the untrusted journal must never select them.
const std = @import("std");
const node = @import("node.zig");
const ffi = @import("ffi.zig");
const commitment = @import("block_v2.zig");
const body = @import("block_v2_host_body.zig");
const p = @import("primitives.zig");
const fixture = @import("block_v2_host_fixture.zig");

pub const GENESIS_MAGIC = "LBV2GN01";
pub const REPLAY_MAGIC = "LBV2RP01";
pub const STATE_MAGIC = "LBV2ST01";
pub const MAX_GENESIS_NOTES: usize = 4096;
pub const MAX_GENESIS_BYTES: usize = 8 + 8 + 16 + 4 + 32 +
    MAX_GENESIS_NOTES * (32 + p.CT_LEN + 2 + node.MAX_NOTE_CIPHERTEXT_LEN);
pub const MAX_BLOCKS: usize = 128;
pub const MAX_REPLAY_BYTES: usize = 12 + MAX_BLOCKS *
    (8 + 4 + 8 + 4 + commitment.CAPACITY * 8 + body.MAX_BODY_BYTES + ffi.MAX_PROOF_LEN);
pub const STATE_BYTES: usize = 208;
pub const PREFLIGHT_MAGIC = "LBV2PF01";
pub const MAX_PREFLIGHT_BYTES = 8 + ffi.BlockV2ResearchExpected.ENCODED_LEN + commitment.CAPACITY * (2 + 31 * 8);

// The opt-in root ABI is defined in lattica_prover_p3.h. This bridge is linked
// separately from the default node and cannot fall back to legacy verification.
extern fn lattica_v2_research_root_verify_v1(
    [*]const u8,
    usize,
    [*]const u8,
    usize,
    [*]const u8,
    usize,
) callconv(.c) i32;

/// Call once before concurrent replay, as required by the native backend slot.
export fn lattica_v2_research_host_initialize_v1() callconv(.c) void {
    ffi.setBlockV2ResearchBackend(lattica_v2_research_root_verify_v1);
}

export fn lattica_v2_research_fixture_genesis_v1(
    output: [*c]u8,
    cap: usize,
    output_len: [*c]usize,
) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (output == null or cap == 0 or cap > MAX_GENESIS_BYTES) return -1;
    const size = fixture.genesis(output[0..cap]) catch return -2;
    output_len[0] = size;
    return 0;
}

export fn lattica_v2_research_fixture_wallet_v1(
    index: u32,
    output: [*c]u8,
    cap: usize,
    output_len: [*c]usize,
) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (index >= 64 or output == null or cap == 0 or cap > fixture.MAX_EXPORT_BYTES) return -1;
    const size = fixture.wallet(index, output[0..cap]) catch return -2;
    output_len[0] = size;
    return 0;
}

export fn lattica_v2_research_body_expected_v1(
    context_ptr: [*c]const u8,
    context_len: usize,
    body_ptr: [*c]const u8,
    body_len: usize,
    output: [*c]u8,
    output_len: usize,
) callconv(.c) i32 {
    if (context_ptr == null or body_ptr == null or output == null or context_len != 64 or
        body_len < body.HEADER_LEN or body_len > body.MAX_BODY_BYTES or output_len < ffi.BlockV2ResearchExpected.ENCODED_LEN) return -1;
    const context_bytes = context_ptr[0..context_len];
    const context = commitment.Context{ .profile_id = context_bytes[0..32].*, .chain_id = context_bytes[32..64].* };
    const decoded = body.decode(body_ptr[0..body_len]) catch return -2;
    const expected = node.blockV2ResearchExpected(context, decoded.transactions()) catch return -2;
    const bytes = expected.encode();
    @memcpy(output[0..bytes.len], &bytes);
    return 0;
}

/// Replay native history and check the next complete candidate against current
/// state and independently supplied issuance grants. This does not apply state
/// or verify a candidate proof. Public statements come from complete envelopes
/// and must still pass independent CPU wallet verification before proving.
export fn lattica_v2_research_candidate_preflight_v1(
    registry_ptr: [*c]const u8,
    registry_len: usize,
    context_ptr: [*c]const u8,
    context_len: usize,
    genesis_ptr: [*c]const u8,
    genesis_len: usize,
    records_ptr: [*c]const u8,
    records_len: usize,
    body_ptr: [*c]const u8,
    body_len: usize,
    at_height: u64,
    grants_ptr: [*c]const u8,
    grants_len: usize,
    output: [*c]u8,
    cap: usize,
    output_len: [*c]usize,
) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (registry_ptr == null or context_ptr == null or genesis_ptr == null or records_ptr == null or
        body_ptr == null or grants_ptr == null or output == null or registry_len < 8 or
        registry_len > ffi.MAX_BLOCK_V2_REGISTRY_BYTES or context_len != 64 or
        genesis_len < 68 or genesis_len > MAX_GENESIS_BYTES or records_len < 12 or
        records_len > MAX_REPLAY_BYTES or body_len < body.HEADER_LEN or body_len > body.MAX_BODY_BYTES or
        grants_len == 0 or grants_len > commitment.CAPACITY * 8 or cap < 120 or cap > MAX_PREFLIGHT_BYTES)
        return -1;
    var state = restore(registry_ptr[0..registry_len], context_ptr[0..context_len], genesis_ptr[0..genesis_len], records_ptr[0..records_len], null) catch return -2;
    defer state.chain.deinit();
    if (at_height != state.height + 1 or at_height >= node.MAX_RANGE_VALUE) return -2;
    const decoded = body.decode(body_ptr[0..body_len]) catch return -2;
    if (grants_len != decoded.count * 8) return -2;
    var grants: [commitment.CAPACITY]u64 = undefined;
    var reader = body.Reader{ .bytes = grants_ptr[0..grants_len] };
    for (grants[0..decoded.count]) |*grant| grant.* = reader.uint(u64) catch return -2;
    const context = commitment.Context{ .profile_id = context_ptr[0..32].*, .chain_id = context_ptr[32..64].* };
    const checked = state.chain.validateBlockV2Research(context, decoded.transactions(), at_height, grants[0..decoded.count]) catch return -2;
    var writer = body.Writer{ .bytes = output[0..cap] };
    writer.put(PREFLIGHT_MAGIC) catch return -1;
    writer.put(&checked.expected.encode()) catch return -1;
    for (decoded.transactions()) |item| {
        const kind: u8 = switch (item) {
            .joinsplit => 0,
            .htlc => |h| if (h.redeem_preimage != null) 1 else 2,
            .issuance => 3,
        };
        var fields: [31]u64 = undefined;
        const count = item.statement(&fields) catch return -2;
        writer.uint(u8, kind) catch return -1;
        writer.uint(u8, @intCast(count)) catch return -1;
        for (fields[0..count]) |field| writer.uint(u64, field) catch return -1;
    }
    output_len[0] = writer.offset;
    return 0;
}

const Genesis = struct { chain: node.Chain, height: u64 };

fn initialState(allocator: std.mem.Allocator, bytes: []const u8) !Genesis {
    return initialStateBounded(allocator, bytes, MAX_GENESIS_BYTES, MAX_GENESIS_NOTES);
}

const MAX_SESSION_GENESIS_NOTES = 2 * fixture.MAX_SUSTAINED_SLOTS;
const MAX_SESSION_GENESIS_BYTES = 68 + MAX_SESSION_GENESIS_NOTES * (32 + p.CT_LEN + 2 + node.MAX_NOTE_CIPHERTEXT_LEN);

fn initialStateBounded(allocator: std.mem.Allocator, bytes: []const u8, max_bytes: usize, max_notes: usize) !Genesis {
    if (bytes.len > max_bytes) return error.OversizeGenesis;
    var reader = body.Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try reader.take(8), GENESIS_MAGIC)) return error.InvalidGenesisVersion;
    const height = try reader.uint(u64);
    if (height >= node.MAX_RANGE_VALUE - 1) return error.InvalidGenesisHeight;
    const issued = try reader.uint(u128);
    const count = try reader.uint(u32);
    if (count > max_notes) return error.OversizeGenesis;
    const expected_anchor = try reader.digest();
    var chain = try node.Chain.init(allocator);
    errdefer chain.deinit();
    // The independently pinned genesis authorizes this initial public supply.
    // Its hidden-value construction is outside this replay API's proof claims.
    chain.supply = .{ .issued = issued, .shielded_pool = issued };
    try chain.tree.ensureUnusedCapacity(count);
    try chain.cm_index.ensureUnusedCapacity(count);
    try chain.anchors.ensureUnusedCapacity(count);
    try chain.transmitted.ensureUnusedCapacity(allocator, count);
    for (0..count) |_| {
        const cm = try reader.digest();
        const kem = try reader.array(p.CT_LEN);
        const size = try reader.uint(u16);
        if (size > node.MAX_NOTE_CIPHERTEXT_LEN) return error.OversizeGenesisCiphertext;
        const borrowed = try reader.take(size);
        if (chain.cm_index.contains(cm)) return error.DuplicateGenesisCommitment;
        const ciphertext = try allocator.dupe(u8, borrowed);
        const position = chain.tree.appendAssumeCapacity(cm);
        chain.cm_index.putAssumeCapacity(cm, position);
        chain.anchors.putAssumeCapacity(chain.anchor(), {});
        chain.transmitted.appendAssumeCapacity(.{ .cm = cm, .kem_ct = kem, .ciphertext = ciphertext });
    }
    if (reader.offset != bytes.len or !std.mem.eql(u8, &expected_anchor, &chain.anchor())) return error.InvalidGenesis;
    return .{ .chain = chain, .height = height };
}

fn writeState(chain: node.Chain, height: u64, blocks: u64, output: []u8) !void {
    var writer = body.Writer{ .bytes = output[0..STATE_BYTES] };
    try writer.put(STATE_MAGIC);
    try writer.put(&chain.stateRoot());
    try writer.put(&chain.eventRoot());
    try writer.put(&chain.anchor());
    try writer.uint(u128, chain.supply.issued);
    try writer.uint(u128, chain.supply.burned);
    try writer.uint(u128, chain.supply.shielded_pool);
    try writer.uint(u128, chain.supply.fees_paid);
    try writer.uint(u64, chain.nullifiers.count());
    try writer.uint(u64, @intCast(chain.transmitted.items.len));
    try writer.uint(u64, @intCast(chain.redeemEvents().len));
    try writer.uint(u64, blocks);
    try writer.uint(u64, height);
    std.debug.assert(writer.offset == STATE_BYTES);
}

fn restore(registry: []const u8, context_bytes: []const u8, genesis: []const u8, records: []const u8, output: ?[]u8) !Genesis {
    if (!ffi.hasBlockV2ResearchBackend()) return error.MissingRootBackend;
    if (context_bytes.len != 64 or !std.mem.startsWith(u8, registry, "LBV2RG01") or
        registry.len > ffi.MAX_BLOCK_V2_REGISTRY_BYTES) return error.InvalidConfiguration;
    const context = commitment.Context{ .profile_id = context_bytes[0..32].*, .chain_id = context_bytes[32..64].* };
    var state = try initialState(std.heap.page_allocator, genesis);
    errdefer state.chain.deinit();
    var reader = body.Reader{ .bytes = records };
    if (!std.mem.eql(u8, try reader.take(8), REPLAY_MAGIC)) return error.InvalidReplayVersion;
    const blocks = try reader.uint(u32);
    if (blocks > MAX_BLOCKS) return error.TooManyBlocks;
    if (output) |bytes| {
        if (bytes.len < (@as(usize, blocks) + 1) * STATE_BYTES) return error.ShortOutput;
        try writeState(state.chain, state.height, 0, bytes[0..STATE_BYTES]);
    }
    for (0..blocks) |index| {
        const height = try reader.uint(u64);
        const body_len = try reader.uint(u32);
        const proof_len = try reader.uint(u64);
        const grant_count = try reader.uint(u32);
        if (height != state.height + 1 or height >= node.MAX_RANGE_VALUE or
            body_len > body.MAX_BODY_BYTES or proof_len == 0 or proof_len > ffi.MAX_PROOF_LEN or
            grant_count == 0 or grant_count > commitment.CAPACITY) return error.InvalidRecord;
        var grants: [commitment.CAPACITY]u64 = undefined;
        for (grants[0..grant_count]) |*grant| grant.* = try reader.uint(u64);
        const decoded = try body.decode(try reader.take(body_len));
        if (decoded.count != grant_count) return error.InvalidGrantCount;
        const proof = try reader.take(@intCast(proof_len));
        try state.chain.applyBlockV2Research(context, registry, decoded.transactions(), proof, height, grants[0..grant_count]);
        state.height = height;
        if (output) |bytes| try writeState(state.chain, state.height, @intCast(index + 1), bytes[(index + 1) * STATE_BYTES ..][0..STATE_BYTES]);
    }
    if (reader.offset != records.len) return error.TrailingReplayData;
    return state;
}

/// All buffers must remain valid and immutable through the call. Output is
/// meaningful only on return 0. No native state survives a failed replay, and
/// no files are read or written by this bridge.
export fn lattica_v2_research_host_replay_v1(
    registry_ptr: [*c]const u8,
    registry_len: usize,
    context_ptr: [*c]const u8,
    context_len: usize,
    genesis_ptr: [*c]const u8,
    genesis_len: usize,
    records_ptr: [*c]const u8,
    records_len: usize,
    output_ptr: [*c]u8,
    output_len: usize,
) callconv(.c) i32 {
    if (registry_ptr == null or context_ptr == null or genesis_ptr == null or records_ptr == null or output_ptr == null or
        registry_len < 8 or registry_len > ffi.MAX_BLOCK_V2_REGISTRY_BYTES or context_len != 64 or
        genesis_len < 68 or genesis_len > MAX_GENESIS_BYTES or records_len < 12 or records_len > MAX_REPLAY_BYTES or
        output_len < STATE_BYTES) return -1;
    var state = restore(registry_ptr[0..registry_len], context_ptr[0..context_len], genesis_ptr[0..genesis_len], records_ptr[0..records_len], output_ptr[0..output_len]) catch return -2;
    defer state.chain.deinit();
    return 0;
}

/// Fresh delivery fixture funding; old genesis/wallet APIs remain unchanged.
export fn lattica_v2_research_delivery_genesis_v1(
    slots: u32,
    output: [*c]u8,
    cap: usize,
    output_len: [*c]usize,
) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (slots == 0 or slots > fixture.MAX_DELIVERY_SLOTS or output == null or cap == 0 or cap > MAX_GENESIS_BYTES) return -1;
    const size = fixture.deliveryGenesis(slots, output[0..cap]) catch return -2;
    output_len[0] = size;
    return 0;
}

/// Verify/replay the complete published branch before preparing one fresh leaf.
/// Records use the same independently supplied grants as host_replay_v1.
/// A caller must fence eventual submission against this history's head token.
export fn lattica_v2_research_delivery_wallet_v1(
    registry_ptr: [*c]const u8,
    registry_len: usize,
    context_ptr: [*c]const u8,
    context_len: usize,
    genesis_ptr: [*c]const u8,
    genesis_len: usize,
    records_ptr: [*c]const u8,
    records_len: usize,
    index: u32,
    output: [*c]u8,
    cap: usize,
    output_len: [*c]usize,
) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (registry_ptr == null or context_ptr == null or genesis_ptr == null or records_ptr == null or output == null or registry_len < 8 or registry_len > ffi.MAX_BLOCK_V2_REGISTRY_BYTES or context_len != 64 or genesis_len < 68 or genesis_len > MAX_GENESIS_BYTES or records_len < 12 or records_len > MAX_REPLAY_BYTES or index >= fixture.MAX_DELIVERY_SLOTS or cap == 0 or cap > fixture.MAX_EXPORT_BYTES) return -1;
    if (!std.mem.eql(u8, context_ptr[32..64], &fixture.CHAIN)) return -2;
    var state = restore(registry_ptr[0..registry_len], context_ptr[0..context_len], genesis_ptr[0..genesis_len], records_ptr[0..records_len], null) catch return -2;
    defer state.chain.deinit();
    const size = fixture.deliveryWallet(index, &state.chain, state.height + 1, output[0..cap]) catch return -2;
    output_len[0] = size;
    return 0;
}

// Research v2: bounded opaque sessions retain only verified native state. The
// caller still owns durable history and must replay published records after
// restart/reorg. A session is never a checkpoint authentication mechanism.
const Session = struct {
    state: Genesis,
    registry: []u8,
    context: commitment.Context,
    blocks: u64 = 0,
    poisoned: bool = false,
};
const SessionSlot = struct { generation: u64 = 0, value: ?Session = null };
var session_slots: [16]SessionSlot = @splat(.{});
var session_lock = std.atomic.Value(bool).init(false);

fn lockSessions() void {
    while (session_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}
fn unlockSessions() void {
    session_lock.store(false, .release);
}
fn sessionFor(handle: u64) ?*Session {
    const index = handle & 255;
    if (index == 0 or index > session_slots.len) return null;
    const slot = &session_slots[@intCast(index - 1)];
    if (slot.generation != handle >> 8) return null;
    if (slot.value) |*value| return value;
    return null;
}

export fn lattica_v2_research_session_open_v2(
    registry_ptr: [*c]const u8,
    registry_len: usize,
    context_ptr: [*c]const u8,
    context_len: usize,
    genesis_ptr: [*c]const u8,
    genesis_len: usize,
    handle_ptr: [*c]u64,
) callconv(.c) i32 {
    if (handle_ptr == null) return -1;
    handle_ptr[0] = 0;
    if (registry_ptr == null or context_ptr == null or genesis_ptr == null or
        registry_len < 8 or registry_len > ffi.MAX_BLOCK_V2_REGISTRY_BYTES or
        context_len != 64 or genesis_len < 68 or genesis_len > MAX_SESSION_GENESIS_BYTES) return -1;
    if (!ffi.hasBlockV2ResearchBackend() or !std.mem.startsWith(u8, registry_ptr[0..registry_len], "LBV2RG01")) return -2;
    lockSessions();
    defer unlockSessions();
    for (&session_slots, 0..) |*slot, index| {
        if (slot.value != null or slot.generation == std.math.maxInt(u56)) continue;
        var state = initialStateBounded(std.heap.page_allocator, genesis_ptr[0..genesis_len], MAX_SESSION_GENESIS_BYTES, MAX_SESSION_GENESIS_NOTES) catch return -2;
        const registry = std.heap.page_allocator.dupe(u8, registry_ptr[0..registry_len]) catch {
            state.chain.deinit();
            return -2;
        };
        slot.generation += 1;
        slot.value = .{ .state = state, .registry = registry, .context = .{ .profile_id = context_ptr[0..32].*, .chain_id = context_ptr[32..64].* } };
        handle_ptr[0] = (slot.generation << 8) | (index + 1);
        return 0;
    }
    return -3;
}

export fn lattica_v2_research_session_close_v2(handle: u64) callconv(.c) i32 {
    lockSessions();
    defer unlockSessions();
    const session = sessionFor(handle) orelse return -1;
    session.state.chain.deinit();
    std.heap.page_allocator.free(session.registry);
    session_slots[@intCast((handle & 255) - 1)].value = null;
    return 0;
}

export fn lattica_v2_research_session_state_v2(handle: u64, output: [*c]u8, cap: usize) callconv(.c) i32 {
    if (output == null or cap != STATE_BYTES) return -1;
    lockSessions();
    defer unlockSessions();
    const session = sessionFor(handle) orelse return -1;
    if (session.poisoned) return -2;
    writeState(session.state.chain, session.state.height, session.blocks, output[0..cap]) catch return -2;
    return 0;
}

fn sessionApply(session: *Session, packet: []const u8) !void {
    var reader = body.Reader{ .bytes = packet };
    if (!std.mem.eql(u8, try reader.take(8), REPLAY_MAGIC) or try reader.uint(u32) != 1) return error.InvalidReplayVersion;
    const height = try reader.uint(u64);
    const body_len = try reader.uint(u32);
    const proof_len = try reader.uint(u64);
    const count = try reader.uint(u32);
    if (height != session.state.height + 1 or height >= node.MAX_RANGE_VALUE or
        body_len > body.MAX_BODY_BYTES or proof_len == 0 or proof_len > ffi.MAX_PROOF_LEN or
        count == 0 or count > commitment.CAPACITY or session.blocks == std.math.maxInt(u64)) return error.InvalidRecord;
    var grants: [commitment.CAPACITY]u64 = undefined;
    for (grants[0..count]) |*grant| grant.* = try reader.uint(u64);
    const decoded = try body.decode(try reader.take(body_len));
    if (decoded.count != count) return error.InvalidGrantCount;
    const proof = try reader.take(@intCast(proof_len));
    if (reader.offset != packet.len) return error.TrailingReplayData;
    try session.state.chain.applyBlockV2Research(session.context, session.registry, decoded.transactions(), proof, height, grants[0..count]);
    session.state.height = height;
    session.blocks += 1;
}

export fn lattica_v2_research_session_apply_v2(handle: u64, packet: [*c]const u8, packet_len: usize, output: [*c]u8, cap: usize) callconv(.c) i32 {
    const max_record = 12 + 24 + commitment.CAPACITY * 8 + body.MAX_BODY_BYTES + ffi.MAX_PROOF_LEN;
    if (packet == null or packet_len < 36 or packet_len > max_record or output == null or cap != STATE_BYTES) return -1;
    lockSessions();
    defer unlockSessions();
    const session = sessionFor(handle) orelse return -1;
    if (session.poisoned) return -2;
    sessionApply(session, packet[0..packet_len]) catch {
        // Even allocation/application failures require reconstruction from
        // durable history. Never serve state after an indeterminate mutation.
        session.poisoned = true;
        return -2;
    };
    writeState(session.state.chain, session.state.height, session.blocks, output[0..cap]) catch {
        session.poisoned = true;
        return -2;
    };
    return 0;
}

export fn lattica_v2_research_session_preflight_v2(
    handle: u64,
    body_ptr: [*c]const u8,
    body_len: usize,
    height: u64,
    grants_ptr: [*c]const u8,
    grants_len: usize,
    output: [*c]u8,
    cap: usize,
    output_len: [*c]usize,
) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (body_ptr == null or grants_ptr == null or output == null or body_len < body.HEADER_LEN or
        body_len > body.MAX_BODY_BYTES or grants_len == 0 or grants_len > commitment.CAPACITY * 8 or
        cap < 120 or cap > MAX_PREFLIGHT_BYTES) return -1;
    lockSessions();
    defer unlockSessions();
    const session = sessionFor(handle) orelse return -1;
    if (session.poisoned or height != session.state.height + 1 or height >= node.MAX_RANGE_VALUE) return -2;
    const decoded = body.decode(body_ptr[0..body_len]) catch return -2;
    if (grants_len != decoded.count * 8) return -2;
    var grants: [commitment.CAPACITY]u64 = undefined;
    var reader = body.Reader{ .bytes = grants_ptr[0..grants_len] };
    for (grants[0..decoded.count]) |*grant| grant.* = reader.uint(u64) catch return -2;
    const checked = session.state.chain.validateBlockV2Research(session.context, decoded.transactions(), height, grants[0..decoded.count]) catch return -2;
    var writer = body.Writer{ .bytes = output[0..cap] };
    writer.put(PREFLIGHT_MAGIC) catch return -1;
    writer.put(&checked.expected.encode()) catch return -1;
    for (decoded.transactions()) |item| {
        const kind: u8 = switch (item) {
            .joinsplit => 0,
            .htlc => |h| if (h.redeem_preimage != null) 1 else 2,
            .issuance => 3,
        };
        var fields: [31]u64 = undefined;
        const count = item.statement(&fields) catch return -2;
        writer.uint(u8, kind) catch return -1;
        writer.uint(u8, @intCast(count)) catch return -1;
        for (fields[0..count]) |field| writer.uint(u64, field) catch return -1;
    }
    output_len[0] = writer.offset;
    return 0;
}

export fn lattica_v2_research_session_wallet_v2(handle: u64, index: u32, output: [*c]u8, cap: usize, output_len: [*c]usize) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len[0] = 0;
    if (index >= fixture.MAX_DELIVERY_SLOTS or output == null or cap == 0 or cap > fixture.MAX_EXPORT_BYTES) return -1;
    lockSessions();
    defer unlockSessions();
    const session = sessionFor(handle) orelse return -1;
    if (session.poisoned or !std.mem.eql(u8, &session.context.chain_id, &fixture.CHAIN)) return -2;
    const size = fixture.deliveryWallet(index, &session.state.chain, session.state.height + 1, output[0..cap]) catch return -2;
    output_len[0] = size;
    return 0;
}

/// Versioned funded workload for long research campaigns. Legacy fixtures and
/// the production protocol are unaffected; the host pins this genesis exactly.
export fn lattica_v2_research_sustained_genesis_v2(slots: u32, output: ?[*]u8, cap: usize, output_len: ?*usize) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len.?.* = 0;
    if (slots == 0 or slots > fixture.MAX_SUSTAINED_SLOTS or output == null or cap < 68 or cap > MAX_SESSION_GENESIS_BYTES) return -1;
    const size = fixture.sustainedGenesis(slots, output.?[0..cap]) catch return -2;
    output_len.?.* = size;
    return 0;
}

export fn lattica_v2_research_session_sustained_wallet_v2(handle: u64, index: u32, output: ?[*]u8, cap: usize, output_len: ?*usize) callconv(.c) i32 {
    if (output_len == null) return -1;
    output_len.?.* = 0;
    if (output == null or cap == 0 or cap > fixture.MAX_EXPORT_BYTES or index >= fixture.MAX_SUSTAINED_SLOTS) return -1;
    lockSessions();
    defer unlockSessions();
    const session = sessionFor(handle) orelse return -2;
    if (session.poisoned or !std.mem.eql(u8, &session.context.chain_id, &fixture.CHAIN)) return -2;
    const size = fixture.sustainedWallet(index, &session.state.chain, session.state.height + 1, output.?[0..cap]) catch return -2;
    output_len.?.* = size;
    return 0;
}
