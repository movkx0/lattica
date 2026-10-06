//! Bounded complete public bodies for the opt-in research host.
//! Detached recursive proofs, trusted context and issuance grants are separate.
//! This is a local research encoding, not an activated consensus wire format.
const std = @import("std");
const node = @import("node.zig");
const commitment = @import("block_v2.zig");
const p = @import("primitives.zig");
const tx = @import("tx.zig");

pub const Transaction = node.BlockV2ResearchTransaction;
pub const MAGIC = "LBV2BD01";
pub const HEADER_LEN: usize = MAGIC.len + 4;
const COMMON_LEN = 1 + 32 + node.N_IN * 32 + 16;
const NOTE_FIXED_LEN = 32 + p.CT_LEN + 2;
pub const MAX_BODY_BYTES: usize = HEADER_LEN + commitment.CAPACITY *
    (COMMON_LEN + 8 + 1 + 32 + node.M_OUT * (NOTE_FIXED_LEN + node.MAX_NOTE_CIPHERTEXT_LEN));
pub const Error = error{
    InvalidLength,
    InvalidVersion,
    InvalidCount,
    InvalidKind,
    InvalidPreimageFlag,
    NonCanonicalField,
    OversizeOutput,
    OversizeValue,
    NoSpace,
};

pub const Writer = struct {
    bytes: []u8,
    offset: usize = 0,

    pub fn put(self: *Writer, bytes: []const u8) Error!void {
        if (bytes.len > self.bytes.len - self.offset) return error.NoSpace;
        @memcpy(self.bytes[self.offset..][0..bytes.len], bytes);
        self.offset += bytes.len;
    }

    pub fn uint(self: *Writer, comptime T: type, value: T) Error!void {
        var bytes: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &bytes, value, .little);
        try self.put(&bytes);
    }

    pub fn digest(self: *Writer, bytes: [32]u8) Error!void {
        _ = commitment.digestFromBytes(&bytes) catch return error.NonCanonicalField;
        try self.put(&bytes);
    }
};

pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn take(self: *Reader, size: usize) Error![]const u8 {
        if (size > self.bytes.len - self.offset) return error.InvalidLength;
        const bytes = self.bytes[self.offset..][0..size];
        self.offset += size;
        return bytes;
    }

    pub fn array(self: *Reader, comptime size: usize) Error![size]u8 {
        return (try self.take(size))[0..size].*;
    }

    pub fn uint(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    pub fn digest(self: *Reader) Error![32]u8 {
        const bytes = try self.array(32);
        _ = commitment.digestFromBytes(&bytes) catch return error.NonCanonicalField;
        return bytes;
    }
};

pub fn encodedSize(transactions: []const Transaction) Error!usize {
    if (transactions.len == 0 or transactions.len > commitment.CAPACITY) return error.InvalidCount;
    var size: usize = HEADER_LEN;
    for (transactions) |item| {
        const t = item.common();
        if (t.fee >= node.MAX_RANGE_VALUE or t.mint >= node.MAX_RANGE_VALUE) return error.OversizeValue;
        size += COMMON_LEN;
        if (item == .htlc) {
            if (item.htlc.current_height >= node.MAX_RANGE_VALUE) return error.OversizeValue;
            size += 8 + 1 + @as(usize, if (item.htlc.redeem_preimage != null) 32 else 0);
        }
        for (t.outputs) |output| {
            if (output.ciphertext.len > node.MAX_NOTE_CIPHERTEXT_LEN) return error.OversizeOutput;
            size += NOTE_FIXED_LEN + output.ciphertext.len;
        }
    }
    return size;
}

/// Copies every public body field. Inner wallet proof bytes are omitted: this
/// encoding is accepted only together with a separately verified recursive root.
pub fn encode(transactions: []const Transaction, buffer: []u8) Error![]const u8 {
    const size = try encodedSize(transactions);
    if (buffer.len < size) return error.NoSpace;
    var writer = Writer{ .bytes = buffer[0..size] };
    try writer.put(MAGIC);
    try writer.uint(u32, @intCast(transactions.len));
    for (transactions) |item| {
        const t = item.common();
        try writer.uint(u8, @intFromEnum(item.kind()));
        try writer.digest(t.anchor);
        for (t.nullifiers) |nf| try writer.digest(nf);
        try writer.uint(u64, t.fee);
        try writer.uint(u64, t.mint);
        if (item == .htlc) {
            try writer.uint(u64, item.htlc.current_height);
            try writer.uint(u8, if (item.htlc.redeem_preimage != null) 1 else 0);
            if (item.htlc.redeem_preimage) |preimage| try writer.put(&preimage);
        }
        for (t.outputs) |output| {
            try writer.digest(output.cm);
            try writer.put(&output.kem_ct);
            try writer.uint(u16, @intCast(output.ciphertext.len));
            try writer.put(output.ciphertext);
        }
    }
    std.debug.assert(writer.offset == size);
    return buffer[0..size];
}

pub const Decoded = struct {
    values: [commitment.CAPACITY]Transaction,
    count: usize,

    /// Ciphertext slices borrow the input buffer, which must remain immutable
    /// and alive through verification/application. Chain application copies them.
    pub fn transactions(self: *const Decoded) []const Transaction {
        return self.values[0..self.count];
    }
};

/// No heap allocation or untrusted allocation hints. Rejects trailing bytes,
/// unsupported tags, noncanonical field encodings and oversized ciphertexts.
/// Returned ciphertext slices borrow `bytes`; keep it alive until the decoded
/// transactions are consumed. Chain application makes its own owned copies.
pub fn decode(bytes: []const u8) Error!Decoded {
    if (bytes.len < HEADER_LEN or bytes.len > MAX_BODY_BYTES) return error.InvalidLength;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try reader.take(MAGIC.len), MAGIC)) return error.InvalidVersion;
    const count = try reader.uint(u32);
    if (count == 0 or count > commitment.CAPACITY) return error.InvalidCount;
    var decoded: Decoded = .{ .values = undefined, .count = count };
    for (decoded.values[0..count]) |*item| {
        const kind = commitment.Kind.fromCode(try reader.uint(u8)) catch return error.InvalidKind;
        const anchor = try reader.digest();
        var nullifiers: [node.N_IN][32]u8 = undefined;
        for (&nullifiers) |*nf| nf.* = try reader.digest();
        const fee = try reader.uint(u64);
        const mint = try reader.uint(u64);
        if (fee >= node.MAX_RANGE_VALUE or mint >= node.MAX_RANGE_VALUE) return error.OversizeValue;
        var height: u64 = 0;
        var preimage: ?[32]u8 = null;
        if (kind == .htlc) {
            height = try reader.uint(u64);
            if (height >= node.MAX_RANGE_VALUE) return error.OversizeValue;
            switch (try reader.uint(u8)) {
                0 => {},
                1 => preimage = try reader.array(32),
                else => return error.InvalidPreimageFlag,
            }
        }
        var outputs: [node.M_OUT]tx.TransmittedNote = undefined;
        for (&outputs) |*output| {
            const cm = try reader.digest();
            const kem_ct = try reader.array(p.CT_LEN);
            const size = try reader.uint(u16);
            if (size > node.MAX_NOTE_CIPHERTEXT_LEN) return error.OversizeOutput;
            output.* = .{ .cm = cm, .kem_ct = kem_ct, .ciphertext = try reader.take(size) };
        }
        const common = node.ShieldedTx{ .anchor = anchor, .nullifiers = nullifiers, .fee = fee, .mint = mint, .proof = &.{}, .outputs = outputs };
        item.* = switch (kind) {
            .join_split => .{ .joinsplit = common },
            .coinbase => .{ .issuance = common },
            .htlc => .{ .htlc = .{ .anchor = anchor, .nullifiers = nullifiers, .fee = fee, .mint = mint, .proof = &.{}, .outputs = outputs, .current_height = height, .redeem_preimage = preimage } },
        };
    }
    if (reader.offset != bytes.len) return error.InvalidLength;
    return decoded;
}

fn testBodies() [4]Transaction {
    const t = node.ShieldedTx{ .anchor = [_]u8{1} ** 32, .nullifiers = .{ [_]u8{2} ** 32, [_]u8{3} ** 32 }, .fee = 0, .mint = 0, .proof = "excluded-inner-proof", .outputs = .{
        .{ .cm = [_]u8{4} ** 32, .kem_ct = [_]u8{5} ** p.CT_LEN, .ciphertext = "first" },
        .{ .cm = [_]u8{6} ** 32, .kem_ct = [_]u8{7} ** p.CT_LEN, .ciphertext = "second" },
    } };
    var redeem = node.ShieldedHtlcTx{ .anchor = t.anchor, .nullifiers = t.nullifiers, .fee = 0, .mint = 0, .proof = t.proof, .outputs = t.outputs, .current_height = 10, .redeem_preimage = [_]u8{9} ** 32 };
    var result: [4]Transaction = .{ .{ .joinsplit = t }, .{ .htlc = redeem }, undefined, .{ .issuance = t } };
    redeem.redeem_preimage = null;
    result[2] = .{ .htlc = redeem };
    result[3].issuance.mint = 7;
    return result;
}

test "research body: mixed roundtrip preserves complete-body root and exact bytes" {
    const bodies = testBodies();
    var buffer: [MAX_BODY_BYTES]u8 = undefined;
    const encoded = try encode(&bodies, &buffer);
    const decoded = try decode(encoded);
    try std.testing.expectEqual(@as(usize, 4), decoded.count);
    const context = commitment.Context{ .profile_id = [_]u8{11} ** 32, .chain_id = [_]u8{12} ** 32 };
    const expected = try node.blockV2ResearchExpected(context, &bodies);
    try std.testing.expectEqualDeep(expected, try node.blockV2ResearchExpected(context, decoded.transactions()));
    for (decoded.transactions()) |item| try std.testing.expectEqual(@as(usize, 0), item.common().proof.len);
    var again: [MAX_BODY_BYTES]u8 = undefined;
    try std.testing.expectEqualSlices(u8, encoded, try encode(decoded.transactions(), &again));
    try std.testing.expectEqualSlices(u8, "first", decoded.values[1].htlc.outputs[0].ciphertext);
    try std.testing.expectEqual(bodies[1].htlc.redeem_preimage, decoded.values[1].htlc.redeem_preimage);
    try std.testing.expectEqual(@as(?[32]u8, null), decoded.values[2].htlc.redeem_preimage);
}

test "research body: every truncated prefix and trailing bytes reject" {
    const bodies = testBodies();
    var buffer: [MAX_BODY_BYTES]u8 = undefined;
    const encoded = try encode(&bodies, &buffer);
    for (0..encoded.len) |size| {
        if (decode(encoded[0..size])) |_| return error.AcceptedTruncatedBody else |_| {}
    }
    buffer[encoded.len] = 0;
    try std.testing.expectError(error.InvalidLength, decode(buffer[0 .. encoded.len + 1]));
}

test "research body: version, kinds, counts, flags and field aliases reject" {
    const bodies = testBodies();
    var buffer: [MAX_BODY_BYTES]u8 = undefined;
    var encoded = try encode(&bodies, &buffer);
    buffer[7] ^= 1;
    try std.testing.expectError(error.InvalidVersion, decode(encoded));
    buffer[7] ^= 1;
    for ([_]u32{ 0, 65, std.math.maxInt(u32) }) |count| {
        std.mem.writeInt(u32, buffer[8..12], count, .little);
        try std.testing.expectError(error.InvalidCount, decode(encoded));
    }
    encoded = try encode(&bodies, &buffer);
    buffer[HEADER_LEN] = 0;
    try std.testing.expectError(error.InvalidKind, decode(encoded));
    encoded = try encode(&bodies, &buffer);
    @memset(buffer[HEADER_LEN + 1 ..][0..8], 255);
    try std.testing.expectError(error.NonCanonicalField, decode(encoded));
    encoded = try encode(&bodies, &buffer);
    const flag_offset = (try encodedSize(bodies[0..1])) + COMMON_LEN + 8;
    buffer[flag_offset] = 2;
    try std.testing.expectError(error.InvalidPreimageFlag, decode(encoded));
}

test "research body: size and range limits apply before application" {
    var bodies = testBodies();
    var buffer: [MAX_BODY_BYTES]u8 = undefined;
    const encoded = try encode(&bodies, &buffer);
    const length_offset = HEADER_LEN + COMMON_LEN + 32 + p.CT_LEN;
    std.mem.writeInt(u16, buffer[length_offset..][0..2], node.MAX_NOTE_CIPHERTEXT_LEN + 1, .little);
    try std.testing.expectError(error.OversizeOutput, decode(encoded));
    bodies[1].htlc.current_height = node.MAX_RANGE_VALUE;
    try std.testing.expectError(error.OversizeValue, encode(&bodies, &buffer));
    bodies = testBodies();
    bodies[0].joinsplit.fee = node.MAX_RANGE_VALUE;
    try std.testing.expectError(error.OversizeValue, encode(&bodies, &buffer));
    bodies = testBodies();
    try std.testing.expectError(error.NoSpace, encode(&bodies, buffer[0..1]));
    try std.testing.expectError(error.InvalidCount, encode(&.{}, &buffer));
}
