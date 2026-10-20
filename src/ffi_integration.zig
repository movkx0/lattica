//! End-to-end FFI integration test: **prove (Rust) → verify (Rust, across the C ABI) →
//! double-spend rejected**, linking the real `lattica-prover-p3` staticlib.
//!
//! Run: build the staticlib first (`cd lattica-prover-p3 && cargo build --release`), then
//! `zig build test-ffi`. Demonstrates the production verify seam on a real join-split proof, that
//! the protocol-side `poseidon2.zig` hashes equal the circuit's public inputs (C-03), and the node's
//! nullifier-set double-spend check.
//!
//! NOTE: on hosts whose `crt1.o` carries a `.sframe` section (gcc/binutils ≥ ~2025), Zig 0.16's
//! linkers can't link the libc-dependent Rust staticlib here. The identical flow, linked with the
//! system toolchain, is in `lattica-prover-p3/tests/ffi_integration.c` (run via `cc … .a` — verified
//! passing). This Zig version is the node-side test for a toolchain whose linker handles the host crt.

const std = @import("std");
const ffi = @import("ffi.zig");
const poseidon2 = @import("poseidon2.zig");
const testing = std.testing;

// The production C ABI implemented by the prover crate (extern declarations centralized in
// prover_abi.zig, mirroring lattica-prover-p3/include/lattica_prover_p3.h).
const prover_abi = @import("prover_abi.zig");
const prover_options = @import("prover_options");
pub const lattica_block_capacity = prover_options.block_capacity;
const prover_runtime = @import("prover_runtime.zig");
const lattica_joinsplit_prove_demo = prover_abi.lattica_joinsplit_prove_demo;
const lattica_joinsplit_verify = prover_abi.lattica_joinsplit_verify;
const lattica_htlc_prove_demo = prover_abi.lattica_htlc_prove_demo;
const lattica_htlc_verify = prover_abi.lattica_htlc_verify;

fn finishGpu() !void {
    if (!prover_options.gpu_prover) return;
    try prover_runtime.Gpu.drain();
    try prover_runtime.Gpu.shutdown();
    try testing.expectError(error.NoProveBackend, ffi.proveJoinSplit(testing.allocator, &.{}));
    try testing.expectError(error.NoProveBackend, ffi.proveHtlc(testing.allocator, &.{}));
    try testing.expectError(error.NoProveBackend, ffi.proveBatch(testing.allocator, &.{}, 0));
    try testing.expectError(error.NoProveBackend, ffi.proveHtlcBatch(testing.allocator, &.{}, 0));
    try testing.expectError(error.NoProveBackend, ffi.proveJoinSplitTree(testing.allocator, &.{}, 1));
    try testing.expect(ffi.hasJoinSplitBackend());
    try testing.expect(ffi.hasHtlcBackend());
    try testing.expect(ffi.hasBatchBackend());
}

// CUDA requires a fresh process after shutdown. Exercise the GPU routes in
// one admitted lifetime and audit the retained outputs after retirement.
test "ffi integration: GPU wallet routes share one lifetime" {
    if (!prover_options.gpu_prover) return error.SkipZigTest;
    ffi.clearJoinSplitTreeBackend();
    try prover_runtime.Gpu.initialize();
    errdefer prover_runtime.Gpu.shutdown() catch {};
    try testing.expect(!ffi.hasJoinSplitTreeBackend());
    try testing.expect(ffi.hasJoinSplitTreeProveBackend());
    var joinsplit = try proveDemo(lattica_joinsplit_prove_demo, ffi.JoinSplitPublicInputs.ENCODED_LEN);
    defer joinsplit.deinit();
    var htlc = try proveDemo(lattica_htlc_prove_demo, ffi.HtlcPublicInputs.ENCODED_LEN);
    defer htlc.deinit();
    const witnesses = [_]u8{0} ** (3 * 2464);
    const tree = try ffi.proveJoinSplitTree(testing.allocator, &witnesses, 3);
    defer testing.allocator.free(tree.proof);
    try finishGpu();
    if (prover_options.gpu_backend == .cuda) {
        try testing.expectEqual(prover_abi.GPU_REJECTED, prover_abi.lattica_gpu_initialize_from_env());
    }
    try auditJoinSplit(&joinsplit);
    try auditHtlc(&htlc);
    try testing.expect(!ffi.hasJoinSplitTreeBackend());
    ffi.setJoinSplitTreeBackend(&prover_abi.lattica_joinsplit_tree_verify);
    defer ffi.clearJoinSplitTreeBackend();
    try testing.expect(ffi.verifyJoinSplitTree(tree.proof, tree.root, 3));
    try testing.expect(!ffi.verifyJoinSplitTree(tree.proof, tree.root, 2));
    var changed = tree.root;
    changed[0] ^= 1;
    try testing.expect(!ffi.verifyJoinSplitTree(tree.proof, changed, 3));
}

const DemoProof = struct {
    buffer: []u8,
    proof_len: usize = 0,
    pi: [256]u8 = undefined,
    pi_len: usize = 0,

    fn deinit(self: DemoProof) void {
        testing.allocator.free(self.buffer);
    }
};

fn proveDemo(comptime call: anytype, expected_public_len: usize) !DemoProof {
    var result = DemoProof{ .buffer = try testing.allocator.alloc(u8, 1 << 20) };
    errdefer result.deinit();
    try testing.expectEqual(@as(i32, 0), call(result.buffer.ptr, result.buffer.len, &result.proof_len, &result.pi, result.pi.len, &result.pi_len));
    try testing.expect(result.proof_len > 0 and result.proof_len <= result.buffer.len);
    try testing.expectEqual(expected_public_len, result.pi_len);
    return result;
}

const NullifierSet = std.AutoHashMap([32]u8, void);

/// Node-side spend application: verify the proof, then reject if any nullifier is already spent;
/// otherwise insert them. Returns true iff the spend is accepted.
fn applySpend(set: *NullifierSet, proof: []const u8, pi: []const u8, nfs: []const [32]u8) !bool {
    if (lattica_joinsplit_verify(proof.ptr, proof.len, pi.ptr, pi.len) != 0) return false;
    for (nfs) |nf| if (set.contains(nf)) return false; // double-spend
    for (nfs) |nf| try set.put(nf, {});
    return true;
}

test "ffi integration: prove(rust) -> verify -> double-spend rejected" {
    if (prover_options.gpu_prover) return error.SkipZigTest;
    var output = try proveDemo(lattica_joinsplit_prove_demo, ffi.JoinSplitPublicInputs.ENCODED_LEN);
    defer output.deinit();
    try auditJoinSplit(&output);
}

fn auditJoinSplit(output: *DemoProof) !void {
    const a = testing.allocator;
    const proof_bytes = output.buffer[0..output.proof_len];
    const pi = &output.pi;
    const pi_bytes = pi[0..output.pi_len];
    // 2. The real Rust verifier accepts the real proof (the node's verify seam).
    ffi.setJoinSplitBackend(&lattica_joinsplit_verify); // node installs it at startup
    try testing.expectEqual(@as(i32, 0), lattica_joinsplit_verify(proof_bytes.ptr, proof_bytes.len, pi_bytes.ptr, pi_bytes.len));

    // 3. C-03: the protocol's poseidon2 hashes equal the circuit's public inputs.
    //    Demo input 0 is nk=(7,700), rho=(11,211) at position 0 ⇒ nf_0 = H(DOM_NF, 7, 700, 11, 211, 0).
    const nf0 = poseidon2.digestBytes(poseidon2.nullifierHash(7, 700, .{ 11, 211 }, 0));
    try testing.expectEqualSlices(u8, nf0[0..], pi_bytes[32..64]);

    // 4. Tampered public inputs are rejected.
    pi[0] +%= 1;
    try testing.expect(lattica_joinsplit_verify(proof_bytes.ptr, proof_bytes.len, pi_bytes.ptr, pi_bytes.len) != 0);
    pi[0] -%= 1;

    // 5. Double-spend: the node's nullifier set accepts the first spend, rejects the replay.
    var set = NullifierSet.init(a);
    defer set.deinit();
    var nf_a: [32]u8 = undefined;
    @memcpy(&nf_a, pi_bytes[32..64]); // nf_0
    var nf_b: [32]u8 = undefined;
    @memcpy(&nf_b, pi_bytes[64..96]); // nf_1
    const nfs = [_][32]u8{ nf_a, nf_b };
    try testing.expect(try applySpend(&set, proof_bytes, pi_bytes, &nfs)); // first spend accepted
    try testing.expect(!(try applySpend(&set, proof_bytes, pi_bytes, &nfs))); // replay rejected
}

test "ffi integration: real HTLC prove(rust) -> verify -> tamper rejected" {
    if (prover_options.gpu_prover) return error.SkipZigTest;
    var output = try proveDemo(lattica_htlc_prove_demo, ffi.HtlcPublicInputs.ENCODED_LEN);
    defer output.deinit();
    try auditHtlc(&output);
}

fn auditHtlc(output: *DemoProof) !void {
    const pb = output.buffer[0..output.proof_len];
    const pi = &output.pi;
    const pi_len = output.pi_len;
    const pib = pi[0..pi_len];
    // 2. The real Rust HTLC verifier accepts the real proof (the node's verifyHtlc seam).
    ffi.setHtlcBackend(&lattica_htlc_verify);
    try testing.expectEqual(@as(i32, 0), lattica_htlc_verify(pb.ptr, pb.len, pib.ptr, pib.len));

    // 3. C-03: the demo HTLC note's owner = htlc_root(redeem_tag, refund_tag, hashlock, timeout) and
    //    its owner-based nullifier (Zig poseidon2) equal the circuit's public inputs. Demo: redeem
    //    party (7,70,div=1), refund party (9,90,div=2), hashlock [81,82,83,84], timeout 10, rho (11,211).
    const rt = poseidon2.recipient(7, 70, 1);
    const ft = poseidon2.recipient(9, 90, 2);
    const owner = poseidon2.htlcRoot(rt, ft, .{ 81, 82, 83, 84 }, 10);
    const nf0 = poseidon2.digestBytes(poseidon2.nullifierHtlc(owner, .{ 11, 211 }, 0));
    try testing.expectEqualSlices(u8, nf0[0..], pib[32..64]); // nf_0 (after the anchor)
    const hl = poseidon2.digestBytes(.{ 81, 82, 83, 84 });
    try testing.expectEqualSlices(u8, hl[0..], pib[pi_len - 32 .. pi_len]); // redeem_hashlock (last field)

    // 4. Tampered public inputs are rejected by the real verifier.
    pi[0] +%= 1;
    try testing.expect(lattica_htlc_verify(pb.ptr, pb.len, pib.ptr, pib.len) != 0);
}
