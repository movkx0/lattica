/* lattica_prover_p3.h — the C ABI of liblattica_prover_p3.a (single source of truth).
 *
 * The Zig node's extern declarations (src/ffi_integration.zig, src/integration_node.zig) and the C
 * integration test (tests/ffi_integration.c) mirror these EXACT signatures; the Rust definitions live
 * in lattica-prover-p3/src/lib.rs (#[no_mangle] extern "C"). Changing anything here is a node-seam
 * (and, for the wire formats, consensus) break.
 *
 * CONVENTIONS
 *   - Return codes: verify → 0 = accept, nonzero = reject (fail-closed).
 *                   prove  → 0 = ok, 1 = malformed/invalid input or internal failure, 2 = an output
 *                   buffer was too small. On rc=2 the *_len outputs are NOT written (the caps are
 *                   checked before any store); size the buffers from MAX_PROOF_LEN / the fixed PI
 *                   widths. *_len are written only on rc=0.
 *   - No call unwinds across the boundary (Rust catches panics); NULL pointers fail closed.
 *   - proof bytes: postcard-serialized p3-uni-stark Proof under the production config (see
 *     src/config.rs; pinned to p3 0.6.1 + the production FRI parameters). Verify rejects
 *     proof_len > MAX_PROOF_LEN (1 << 21, mirrored by src/ffi.zig).
 *   - digests: 32 bytes = 4 canonical little-endian Goldilocks u64 limbs (non-canonical ⇒ reject).
 *   - public inputs (little-endian, byte-exact):
 *       join-split (208 B): anchor(32) ‖ nf0(32) ‖ nf1(32) ‖ out_cm0(32) ‖ out_cm1(32) ‖
 *                           tx_binding(32) ‖ fee(u64) ‖ mint(u64)
 *       HTLC (248 B):       the join-split layout ‖ current_height(u64) ‖ redeem_hashlock(32)
 *   - witnesses (wallet → prover): fixed-length records; JS_WITNESS_LEN = 2464 B,
 *     HTLC_WITNESS_LEN = 2728 B (field order per src/lib.rs js_witness_len / htlc_witness_len).
 *     Batch proving takes n_tx concatenated records (witness_len must equal n_tx * record length;
 *     1 ≤ padded_tiles(n_tx) ≤ MAX_BATCH_TILES = 64).
 */
#ifndef LATTICA_PROVER_P3_H
#define LATTICA_PROVER_P3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Process-local OpenCL prover lifecycle (requires Rust features block-v2,gpu).
 * Returns LATTICA_GPU_OK, LATTICA_GPU_REJECTED, or LATTICA_GPU_UNAVAILABLE.
 * These status codes are separate from the proving buffer-size return codes.
 *
 * Configure the environment once, before starting Rust/native proof work:
 * - LATTICA_GPU_DEVICE_UUID: explicit GPU UUID; no default-device selection.
 * - LATTICA_V2_GPU_MANAGED_BYTES: explicit positive decimal byte allowance.
 * - Set LATTICA_V2_QUOTIENT_FUSION and all of the following GPU switches to 1:
 *   LATTICA_V2_GPU_{HASH,RETAIN_TREES,RESIDENT_LDE,OPENINGS,QUOTIENT_LDE,
 *   QUOTIENT_EVAL,QUOTIENT_RESIDENT,LOOKUP,OPENING_EVAL,FRI_RESIDENT,
 *   PCS_DEVICE_ONLY,WITNESS,RANDOMNESS,TRANSCRIPT}.
 * - Set LATTICA_PROVING_POLICY=gpu-required to enforce device completion.
 *   This policy rejects debug CPU constraint audits; use a release library.
 * - Existing host, storage and engine budgets still apply. Public recursive
 *   worker assignments cannot admit private inputs. Wallet-owned local services
 *   may use LATTICA_WALLET_WORKER_BUDGET with matching cgroup/device budgets.
 * - The legacy LJSTREE1 container uses GPU leaf proofs and root binding when
 *   this backend is selected. Its format and CPU verifier remain unchanged;
 *   it is not a recursive proof or a network-format activation.
 *
 * Initialization never chooses a partial proving path or CPU fallback. Repeated
 * initialization with the same settings is allowed; changing a live engine's
 * UUID or OpenCL index selector is rejected. Backend modes are immutable
 * for the process, including after shutdown. Do not race initialization with
 * Rust lifecycle setup or proof admission; never mutate the environment while
 * calls are active. Native lifecycle calls serialize with one another.
 *
 * drain finishes submitted work and rejects a missing engine. shutdown refuses
 * live retained commitments/device sessions, is idempotent after cleanup, and
 * does not switch the prover back to CPU. Verification never initializes a GPU.
 * The existing proof/public-input bytes and proving entrypoints are unchanged.
 */
enum {
    LATTICA_GPU_OK = 0,
    LATTICA_GPU_REJECTED = 1,
    LATTICA_GPU_UNAVAILABLE = 2
};
int32_t lattica_gpu_initialize_from_env(void);
/* Fresh Linux public recursive worker startup (block-v2 + gpu + stream).
 * Requires gpu-required and the complete owned switches above, plus the
 * existing LATTICA_V2_WORKER_BUDGET assignment matching this process's capped,
 * zero-swap worker/fleet cgroups, CPU/GPU configuration and scratch filesystem.
 * Fleet slices may use lattica-v2-multi.slice or lattica-v2-multi-*.slice;
 * the actual parent must exactly match the assigned slice. Wallet assignments,
 * an existing GPU engine or an existing global Rayon pool reject.
 *
 * This initializes the backend only: it neither approves a registry, installs
 * a verifier, serves proof packets nor authorizes private wallet inputs. Use
 * the existing pinned public worker protocol and independent CPU verification.
 * Admission can irreversibly lower process limits before Rayon starts. Discard
 * the worker process after any failed startup. Failed startup
 * releases a newly created GPU engine. The normal drain/shutdown API applies.
 */
int32_t lattica_gpu_public_worker_initialize_from_env(void);
/* Blocking startup + typed public-worker service + teardown, once in a fresh
 * Linux process. Do not call initialize first. OpenCL uses the same release
 * features, owned GPU switches and enforced assignment as public startup.
 * The opt-in gpu-cuda,block-v2,stream build also supports this complete service
 * in release mode with LATTICA_PROVING_POLICY=gpu-required. Its independently
 * supplied assignment must select backend="cuda" and contain the version-1
 * cuda construction bounds (program_host_bytes, wires, input_values), plus
 * explicit GPU managed, per-allocation, context, headroom and host-output bytes.
 * It uses the same OS/allocator admission and protocol identity. CUDA runtime
 * ownership stays inside this call; separate initialize/drain/shutdown exports
 * remain unavailable in CUDA builds. OpenCL rejects a CUDA assignment.
 * bootstrap is the bounded local execution::native_worker::Bootstrap encoding
 * (1..65536 bytes), supplied by a trusted host independently of worker packets.
 * Its registry, profile, executable, policy context and launch directory are
 * pinned through the existing typed HELLO/JOB/CONTEXT/STOP protocol. This grants
 * no registry approval, verifier activation or private wallet access.
 * socket_fd must be a connected AF_UNIX SOCK_STREAM. It is duplicated; the
 * caller retains ownership and must not perform concurrent I/O on that stream.
 * bootstrap must remain readable and completed_out aligned/writable for this
 * entire call, without overlap or concurrent mutation. Null/invalid lengths
 * reject. Non-null pointers must be valid. completed_out is zero on failure;
 * GPU_OK writes the completed job count only after clean STOP and GPU shutdown.
 * Disconnects/protocol errors reject and attempt GPU cleanup. Exit the worker
 * process after any return; coordinator reservations require observed exit.
 * No call unwinds across this boundary. Uses GPU_* lifecycle statuses above.
 * Admission retains 65537 bytes for the qualified caller's bootstrap buffer
 * (including its EOF probe), plus 65536 bytes for launch-path backing, alongside
 * protocol packets/results. Additional caller-owned storage needs its own
 * allowance; the service cannot infer an allocation's capacity from this pointer.
 * Caller stack admission reserves 8 MiB plus bounded guards/signal backing.
 * Keep that stack and its alternate stack within the admitted bounds for the
 * entire call. Main-thread callers must keep RLIMIT_STACK <= 8 MiB; raising it
 * after admission invalidates the resource contract. Other caller threads and
 * their storage need separate accounting.
 * GNU/Linux stream workers check reported glibc System backing against the
 * reserved 512 MiB baseline before assignment decoding and before Rayon starts.
 * Missing/invalid observations or excess backing reject startup. This boundary
 * check does not bound direct mappings, later allocator growth or process RSS.
 * Before Rayon starts, stream admission also fixes a process-wide ceiling on
 * live/in-flight Rust System requests, outside stack and retained-heap reserves.
 * Refused requests follow the caller's allocation-failure behavior; infallible
 * Rust allocations may abort the worker. This ceiling lasts until process exit
 * and excludes allocator metadata/retention, foreign allocations and mappings.
 * A second shared ceiling charges simultaneous System requests and full spill
 * backing, including in-flight reservations, with mapped GPU staging reserved
 * separately. Nonresident spill capacity is still charged. This ceiling also
 * persists through exit and is not complete allocator or RSS admission.
 * Stream startup also checks cold private writable data against the retained
 * 512 MiB baseline, then lowers both RLIMIT_DATA limits
 * to worker RAM minus caller/Rayon stacks, the full assigned spill allowance
 * and mapped GPU staging. Disk-backed spill capacity is still reserved; no
 * assumption of nonresident pages is made. These hard limits persist
 * until process exit; they are not restored. Keep other startup owners quiescent
 * during admission. Cached spill cap, directory and backing must match admission;
 * current environment variables cannot replace an older cached configuration.
 * Active spill scopes reject before thread creation without changing their config
 * or admitting a worker. Kernel data limits exclude shared mappings and grow-down
 * stacks and do not establish complete RSS or workload lifetime admission.
 * The kernel's ignore_rlimit_data parameter must be visible, disabled and kept
 * fixed throughout the worker lifetime; unknown enforcement rejects startup.
 */
int32_t lattica_gpu_public_worker_serve(int32_t socket_fd,
                                      const uint8_t *bootstrap, size_t bootstrap_len,
                                      uint64_t *completed_out);
int32_t lattica_gpu_drain(void);
int32_t lattica_gpu_shutdown(void);

/* --- single-transaction join-split ------------------------------------------------------------ */
int32_t lattica_joinsplit_verify(const uint8_t *proof_ptr, size_t proof_len,
                                 const uint8_t *pi_ptr, size_t pi_len);
int32_t lattica_joinsplit_prove(const uint8_t *witness_ptr, size_t witness_len,
                                uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                                uint8_t *pi_out, size_t pi_cap, size_t *pi_len);
/* demo prover (fixed internal witness) — dev/integration only */
int32_t lattica_joinsplit_prove_demo(uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                                     uint8_t *pi_out, size_t pi_cap, size_t *pi_len);

/* --- single-transaction HTLC spend (redeem/refund) --------------------------------------------- */
int32_t lattica_htlc_verify(const uint8_t *proof_ptr, size_t proof_len,
                            const uint8_t *pi_ptr, size_t pi_len);
int32_t lattica_htlc_prove(const uint8_t *witness_ptr, size_t witness_len,
                           uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                           uint8_t *pi_out, size_t pi_cap, size_t *pi_len);
int32_t lattica_htlc_prove_demo(uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                                uint8_t *pi_out, size_t pi_cap, size_t *pi_len);

/* --- batch: one proof per block (tx-root = 32-byte digest, the only public input) -------------- */
int32_t lattica_batch_verify(const uint8_t *proof_ptr, size_t proof_len,
                             const uint8_t *root_ptr, size_t root_len);
int32_t lattica_batch_prove(const uint8_t *witness_ptr, size_t witness_len, size_t n_tx,
                            uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                            uint8_t *root_out, size_t root_cap, size_t *root_len);
int32_t lattica_joinsplit_tree_verify(const uint8_t *proof_ptr, size_t proof_len,
                                      const uint8_t *root_ptr, size_t root_len, size_t n_tx);
int32_t lattica_joinsplit_tree_prove(const uint8_t *witness_ptr, size_t witness_len, size_t n_tx,
                                     uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                                     uint8_t *root_out, size_t root_cap, size_t *root_len);
int32_t lattica_htlc_batch_verify(const uint8_t *proof_ptr, size_t proof_len,
                                  const uint8_t *root_ptr, size_t root_len);
int32_t lattica_htlc_batch_prove(const uint8_t *witness_ptr, size_t witness_len, size_t n_tx,
                                 uint8_t *proof_out, size_t proof_cap, size_t *proof_len,
                                 uint8_t *root_out, size_t root_cap, size_t *root_len);

/* Opt-in --features block-v2-host only. Research candidate; no activation or
 * legacy fallback. Inputs are bounded/canonical. Expected bytes are:
 * "LBV2EX01" || profile[32] || chain[32] || ordered_root[32] || count(u64 LE).
 * The host must independently select the registry/profile/context and derive
 * ordered_root from complete transaction envelopes. Registry bytes use the
 * canonical LBV2RG01 twelve-key envelope. 0 means CPU root verification passed;
 * nonzero rejects. State, heights, issuance policy and durable application are
 * checked separately by the host. No wallet/inner proof archive is required. */
/* Selected research block capacity; 64 unless built with block-v2-capacity-128. */
uint32_t lattica_v2_research_capacity_v1(void);

int32_t lattica_v2_research_root_verify_v1(
    const uint8_t *proof_ptr, size_t proof_len,
    const uint8_t *expected_ptr, size_t expected_len,
    const uint8_t *registry_ptr, size_t registry_len);

/* Opt-in research native-witness leaf prover. No state/issuance authority is
 * inferred from this call. Request: LBV2LW01 || chain[32] || kind(u64 LE)
 * || height(u64 LE) || authorized_mint(u64 LE), exactly 64 bytes. Kinds are
 * 1 join-split (height/mint zero), 2 HTLC (mint zero), 3 issuance (height zero,
 * positive authorized mint). Raw witness uses the existing native witness ABI.
 * Export: LBV2WP01 || wallet_len(u32 LE) || public_count(u32 LE)
 * || LBV2TW01 wallet envelope || canonical public u64 LE limbs.
 * Maximum export size: 2 MiB + 264 bytes. No witness bytes are exported.
 * Valid output_len is zero on failure; returns 0 only on success.
 * Buffers and distinct output_len must remain valid throughout the call.
 */
int32_t lattica_v2_research_wallet_prove_v1(
    const uint8_t *request, size_t request_len,
    const uint8_t *witness, size_t witness_len,
    uint8_t *output, size_t output_cap, size_t *output_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LATTICA_PROVER_P3_H */
