#ifndef LATTICA_BLOCK_V2_HOST_BRIDGE_H
#define LATTICA_BLOCK_V2_HOST_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Opt-in research bridge, linked with the block-v2-host Rust static library.
 * Initialize once before concurrent calls. There is no legacy verifier fallback.
 * Registry, context (profile[32] || chain[32]), genesis and issuance grants are
 * independently selected by the host. Journal contents must not select them.
 * Buffers remain readable/immutable for the call; output must be writable.
 * Replay returns 0 only on full acceptance and writes one 208-byte LBV2ST01
 * state summary for genesis followed by one per accepted block. Supply output
 * capacity for (block_count + 1) summaries. Discard all output on nonzero return.
 * Genesis/public-body/replay encodings are local research formats, not activated
 * consensus wire formats. This API does not perform durable writes.
 */
void lattica_v2_research_host_initialize_v1(void);
int32_t lattica_v2_research_host_replay_v1(
    const uint8_t *registry, size_t registry_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *genesis, size_t genesis_len,
    const uint8_t *records, size_t records_len,
    uint8_t *output, size_t output_len);

/* Fixed public research fixtures from four deterministic synthetic wallets.
 * No real funds or private witness/key exports. These functions allocate native
 * scratch state; the wallet call proves and CPU-verifies one fresh research leaf.
 * Genesis is LBV2GN01; wallet output is LBV2FX01 || body_len(u32 LE) ||
 * leaf_export_len(u32 LE) || complete single body || LBV2WP01 leaf export.
 * Each leaf export is LBV2WP01 || wallet_len(u32 LE) || public_count(u32 LE)
 * || LBV2TW01 wallet proof || public_count canonical u64 LE limbs.
 * Use distinct writable output and output_len buffers; zero output_len on error.
 * The generated ciphertexts are checked by recipient decryption before export.
 */
int32_t lattica_v2_research_fixture_genesis_v1(uint8_t *output, size_t cap, size_t *output_len);
int32_t lattica_v2_research_fixture_wallet_v1(uint32_t index, uint8_t *output, size_t cap, size_t *output_len);
/* Multi-height synthetic delivery fixtures. Slots: 1..2048 (two funded notes
 * each). Four deterministic wallets; redeem deadlines cover the 128-block
 * research history. These are separately pinned genesis inputs, not compatible
 * funding for the original fixture_wallet_v1's HTLC notes.
 * delivery_wallet verifies every record before proving a fresh leaf at the
 * next height/current anchor. Missing or spent slots are rejected. The packet
 * format is LBV2FX01 as above. Caller must fence publication against the exact
 * journal head used to supply records. No durable state is changed here. */
int32_t lattica_v2_research_delivery_genesis_v1(
    uint32_t slots, uint8_t *output, size_t cap, size_t *output_len);
int32_t lattica_v2_research_delivery_wallet_v1(
    const uint8_t *registry, size_t registry_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *genesis, size_t genesis_len,
    const uint8_t *records, size_t records_len,
    uint32_t index, uint8_t *output, size_t cap, size_t *output_len);

/* Preflight replays verified history and checks the next complete candidate's
 * anchors, nullifiers, height, public values and independent issuance grants.
 * It does not authenticate the candidate or apply any state. Wallet proofs must
 * be verified separately, and eventual application must still pass root audit
 * and the durable head fence. Grants are one u64 LE per transaction.
 * Output: LBV2PF01 || LBV2EX01[112] || one statement record per transaction.
 * Statement record: kind(u8: join-split=0, redeem=1, refund=2, issuance=3) ||
 * public_count(u8: 26 or 31) || canonical public limbs (u64 LE).
 * Allocate 16120 bytes. Discard output on nonzero status; output_len is then 0.
 */
int32_t lattica_v2_research_candidate_preflight_v1(
    const uint8_t *registry, size_t registry_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *genesis, size_t genesis_len,
    const uint8_t *records, size_t records_len,
    const uint8_t *body, size_t body_len, uint64_t at_height,
    const uint8_t *grants, size_t grants_len,
    uint8_t *output, size_t cap, size_t *output_len);

/* Derive the 112-byte LBV2EX01 expectation from complete bodies and the host's
 * 64-byte profile/chain context. This performs no proof or state verification. */
int32_t lattica_v2_research_body_expected_v1(
    const uint8_t *context, size_t context_len,
    const uint8_t *body, size_t body_len,
    uint8_t *output, size_t output_len);
#ifdef __cplusplus
}
#endif
#endif
