// Feature-only diagnostics, appended after the unchanged production bundle.
// The per-call cap is intentional: call boundaries must never be split to
// avoid private-memory admission. All requests use the production RNG helper.
__kernel void pq_private_rng_calls_probe(
    __global pq_private_rng_state *states,
    __global const ulong *lengths, uint call_count,
    __global ulong *output_words, ulong output_bytes,
    __global ulong *progress, ulong progress_words,
    ulong initial_counter, __global uint *status, uint phase_id) {
    if (get_global_id(0) != 0) return;
    pq_private_rng_state rng;
    if (!pq_private_begin(status, 0, states, &rng)) return;
    uchar bytes[4096];
    ulong total = 0;
    int valid = call_count >= 1 && call_count <= 256
        && output_bytes <= 1048576UL
        && progress_words == 2UL * call_count
        && initial_counter <= PQ_PRIVATE_COUNTER_END
        && rng.next_counter == 0 && rng.random_calls == 0 && rng.proposals == 0;
    for (uint i = 0; i < call_count && valid; ++i) {
        valid = lengths[i] <= 4096UL && lengths[i] <= 1048576UL - total;
        if (valid) total += lengths[i];
    }
    valid = valid && total == output_bytes;
    if (!valid) {
        pq_private_poison(&rng, PQ_PRIVATE_BAD_INPUT);
    } else {
        // Diagnostic-only terminal-counter probes start a fresh state here;
        // production callers never receive an API to reposition their stream.
        rng.next_counter = initial_counter;
        ulong cursor = 0;
        __global uchar *output = (__global uchar *)output_words;
        for (uint i = 0; i < call_count; ++i) {
            // Includes zero lengths: one original call, no AES block consumed.
            // A single request remains a single helper call even at 4096.
            if (!pq_private_random_bytes(&rng, bytes, lengths[i])) break;
            for (ulong j = 0; j < lengths[i]; ++j) output[cursor + j] = bytes[j];
            cursor += lengths[i];
            progress[2UL * i] = rng.next_counter;
            progress[2UL * i + 1UL] = rng.random_calls;
            pq_private_wipe_local(bytes, sizeof bytes);
        }
    }
    // Also retire partial/failed requests and untouched private scratch.
    pq_private_wipe_local(bytes, sizeof bytes);
    status[2] = phase_id;
    pq_private_finish(states, status, 0, &rng);
}
