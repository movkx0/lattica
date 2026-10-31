# Native opening planner allocation qualification

The first B038 focused test incorrectly asserted that the complete
`opening::native_plan` was allocation-free. The coordinator preserved its
failed run: 272 allocation requests totaling 17,952 bytes. The new B038
`Additional::new` helper is allocation-free; the enclosing original opening
planner has always called allocating evaluation/reduction planners. The
correction does not change that planner, its admission or any budget.

For each of 34 native matrices, `plan_shape` calls both `EvaluationPlan::new`
and `ReductionPlan::new` twice: once at actual live bytes and once at zero live
bytes for the adaptive upper bound. Every evaluation attempt copies four
usize values into an exact Vec and grows to eight slots when extending it.
Every reduction attempt copies seven and grows to fourteen when pushing.
The successful first-fit fixture therefore requests
`34 * 2 * ((4 + 8) + (7 + 14)) * 8 = 17,952` bytes in
`34 * 2 * (2 + 2) = 272` requests. This explains the observation; the corrected
test does not use the observed total as an admission or expected hard-coded
count.

The source-derived bound includes all possible halving iterations. Evaluation
starts at `min(2 * rows, 65536)`, reduction at
`min(32 * rows, 2^20)`; both divide rows by two after a failed candidate. Each
attempt has at most two Vec allocation/reallocation requests and one fixed
diagnostic of at most 64 bytes. A final 4096-byte diagnostic slot is included.
At 4096 rows this bounds 6529 requests and 440384 cumulative requested bytes.
This is stricter than a live-storage bound: each attempt's Vec and temporary
error are destroyed before the next attempt, and each planner returns only
scalar fields before the next call.

The source partition was already admitted before this planning operation.
A016's `LegacyPlannerCensus` includes the maintained `PlannerResources`, whose
temporary partition explicitly includes `(4+8+7+14) * sizeof(usize)` plus the
4096-byte failure scratch. Its conservative original vector/report request
partition is also retained. The corrected test proves that the stronger full
native-opening cumulative request ceiling fits that same original planner
partition. B039 checks the original preparation token before physical/PCS
planning; the earlier source device Plan has already been destroyed before
`opening::native_plan`, so these temporary planners do not overlap.

All remaining success-path helpers in this opening composition are scalar or
fixed-array geometry: matrix/FRI/query/randomness plans, tree layout and host
output census. Their failure strings terminate the phase within the charged
diagnostic slot. Source canaries pin the two halving loops, their Vec growth
operations, bounded diagnostic literals and original planner scratch fields.

The corrected tests separately require exactly zero successful requests from
`Additional::new`, require the complete native planner's measured requests to
fit the source-derived ceiling, and preserve the original exact/one-byte-short
managed-cap checks, host-versus-device comparison and mode refusal tests.
The capsule contains no production behavior change. Execution remains the
coordinator's responsibility, and the original failed evidence is retained.
