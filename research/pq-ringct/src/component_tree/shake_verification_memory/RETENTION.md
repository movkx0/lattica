# Original native verification component retention

This is a crate-only preparation seam for a separately admitted request
workspace. It neither enables PairedV1 nor authorizes another native proof.
The existing public `AdmittedVerification::verify` still releases its component
on success, configuration error, invalid proof, or unwinding.

`verify_retaining_original` consumes the same admitted input and returns
`Result<(VerificationReceipt, Reservation), (VerificationFailure, Reservation)>`.
It calls the same private borrowed verifier as the default path. The helper's
configuration and all native-verifier and diagnostic-formatting temporaries
are destroyed before the original reservation is moved into either result.
The returned receipt and failure contain only inline data. There is no token
clone, split, release, readmission, reconstructed configuration, or retry.
Unwinding drops the still-owned original reservation normally.

The request workspace must hide this raw component behind its own typed state.
Only successful retirement can return it to an already admitted next phase;
an error's reservation is terminal-cleanup ownership and must not grant retry
authority. This module alone does not construct that workspace or prove the
complete request, transaction graph, or final aggregation.

The original independent-verifier component remains exactly 64 MiB. The
requested-heap census remains `Bounds::cumulative_requested_bytes`, including
configuration, periodic columns, native verification, and all Rayon allocation
requests already counted by the original source census. `entry_frame_bytes`
separately counts full entry/helper/configuration/result/error/diagnostic and
formatting owners. Checked addition of these two bounds must fit inside the
unchanged 64 MiB component. Four slots per counted type cover local, returned,
residual-conversion, and forwarded storage without assuming move elision.
The enclosing guard continues to cover downstream execution stacks, thread
pools, allocator overhead, and process memory; this is not an RSS bound.

`Plan::retaining_original_caller_host_bytes` is a pure checked size helper.
Before constructing native source or PCS state, the enclosing request must
reserve its result inside the existing worker allowance. It counts two full
admitted-self slots, four full owning `Result` slots, both complete branch
tuples twice, twice each receipt/failure/reservation field, and eight words of
scalar/reference bookkeeping. This includes all inline diagnostic capacity.
It remains charged through destruction of the returned value. The caller
must additionally count its own request/workspace owners and any forwarding
beyond this immediate call. No numeric bound issues a reservation or changes
the 32 GiB worker, 8 GiB managed-device, or other enclosing limits.

The focused non-proving test cases cover an exact-full ledger on both invalid
proof and injected configuration refusal, unchanged complete snapshots and
same-ledger/category ownership on return, terminal failure retirement, and
one-byte-short caller-frame refusal before source construction. The existing
ignored fresh native CPU-proof test is extended to compare all three entry
paths, retain the original component on success, release it explicitly, and
finish the existing statement/proof mutation checks with zero final quota.
The allocation-audit feature still compares actual requested heap to the heap
census separately from inline frames. Only the coordinator may run these tests
in the serialized resource slot. Source parsing alone is not test evidence.
