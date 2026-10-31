# Exact active opt-validator source policy

`new_active_opt_validate_v1` is an opt-in request-storage constructor for the
existing full opt-validator policy: `Estimated`, maximum AES 64/SHAKE 32 and a
24 GiB native estimate allowance. It accepts no different policy. The existing
`new`, `source_geometry` and graph-collection entry points retain their original
8 GiB estimate gate and behavior.

Both source constructors use the same checked partition/storage arithmetic and
the same unchanged `construct` implementation. The new entry fixes its borrowed
input/profile/operation/subrequest/output before any copy. It precomputes the
whole cumulative request-storage charge, including every rejected partition
attempt. Construction requires that exact original same-ledger token, performs
the existing `Request::new` call, and rechecks all source geometry afterward.
No extra retained payload, allocation site or proof authority is introduced.

The estimate is not managed GPU memory. Actual worker host 32 GiB, managed 8 GiB,
context 4 GiB, native 24 GiB, process 47 GiB, row/thread and zero-swap limits remain
unchanged. No native/PCS/runtime/outer admission or graph/context authentication
is supplied by this request owner. Complete source and execution boundaries
must independently pass before any proof dispatch.

The source estimate for an n-permutation batch is
`n * 4096 * 518 * 8 * 48 + 512 MiB`. Batch 32 estimates 26,608,664,576 bytes,
above 24 GiB; batch 16 estimates 13,572,767,744 and fits. The original constructor
therefore selects 16 for the two long requests before dispatch. The unchanged
source lengths yield:

| Request | Input/output bytes | Native segment shapes | Native count | Paired groups |
| --- | --- | --- | ---: | ---: |
| ParametersPp | 109/32 | singleton | 1 | 1 |
| HashAlpha | 230496/32 | 105x16,8,4,2,padding singleton | 109 | 55 |
| HashX | 16416/137 | 7x16,8,padding singleton,squeeze-tail singleton | 10 | 5 |

This is 120 native segments and 61 paired leaves. Compared with 120 singleton
leaves, the binary request trees schedule 59 fewer leaves and 59 fewer parents.
It explains the 118-proof scheduling difference; it proves no speedup or height
closure. The earlier default-max8 reference collection's 1/214/17 counts remain
accurate for that separate policy and are not active opt-validator counts.

Two CPU tests are authored for exact policy refusal/default behavior, original
constructor differential comparison, every source cache key/shape/coverage,
HashX padding/squeeze indices, exact source preallocation, one-byte-short
admission and zero terminal source storage. No tests, builds or GPU work have
been executed in this capsule. The surrounding source fixture and reference
request remain external to this request-storage ledger.
