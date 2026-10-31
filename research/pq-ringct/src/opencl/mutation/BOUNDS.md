# Typed CLI smoke mutation qualification

This change fixes the adjacent `pq-byte` and `pq-aes-component` CLI smoke
paths. It does not change owned-session dispatch, transaction acceptance,
native or recursive security parameters, proving policy, or resource limits.
The existing first and last positive verification calls remain unchanged.

## Rejection and restoration

Only `RegisteredVerificationFailure::RelationRejected` earns mutation credit.
Admission, configuration, allocation, accepted mutations and panics cannot
produce a successful smoke result. Diagnostics are never parsed. This fixes
report integrity; it is not evidence that the original positive verifier
accepted an invalid proof.

The byte public probe copies exactly two field elements on the stack. Public
and opening guards borrow the original mutable proof, validate the exact slot,
and retain the original word. The verification callback can borrow only a
shared proof, so it cannot invalidate the restoration slot. Guards restore
before outcome classification and during unwinding. A panic remains a panic;
this change does not claim broader panic-safe GPU shutdown in the older CLI
smoke harness.

## Incremental admission

`Admission::new` subtracts the complete new charge from the existing explicit
host allowance before device selection, AES fixture generation, or GPU
initialization. The reduced limit is passed to the existing environment check,
registration and AES prepare/prove paths. In particular, the configured host
output budget must fit the reduced allowance. Checked subtraction and the
original 1 GiB minimum must both pass. The device allowance, row limit, maximum
host allowance, GPU reserve and proof-generation policy are unchanged.

This is incremental accounting within the legacy CLI smoke allowance, not a
complete phase bound or planner-issued admission token. The caller's existing
external complete-job admission obligation remains. No owned endpoint,
prepared-state cache, outer caller envelope or new execution authority is
introduced. C035's 1 MiB outer caller ceiling is unrelated and unchanged.

The added charge contains:

- The entire core classified-call increment for bytes, or B059's entire
  core-plus-NodeKey forwarding increment for AES.
- Four complete copies of the enumerated guards and constructor results,
  typed and caller results, original field words, fixed public array,
  references, closure captures, admission owners/results and helper frames.
  The census retains both mutually exclusive guard specializations. Sixteen
  scalar words per copy cover the census locals, nested checked arithmetic and
  probe indexes. No proof or registered-key clone is created.
- Two bounded 256-byte local diagnostics in addition to the core diagnostic
  already charged by its API. Each new message is static and checked by tests.
- Storage for the four new primitive report members, their strings and Value
  transports. Cargo.lock pins serde_json 1.0.154 without `indexmap`, hence its
  BTreeMap backend. The Rust 1.96.0 BTreeMap node uses 11 key/value slots and 12
  edges. The census conservatively uses 16 full String/Value slots and 32
  pointer/scalar slots per node. The fixed top-level report has 26 keys,
  below 64; four insertions reserve three nodes each, four 128-byte keys, a
  128-byte classification string, and four Value transports. Four complete
  copies cover construction/moves. The pinned toolchain node source is
  recorded in metadata. Changing the report shape, map backend or toolchain
  requires requalification of this bound.

Every runtime sum, product and host conversion is checked. Existing limits are
not increased. A host allowance of exactly 1 GiB now fails before dispatch,
because the unchanged 1 GiB floor must remain after the additional reservation.

## Reporting and coordinator guard

Keep `host_allowance_bytes` as the original explicit allowance. Require the
following additional fields in `tools/opencl_qualify.py` after integration:

- `mutation_outcome_classification == "typed-numerical-rejection-v1"`.
- `mutation_numerical_rejections == 2` with integer type, not a Boolean.
- Positive integer `mutation_probe_host_reserved_bytes` and integer
  `mutation_remaining_host_bytes >= 1 << 30`.
- Exact sum of reserved and remaining equals `host_allowance_bytes`, with the
  original allowance still matching the externally admitted request.

The classification and count are emitted only after both typed probes and the
unchanged final positive verification succeed. Preserve all existing strict
native execution, device, source, artifact and terminal audits. These fields do
not establish full-phase admission or a complete transaction result.

## Authored verification

Run `opencl::mutation::tests` under the coordinator's serialized research test
build. The tests cover misleading diagnostic text for every infrastructure
class, accepted mutations, exact original-byte restoration after returned
errors and unwinding, invalid slots before any callback, fixed-size public
copy, exact subtraction, device/row preservation, boundary refusal and checked
arithmetic. Zero proof templates are shape fixtures only, never submitted to
the numerical verifier and never claimed as valid proofs. C035's separate
genuine CPU proof tests qualify numerical classification; they do not qualify
these CLI smoke stages on a GPU. Genuine byte/AES smoke runs remain subject to
the original exclusive coordinator admission and terminal audits.

This capsule is source/rustfmt qualified only. It claims no build, test, GPU,
full-workflow, protocol-adoption or performance success.
