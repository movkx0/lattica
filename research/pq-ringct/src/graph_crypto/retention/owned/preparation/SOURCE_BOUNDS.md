# Original SHAKE preparation owner

This preparation owner is enabled only by the coordinator's explicit
`owned-native-shake` feature on release Linux/x86_64. It neither selects the
production path nor authorizes a proof operation.

The only source constructor borrows a `ReservedShakeRequest` and segment index.
It checks the original payload length/capacity, descriptor, partition counts,
complete contiguous segment coverage, per-segment geometry and actual enum.
The exact singleton or homogeneous-batch census comes from A016-r2. An equal
but different request cannot replace that original owner. The request keeps
its raw input and partition reservation alive, without a copy or second claim.

The original shared-ledger token must match two exact categories:

- `SymbolicCompiler` owns A016's symbolic-plus-periodic partition through
  normalization and PCS: 192 MiB plus the source-derived periodic staging.
- `PhaseScratch` owns every other A016 host item, including AIR-owned arrays,
  readback/conversion, matrix/staging owners, owned-seed configuration and the
  original planner census, plus the actual plan, pending owner and bounded
  recorder bridge inline types.

This sum includes configuration and planner exactly once. Both categories have
zero device bytes. A016's five-matrix generation facts remain available to the
separate complete device/PCS planner; they are not an implicit device claim.
Runtime, raw request input, additional OCL/compiler/report/verification storage
and retained proof output remain separately owned.

`claim_for` consumes an exact original token and verifies the request owner,
index, pointer identity, original ledger, unchanged 32 GiB/8 GiB upper limits
and complete category requirements. The non-cloneable pending owner exposes
only borrows of its original token, AIR and input. It provides no extraction,
detached attachment, callback, numeric budget constructor or dispatch method.

Four authored planning CPU tests cover real singleton/batch/padding/squeeze schedules,
payload borrowing, category boundaries, identity substitution, movement,
original request preservation after refusal, and final cleanup. Agent A has
formatted but has not executed these tests.

The closed `PendingNativePreparation::record` method takes an exclusive borrow
of this owner and the original ledger. It rechecks the original token, exact
42-by-128 periodic geometry and source degree hint 7. It matches the actual
`ShakeSegmentAir` enum, evaluates only that concrete singleton/batch AIR into
the core bounded builder, and fills only that source's existing borrowed
periodic columns. No generic AIR or callback is passed into the core crate.
Any dynamic fill error is mapped and dropped while the same claim remains live.
The method does not allocate a second input payload or a native owned periodic
table.

The returned opaque `PreparedShake` retains an exclusive borrow of the original
preparation `Reservation`. That borrow prevents another recording from using
this token until the first recording and its core continuation are destroyed.
Its internal conversion returns both the existing `uni::Prepared` and that same
exclusive token borrow. The fixed consumer must keep the borrow through all PCS
and compiler cleanup; output/native proof and report reservations remain a
separate ownership obligation. No recording object authorizes GPU dispatch.

Three additional authored research tests cover actual singleton, homogeneous
absorb/squeeze batch and padding/tail metadata against the upstream symbolic
constraint count/degree and owned periodic reference, foreign-ledger refusal,
independent input owners, moves and cleanup. The core bridge separately compares
a test-only source's full canonical normalized DAG against the upstream builder
and checks exact table handoff, incomplete/repeated/nonbinary columns, nested
failure, unwind recovery, one-byte-short admission and original token lifetime.
These are source-level qualification tests, not proof or performance results.
The independent CPU verifier and fixed-kernel producer remain separate work.
