# Fixed phase reports and remaining source transients

This owner accounts for copied receipts and failure evidence belonging to one
closed native-child, wrapper-compilation or registered-wrapper phase. It is not
a dispatch permit. Neither a reservation token nor successful capture admits
the original backend report/error, graph, child proofs, compiler or verifier.
Paired execution remains unavailable while any Required term is unknown.

## Concrete backing before allocation

`PhaseReportOwner::requirements()` has no caller-supplied count or byte limit.
`from_reservation` first checks the ledger identity, exact category/amount and
fixed phase identity. Failure returns the original reservation unchanged.
Only then are the boxed payload and fixed encoding Vec constructed. The Vec is
created by one `vec![0; ENCODED_BYTES]` request and never grows. Allocator-rounded
storage is part of the enclosing allocator/process allowance, not claimed by
this requested-backing bound. No capacity census authorizes an earlier request.

Each snapshot has concrete arrays for 19 stage capabilities, 114 observations
(19 stages times six backends) and 16 child receipts. A capability must have a
unique stage; an observation must have a unique `(stage, backend)` pair; a child
must have a unique ID. Labels have at most 64 UTF-8 bytes and are copied exactly;
oversized labels refuse. The current closed Run inventories use fewer stage
slots, but all enum variants fit and are covered by exhaustive encoding matches.

The owner has two snapshot slots. Native production permits one, registered
production permits two, and compilation permits zero. This bounds retention;
it does not assert that the supplied receipt belongs to that computation. The
closed caller must still validate the report's policy, inventory, identity and
completion before releasing its proof.

There is one failure slot. It copies at most 2048 UTF-8 bytes, preserving a code,
original byte count and explicit truncation flag. It accepts a borrowed string,
never formats/clones the original error and never replaces the first failure.
The original error allocation remains a separate preceding admission duty.

The source request is:

```
Report.host = 2*sizeof(Payload) + 2*sizeof(Snapshot)
            + ENCODED_BYTES + sizeof(PhaseReportOwner) + 39 + 6
Report.device = 0
```

`Payload` covers the boxed owner; the second payload covers construction and
fixed failure-copy overlap. The two snapshot terms conservatively cover the
capture result and assignment temporary while the payload remains owned. The
fixed owner includes its Box/Vec/token headers. Decimal encoding uses one
39-byte array (maximum u128); control escaping uses a six-byte array. These are
source-requested backing/copy terms, not a proof of compiler stack-frame size.
The existing enclosing stack allowance, allocator metadata and process guard
remain necessary and unchanged.

All fields drop in declaration order: boxed payload, encoding Vec, reservation.
There is no Clone, payload extraction or unreserved constructor. A move or
successful phase/context cleanup does not release the report charge. Normal
destruction of the final owner releases it; checked consuming reclamation may
instead destroy both actual storage owners and return the unchanged original
reservation, as detailed in [reclamation/BOUNDS.md](reclamation/BOUNDS.md). The
phase lifecycle test uses an actual context lease, then retires/drops the
context while encoding the still-charged report owner.

## Encoding bound

Encoding visits only concrete fields and uses no serde serializer, formatter,
JSON tree, owned String, output callback or reallocation. It preserves every
field of each captured `proving::Report`, including coverage flags, cached
components, profile and FRI metadata. UTF-8 bytes pass through unchanged except
JSON quotes, backslashes and control bytes. Integer formatting is exact for all
u64/u128 values. Partial output is inaccessible after an encoding refusal.

The fixed buffer is the following sum (all constants are source constants):

```
2 * (114*512 + 19*128 + 16*512 + 2048) + 2048*6 + 2048 bytes
```

512 bytes exceed an observation's fixed keys, two enum labels, three 20-digit
u64s and two 39-digit u128s. 128 bytes exceed a capability's two enum fields.
512 bytes exceed a component's six keys, its maximally escaped 64-byte label,
20-byte scope name and four five-byte booleans. The per-report 2048 bytes cover
its remaining fixed keys, two maximally escaped labels, enum names and scalars.
Failure text expands by at most six; the final 2048 bytes cover its fixed fields
and the phase identity. Tests exercise every slot, maximal integers and control
escaping, and compare ordinary captured reports against serde's complete JSON.

The JSON's `dispatch_authorized:false` and
`source_transients_admitted:false` describe this diagnostic owner's authority.
They must not be interpreted as successful workflow admission.

## Opt-in registered receipt capture

`RegisteredProgram::new_with_request_and_identity_hint_and_report` returns the
successful preprocessing Report alongside the unchanged program.
`prove_with_request_and_report` returns the successful proving Report alongside
the proof. Both share the original source implementation; existing APIs discard
the returned Report exactly as their callers did before. Default request policy
and JSON emission are unchanged. Native `research::prove` already returns its
Report. This slice does not switch any context to silent reporting.

These adapters preserve **successful** receipts when a future caller requests
`emit_report:false`. They do not preserve an escaping Report on failure:
`Run::finish` returns `Error::IncompleteCoverage`, while an early return reaches
`Run::drop`. Silent reporting therefore remains ineligible for the complete
paired path until failure evidence and its temporary storage are bounded.

## Exact remaining transient boundaries

The relevant sources are `lattica-prover-p3/src/proving.rs` and
`proving/composition.rs`, plus the backend paths named below.

* `Capabilities::admit` collects `Unsupported.gaps`. `Run::new` allocates an
  `Arc<Mutex<State>>`; stage observation inserts grow a Vec, although deduplication
  bounds the logical domain at 114. Current capability constructors have at most
  16 entries (17 with debug constraint audit). These source counts do not include
  allocator metadata, temporary old/new Vec overlap or retained clones.
* `Run::finish` owns the Run's capabilities while cloning them into the Report;
  it also constructs `missing`, `unaccounted` and `missing_components` vectors.
  The observation/component Vecs move into the Report. A composed child may
  simultaneously retain Parent capabilities and the parent's shared State.
  `CachedScope` clones another capability inventory. The standalone registered
  and native research calls use leaf Runs, but other callers may compose them.
* `Run::publish` calls `serde_json::to_string` if emission is enabled. Static
  entry-point/component labels accepted by the general reporting API have no
  byte ceiling. The fixed snapshot's 64-byte limit cannot retroactively bound
  this prior serialization. Optional backend diagnostic `json!`/`eprintln!`
  paths and tracing subscribers are also outside the snapshot.
* `Run::finish` formats missing components/inventories through its Error display
  when a caller uses `to_string`. Native `block_v2/native_gpu/research.rs::prove`
  uses that conversion and accepts a trace-generation callback returning String.
  Registered admission retains `AdmissionError::ProvingPolicy` or GPU error
  Strings; later execution/context diagnostics can format them again. Fixed
  failure-prefix capture does not bound those original constructions.

No arbitrary cushion is supplied for those allocations. Their complete overlap,
closed callback/label domain, failure-report preservation and backend diagnostic
paths still require source bounds before the paired phase can dispatch. The
new report owner only closes its specifically enumerated retained/copy/encoding
term, and the additive backend APIs remove the successful-receipt capture gap.

## Focused qualification

The coordinator ran these checks serially under the existing worker guard and
audited terminal completion, process reaping and source/executable/log identities.
No GPU benchmark or workflow-speedup claim belongs to this slice.

* `execution::phase_`: all 18 report/lifecycle tests passed. Guard wall time
  74.22855 seconds; peak process bytes 1,319,682,048. The record SHA-256 is
  `6910d75f435d0aba3c374f56dc8b02d9fd1e27e4188a8932f25904bbe53e7183`;
  log SHA-256 is
  `dfa37ecec33592bb77c8df77fbcbce211ae25f8bb1f7e896c911e00ac34ac97f`.
* `block_v2::machine::backend::reported_tests`: both CPU receipt/proof tests
  passed, including independent verification and unchanged policy/input
  refusals. Guard wall time 110.2771 seconds; test execution 0.14 seconds; peak
  process bytes 2,638,807,040. The record SHA-256 is
  `1d130024057f89b43bdee062a8db98e1cc160edfb357708095194b00a0febcb1`;
  log SHA-256 is
  `6a51d9a471f26217df9c58a1484e847786af5b36503adcd12955502e1176ee47`.

Both test builds used release mode, offline dependencies and no default GPU
feature: research `recursive-wide` for the first filter, core
`block-v2-wide-lanes` for the second. Agent C's peer review and the coordinator's
backend review found no source blocker. The only post-validation source change
was rustfmt formatting of the new backend regions; these evidence notes were
then appended. The raw qualification hashes above identify the tested snapshot,
not a new performance measurement or a byte-identical post-format executable.
