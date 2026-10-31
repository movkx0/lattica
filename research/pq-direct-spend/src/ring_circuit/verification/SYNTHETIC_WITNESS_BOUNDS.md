# In-place synthetic witness admission

C025's explicit receipt and forwarding census exposed a real overflow of the
existing 1 MiB verifier caller limit: the previously qualified caller requested
1,040,376 bytes, leaving only 8,200 bytes. The focused CPU test rejected the
ordinary fixture before any spare ring capacity was added. Increasing a limit
or making that baseline test expect rejection would not resolve the problem.

The verifier previously constructed an all-zero stack `Witness` and returned it
by value. Its census conservatively included three full payload slots for the
literal, return and receiving local, without relying on compiler move elision.
The new private constructor first runs the complete caller admission, then uses
fallible `alloc_zeroed(Layout::new::<Witness>())` to initialize one heap payload
in place. A null result returns `ResourceLimit`. A successful result immediately
becomes the sole `Box<Witness>` owner, with no fallible operation or allocation
between successful allocation and ownership conversion.

The unsafe conversion requires the exact global allocator/layout match and the
current `Witness` representation: only `usize`, `u64` and fixed signed-integer
arrays. Every field permits zero, exactly matching the previous synthetic
values. An exhaustive typed constant in production source checks every field
against `usize`, `u64` or `i64` arrays; adding a field or changing its type requires
re-auditing the guard. That constant is never called and allocates nothing.
No full `Witness` is materialized or moved on the stack. The existing
zeroizing `Drop` runs before the Box deallocates its backing on normal return,
compiler failure or unwind. The existing compiler catch/unwind path destroys
the witness before returning a reconstructed relation or failure. No witness
data from a prover is retained or consulted by independent verification.

The source census charges one complete payload, twelve Box owner/move headers,
eight complete `Result<Box<Witness>, Error>` slots, four scalar admission-result
slots, eight allocation-layout values, eight raw pointer slots and eight
statement references. It separately charges four sealed allocation-source
objects, four optional counter references, four standalone counter references,
four local `Cell<usize>` control values and four scalar counter temporaries.
These include both entry wrappers,
the allocation-source forwarding frames and the test observer even when the
production path uses no observer. These are additive to the receipt census,
reports, session, caller orchestration and original fixed hash/error/header
charges. The compiler still
subtracts the complete unchanged 1 MiB caller allowance and retained artifact
allowance before admitting its own construction envelope. GPU, context, host,
process, swap, thread, row and cryptographic parameters are unchanged.

The existing CPU test now exhaustively names every Witness field and checks
their exact zero values, retains the domain-validity check, checks ordinary
caller admission and rejects excessive actual Vec capacity through both caller
admission and the constructor. The ignored complete-program differential test
continues comparing zero and patterned synthetic hints to the authentic witness
program. Coordinator compilation/correctness and full artifact/CPU verification
remain required; C has performed only source/rustfmt checks for this revision.

A private per-call allocation source supplies either the exact global zeroed
allocation or a forced null result observed by a local counter. Production
constructs only the ordinary path. A test-only wrapper can select null; it
cannot provide an arbitrary pointer, replace the global allocator, or affect
another call. Both wrappers call the same constructor, which admits complete
caller storage before invoking that allocation source. The regression checks
one allocation attempt and `ResourceLimit` for an admitted statement, and zero
attempts for a statement whose actual ring capacity exceeds caller admission.
The null result traverses the constructor's real null-pointer rejection branch;
the test requires no actual allocator exhaustion or GPU session. The successful
global allocation still becomes a Box without any intervening fallible action.
