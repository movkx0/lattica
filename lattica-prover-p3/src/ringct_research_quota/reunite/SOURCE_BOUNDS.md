# Original reservation reunification

`Reservation::reunite` consumes two non-cloneable original reservations from the
same `Rc<RefCell<Snapshot>>`. It computes checked category and total sums before
mutating either token. On success the original recipient keeps its ledger handle
and owns the sum; the donor becomes empty and drops, releasing no bytes. Every
current and peak counter is unchanged. On refusal both original tokens return
intact alongside the inline error. There is no ledger admission, category
conversion, proof dispatch, cache selection, fallback or numeric receipt input.

The method creates no allocation or new ledger handle. Its fixed `Requirements`
and overlapping result/reservation/error headers must be covered by each closed
caller's original phase bookkeeping. Calling this operation alone does not prove
that data previously using either reservation has been destroyed. A native-to-
outer phase planner still needs an exact runtime retirement binding and original
payload destruction before transferring scratch to a different phase.

Four authored CPU tests cover all eight categories, full current/peak snapshots,
round-trip splitting, moves/destruction, foreign-ledger refusal with both claims
intact, shared handles, zero claims at full allowance, and checked host/device
category/total overflow. Overflow uses pure requests instead of fabricating
impossible live ledger claims. No test or build was run by Agent A.
