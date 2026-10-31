# Typed NodeKey forwarding

`verify_classified` forwards the original proof and public-value borrows to
`RegisteredVerifier::verify_classified`. It neither clones proof state nor
changes `NodeKey::verify` or `verify_request`. Only the core numerical verifier
may identify a relation rejection; this wrapper preserves every error variant.

`classified_call_extra_bytes` is additive to the existing legacy verification
bound. It includes the core additive requirement and four complete copies of
all wrapper argument, receiver, return-result and scalar layouts, covering
forwarding and move overlap. No data-dependent heap allocation is introduced.
The caller must additionally precharge its own probe owners, mutation backing,
results and caller/helper frames before dispatch. It must restore mutable
probes on both returned failure and unwinding, and credit only
`RelationRejected`.

This capsule is source/rustfmt qualified only. Integration, builds, tests and
genuine mutation checks belong to the coordinator. No performance or complete
RingCT workflow claim follows from this forwarding helper.
