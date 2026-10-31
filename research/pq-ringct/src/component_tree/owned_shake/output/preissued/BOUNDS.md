# Classified output mutation probes

B057 changes the existing public/context negative probes to C035's typed
registered-verifier outcome. Only `RelationRejected`, issued by the actual
numerical `verify_batch` failure, earns rejection credit. Admission, structural,
configuration and fallible public-copy failures terminate qualification. A
successful verification also fails the probe; diagnostic text is never evidence.

The initial and final unmutated successful verification calls remain unchanged.
Each probe uses a precharged fixed46-word public copy and leaves the retained
output untouched, including on unwinding. The local probe is restored before
classification. No proof or verifier is cloned and no new accepted-output
constructor is introduced. The same two public fields are checked sequentially.

`OutputRecheck::reserve_before_native` retains the complete original verifier
lifecycle plus its original two owner frames, then adds C035's classified call
charge and eight copies of all new enum/result/owner/helper/public-copy/reference
frames. Helper arrays are additive and no move/inlining credit is taken. The
original resource envelope and source identity checks are unchanged. No caller
may reuse an older smaller pre-native claim after this source rotation.

The authored classifier test checks that misleading diagnostic text cannot
override typed infrastructure errors. It constructs no genuine proof, retired
attempt or accepted output. C035 separately tests actual numerical rejection
and injected infrastructure failures. Coordinator release builds and tests,
genuine output mutation runs and original guarded cleanup remain required;
source/rustfmt inspection alone is not mutation qualification or a speedup.
