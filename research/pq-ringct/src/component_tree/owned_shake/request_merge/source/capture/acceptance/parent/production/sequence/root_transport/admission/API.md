# Frozen composition contract required before integration

All paths are beneath the private, release/Linux/x86_64 owned-native-shake test
sequence root_transport module. This file describes interfaces, not permission
to dispatch. A owns admission.rs and admission/*; B owns root_transport.rs; C
owns header.rs and header/*. Coordinator owns ancestor wiring and the immutable
output adapter. No agent adds a driver or selector in this prerequisite.

A supplies sequence-visible `PreissuedRootTransport<'bound,'source,'request>`
and `RootTransportPlanReport`, plus sequence-visible `reserve_before_native`
and `plan_report`. Other methods are root_transport-private: `check(ledger)`,
`source()`, `expected_spec()`, `expected_header()`, `envelope()`, `cpu_heights()`
and `decoder_limit()`. Result errors are fixed `ParentCompileError` values.
The original reservations have no accessor or extraction API.

B supplies `RootTransportAction<'phase,'bound,'source,'request>`,
`RootTransportMeasurements`, and
`RetainedRootTransportReport<'bound,'source,'request>`. The action holds shared
references to the actual AcceptedChild, A's preissued owner and Ledger. The
retained report contains fixed measurements followed by that whole preissued
owner. No Clone/Copy is implemented for the measurements or retained report.
`Component::roundtrip_root` consumes the same actual Component; the immutable
output adapter supplies its own original owner/key/proof/request and never
exposes detached proof/key/root values or a generic callback.

C supplies `HEADER_BYTES=2480`, `PACKET_LIMIT=2<<20`, `PUBLICS=46`,
`CAP_ROOTS=64`, `RootHeaderValues<'a>`, `HeaderCheckedPacket<'a>`,
`HeaderRefusal`, `HeaderProbeReport`, and `HeaderProbeError`. The value view
contains height plus borrowed fixed public/cap arrays and conveys no authority.
`encode_header(values,inner_bytes,output)` and
`validate_packet(packet,expected)` are allocation-free. The checked view exposes
only its borrowed inner bytes. `probe_packet(original,scratch,expected)` uses
the second full packet, typed framing/binding refusals and one trailing byte
already admitted within that packet; it performs no inner decode or proof test.

B reexports the preissued type privately to sequence. A's concrete size census
references B and C layouts, so all three exact external payload/capsule hashes
must agree in the combined review. Canonical preimages/absences are checked only
when the coordinator stages the combined files. Separate ancestor wiring then
requires its own review before serialized compilation and focused tests.
