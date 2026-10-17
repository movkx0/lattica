Typed aggregation benchmarks
============================

Start with ../../docs/gpu-benchmarking.md for a clean-checkout Linux recipe,
CPU/GPU build separation, public fixture preparation, and measurement rules.

The default candidate capacity is 64. The explicit block-v2-capacity-128
feature selects capacity 128; both binaries, keys, fixtures, and qualification
must match. Capacities 256 and 512 remain research proposals.

Controller entry points:
- block-v2-typed-cpu-prepare.py: public wallets and CPU registrations.
- block-v2-typed-gpu-run.py: one bounded GPU aggregation and CPU root audit.
- block-v2-typed-multi-gpu-run.py: independently admitted devices and jobs.
- block-v2-typed-shared-gpu-run.py: persistent workers and owned GPU options.
- block-v2-pool-README.txt: persistent-pool operations and qualification.

Use --help for current flags. The Linux controller requires systemd, cgroups,
OpenCL inventory, and nvidia-smi. Use apple-current-benchmark-README.txt on Mac.

Older detailed commands and measured snapshots are retained in
../../docs/archive/typed-benchmark-2026-10-17.txt. They may depend on local
artifacts or old sources; use the current guide for a new GPU comparison.
