# Apple Silicon development

`main` is the integration branch. The pending Mac research source was preserved
in checkpoint `1604392` and integrated with the shared prover/pool at `9733a24`.
The six previously omitted Rust/Metal modules are now tracked. Current validation
and measured results are linked from `../docs/apple-main-integration-2026-10-06.html`.

Before source commits, run `python3 scripts/check-apple-source-commit.py --repo ..`
from this crate. Review the staged diff; source completeness does not replace
compilation or correctness checks. Resolve ignored source explicitly and do not
force-add benchmark binaries or output directories.

Prefer focused correctness checks followed by the two-job, 18-thread compact
comparison in `scripts/apple-current-benchmark-README.txt`. Preserve historical
benchmark evidence. Keep Apple experiment settings isolated from Linux settings;
the Linux pool runtime is not qualified by macOS tests.
