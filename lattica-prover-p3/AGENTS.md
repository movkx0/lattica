# Pending Apple source checkpoint

The repository integration branch is `main`. Additional Apple research source
still exists in the MacBook Pro working tree and must be included in its next
source commit. Do not use SSH from the Linux host to retrieve it; the user asked
for a local Mac commit instead.

These checkpoint requirements apply to the Mac working tree containing the
pending research source, not routine Linux commits that prepare this handoff.
Remove this pending-checkpoint section once the Mac source is integrated and
validated on `main`.

Before that Mac commit, run `python3 scripts/check-apple-source-commit.py --repo ..`
from this crate. The check must pass: all six pending Rust/Metal modules must
be in the index, along with every changed source file and new benchmark helper.
Use `--stage` to stage source/configuration changes, then review
`git diff --cached`. Resolve ignored source explicitly; do not force-add
benchmark outputs or binaries. This check is for source completeness and does
not replace compilation or correctness tests.

If the Mac has not fetched these instructions yet, follow the checkpoint
commands in `scripts/apple-current-benchmark-README.txt` from `origin/main`.
First commit the Mac work on a separate checkpoint branch without resetting or
overwriting the working tree. Push that branch, then integrate it into `main`
while preserving the shared pool and native delivery changes already there.
Keep the recorded source archive and measured benchmark evidence unchanged.
