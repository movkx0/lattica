"""Shared audited dependency manifest for table-generation receipt checks."""
import re
from pathlib import PurePosixPath
from opencl_private_spend_validate import ROOT
MANIFEST = 'lattica-prover-p3/src/block_v2/machine/numeric_sources.rs'

def selected(label, native=False):
    path = PurePosixPath(label)
    if label.endswith('/precomputed/data.rs') or path.name == 'tests.rs' or path.name.endswith('_tests.rs') or 'tests' in path.parts:
        return False
    if path.suffix != '.rs' and path.name not in ('Cargo.toml','Cargo.lock'):
        return False
    entries = re.findall(r'"(core|native):([^"\n]+)"', (ROOT / MANIFEST).read_text())
    return any((native or scope == 'core') and (label == prefix or prefix.endswith('/') and label.startswith(prefix)) for scope,prefix in entries)

def select_receipt(files, native=False):
    # Runtime invalidation uses only the Rust manifest. Reproduction additionally
    # pins the qualification/generation tooling and tests to the recorded run.
    return {k:v for k,v in files.items() if selected(k,native) or k.startswith('research/pq-ringct/tools/')}
