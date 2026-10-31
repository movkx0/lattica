#!/usr/bin/env python3
"""Test the naive packed cycle-mask adapter using unchanged native arithmetic.

This is an algebra experiment, not a prover, verifier, or new security profile.
The native challenges are read from the 32 previously validated public artifacts.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess

ROOT = Path(__file__).resolve().parent
CAMPAIGN = ROOT.parents[2]
BASELINE = CAMPAIGN.parent / "compact-proof-v3-20261030"
NATIVE = ROOT.parent / "pq-ringct/vendor/matrict-plus/n10"
Q = 167770241
D = 256
SLOTS = 64
LANES = 4
MONT = pow(2, 32, Q)
MONT_INV = pow(MONT, -1, Q)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_sources():
    manifest = json.loads((ROOT / "NATIVE-CYCLE-SOURCES.json").read_text())
    for name, expected in manifest["native_files"].items():
        if sha(NATIVE / name) != expected:
            raise ValueError("native source mismatch: " + name)
    if sha(BASELINE / "VALIDATION.json") != manifest["validation_sha256"]:
        raise ValueError("baseline validation record changed")
    if sha(BASELINE / "measurement-1/report.json") != manifest["measurement_sha256"]:
        raise ValueError("baseline measurement report changed")
    return manifest


def evaluation_powers():
    # The first CRT factor is X^4 - omega_q[32]/MontgomeryRadix.
    # The remaining factors use exponents +/-3^j, in the documented order.
    source = (NATIVE / "poly_q.c").read_text()
    body = re.search(r"omega_q\[R\]\s*=\s*\{([^}]+)\}", source).group(1)
    omega = [int(v) for v in re.findall(r"\d+", body)]
    if len(omega) != 64:
        raise ValueError("unexpected native twiddle table")
    primitive = omega[32] * MONT_INV % Q
    roots = [pow(primitive, sign*pow(3, j, 128) % 128, Q)
             for sign in (1, -1) for j in range(32)]
    if pow(primitive, 64, Q) != Q-1 or len(set(roots)) != 64:
        raise ValueError("invalid CRT roots")
    return [[pow(root, j, Q) for j in range(64)] for root in roots]


def evaluate(poly, powers):
    """Independent direct CRT evaluation, with ordinary field representatives."""
    if len(poly) != 256:
        raise ValueError("polynomial length")
    lanes = [[(j, poly[4*j+lane]) for j in range(64) if poly[4*j+lane]]
             for lane in range(4)]
    return [sum(value * row[j] for j, value in lane) % Q
            for row in powers for lane in lanes]


class Poly(ctypes.Structure):
    _fields_ = [("coefficients", ctypes.c_uint64 * 256)]


def as_poly(values):
    if len(values) != 256:
        raise ValueError("polynomial length")
    return Poly((ctypes.c_uint64 * 256)(*(v % Q for v in values)))


def native_ntt(library, values):
    poly = as_poly(values)
    library.ntt_q(ctypes.byref(poly))
    return list(poly.coefficients)


def normalize(values):
    return [v * MONT_INV % Q for v in values]


def public_challenges():
    report = json.loads((BASELINE / "measurement-1/report.json").read_text())
    if len(report["cases"]) != 32:
        raise ValueError("expected all 32 validated cases")
    for ordinal, case in enumerate(report["cases"]):
        artifact = case["artifacts"]["native"]
        name = artifact["file"]
        if Path(name).name != name:
            raise ValueError("artifact path must be a basename")
        packet = (BASELINE / "measurement-1" / name).read_bytes()
        if (len(packet) != 256532 or packet[:8] != b"LPQMPK01"
                or hashlib.sha3_256(packet).hexdigest() != artifact["sha3_256"]):
            raise ValueError("validated native artifact changed")
        # Native packet framing = 84 bytes; statement = 202848 bytes.
        # Proof: seven Q polys, five QHAT polys, 32-byte alpha, then 2-bit x.
        offset = 84 + 202848 + 7*28*32 + 5*32*32 + 32
        packed = int.from_bytes(packet[offset:offset+64], "little")
        digits = [(packed >> (2*j)) & 3 for j in range(256)]
        if any(v > 2 for v in digits):
            raise ValueError("invalid challenge coefficient")
        x = [v-1 for v in digits]
        if any(sum(bool(v) for v in x[lane::4]) != 11 for lane in range(4)):
            raise ValueError("challenge violates native group weights")
        yield ordinal, artifact["sha3_256"], x


def screen(output):
    manifest = checked_sources()
    output = output.resolve()
    if output.parent != CAMPAIGN:
        raise ValueError("output must be a fresh child of the research campaign")
    output.mkdir(exist_ok=False)
    library_path = output / "native_arithmetic.so"
    command = ["/usr/bin/cc", "-O2", "-std=c11", "-fPIC", "-shared",
               "-o", str(library_path), str(NATIVE / "poly_q.c")]
    built = subprocess.run(command, capture_output=True, timeout=60, check=False)
    (output / "build.log").write_bytes(built.stdout + built.stderr)
    if built.returncode:
        raise ValueError("native arithmetic build failed; see build.log")
    library = ctypes.CDLL(str(library_path))
    library.ntt_q.argtypes = [ctypes.POINTER(Poly)]
    library.ntt_q.restype = None
    library.mult_rq.argtypes = [ctypes.POINTER(Poly)] * 3
    library.mult_rq.restype = None
    powers = evaluation_powers()
    rng = random.Random(20261031)  # Public differential vectors only.
    vectors = [[int(i == j) for i in range(256)] for j in range(256)]
    vectors += [[rng.randrange(Q) for _ in range(256)] for _ in range(16)]
    for values in vectors:
        if normalize(native_ntt(library, values)) != evaluate(values, powers):
            raise ValueError("native NTT disagrees with direct CRT evaluation")
    cases = []
    first_failure = None
    for ordinal, digest, x in public_challenges():
        transformed = native_ntt(library, x)
        ordinary = normalize(transformed)
        if ordinary != evaluate(x, powers):
            raise ValueError("observed challenge NTT mismatch")
        failed = 0
        for j in range(51):
            # A valid 52-bit balance: inputs (2^(j+1),0), outputs (2^j,2^j).
            # Its packed difference is 2 in slot j and -1 in slot j+1.
            difference = [0] * 256
            difference[4*j] = 2*MONT % Q
            difference[4*(j+1)] = -MONT % Q
            a, b, product = as_poly(transformed), as_poly(difference), Poly()
            library.mult_rq(ctypes.byref(product), ctypes.byref(a), ctypes.byref(b))
            f = normalize(product.coefficients)
            expected = [0] * 256
            for lane in range(4):
                expected[4*j+lane] = 2*ordinary[4*j+lane] % Q
                expected[4*(j+1)+lane] = -ordinary[4*(j+1)+lane] % Q
            if f != expected:
                raise ValueError("native packed product mismatch")
            residual = [sum((f[4*k+lane] << k) for k in range(64)) % Q
                        for lane in range(4)]
            failed += any(residual)
            if any(residual) and first_failure is None:
                first_failure = dict(case=ordinal, adjacent_bit=j,
                                     inputs=[1 << (j+1), 0], outputs=[1 << j, 1 << j],
                                     weighted_product_mod_q=residual)
        cases.append(dict(case=ordinal, native_artifact_sha3_256=digest,
                          failed_naive_balance_checks=failed, valid_balances_tested=51))
    checked_sources()
    if first_failure is None:
        raise ValueError("no obstruction reproduced; reassess the adapter")
    result = dict(schema="native-cycle-packing-screen-v1", source_manifest=manifest,
                  compiler_command=command, library_sha256=sha(library_path),
                  ntt_differential_vectors=len(vectors)+len(cases),
                  native_product_comparisons=51*len(cases), cases=cases,
                  first_failure=first_failure,
                  naive_adapter_preserves_balance=False,
                  unpacked_response_geometry=dict(bit_width=52, transmitted_polynomials=51,
                                                  degree=256, coefficients=51*256,
                                                  serialized_bytes_estimate=None),
                  common_low_degree_ternary_challenge=dict(max_nonzero_coefficients=4,
                      native_required_nonzero_coefficients=44,
                      compatible_with_existing_profile=False),
                  proof_generated=False, full_relation=False, zero_knowledge_established=False,
                  proof_size_improvement_measured=False, replacement_qualified=False,
                  limitations=["Rules out the naive single packed response with the fixed weighted-sum check only.",
                      "Zero masks isolate an algebra identity; no sampler or proposed proof is executed.",
                      "The full paper and other packed balance constructions are not ruled out.",
                      "Unpacking geometry is not a proof-size estimate or a security parameter choice."])
    (output / "report.json").write_text(json.dumps(result, indent=2)+"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    report = screen(args.output_directory)
    print(json.dumps({key:report[key] for key in ("ntt_differential_vectors",
        "native_product_comparisons", "first_failure", "naive_adapter_preserves_balance",
        "proof_generated", "proof_size_improvement_measured")}, indent=2))
