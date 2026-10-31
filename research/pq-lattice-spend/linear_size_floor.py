#!/usr/bin/env python3
"""Partial estimator floor, NOT a serialized size or a general lower bound.

Apply the original LaZer lin-codegen default profile to the 104 binary degree-256
polynomials needed just for the 52 ternary key/opening polynomials. Enumerate
every polynomial partition between the Ajtai and BDLOP commitments; omit all
other (positive) proof contributions. No Sage parameter generation is simulated.
"""
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEGREE = 256
MODULUS = 167770241
BINARY_POLYNOMIALS = 104


def ceil_sqrt(value):
    return isqrt(value) + (isqrt(value)**2 != value)


def response_bits_per_coefficient(coefficients):
    if coefficients == 0:
        return 0
    # lin-codegen: alpha=ceil(sqrt(sum(wl2_i**2))). Default gamma1=14,
    # d=64, eta=140. Z=0 for an all-binary witness.
    sigma = 14 * 140 * ceil_sqrt(coefficients)
    exponent = 0
    low = Fraction(31, 20)  # upstream round_stdev uses 1.55 * 2**exponent
    while low * 2 <= sigma:
        low *= 2
        exponent += 1
    if sigma - low > low * 2 - sigma:
        exponent += 1
    # ceil(log2(1.55 * 2**exponent) + 2.5) == exponent+4.
    return exponent + 4


def estimate_floor():
    p_half = (MODULUS - 1) // 2
    # Original lin-codegen default PSI=3358, wlinf=1, E=0.
    q_floor = 2 * (1 + 3358) * (p_half + BINARY_POLYNOMIALS * p_half * DEGREE) + 1
    # Conservative field width: actual selected q is at least this large.
    field_bits_floor = (q_floor - 1).bit_length()
    candidates = []
    for ajtai in range(BINARY_POLYNOMIALS + 1):
        a_coeffs = ajtai * DEGREE
        b_coeffs = (BINARY_POLYNOMIALS - ajtai) * DEGREE
        bits = (a_coeffs * response_bits_per_coefficient(a_coeffs)
                + b_coeffs * field_bits_floor)
        candidates.append((bits, ajtai))
    bits, ajtai = min(candidates)
    return {
        "schema": "lazer-default-linear-estimator-floor-v1",
        "binary_polynomials": BINARY_POLYNOMIALS,
        "binary_coefficients": BINARY_POLYNOMIALS * DEGREE,
        "proof_ring_degree": 64, "gamma1": 14, "eta": 140,
        "field_bits_floor": field_bits_floor,
        "partitions_checked": len(candidates),
        "minimizing_ajtai_polynomials": ajtai,
        "partial_estimator_bits_floor": bits,
        "partial_estimator_bytes_floor": (bits + 7) // 8,
        "source_parameter_generation_performed": False,
        "proof_generated": False, "serialized_bytes_measured": False,
        "full_ringct_relation": False, "security_equivalence_established": False,
        "scope": "Floor of selected terms of the original default linear estimator for binary-expanded secrets, not a wire bound or a claim about other constructions.",
    }


def source_checked_report():
    record = json.loads((ROOT / "UPSTREAM-linear-size.json").read_text())
    vendor = ROOT / "vendor/lazer-original-size-source"
    actual = {str(p.relative_to(vendor)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in vendor.rglob("*") if p.is_file()}
    if actual != record["source_files"]:
        raise ValueError("original sizing-source hash mismatch")
    return {**estimate_floor(), "revision": record["revision"],
            "source_files": record["source_files"]}


if __name__ == "__main__":
    print(json.dumps(source_checked_report(), indent=2))
