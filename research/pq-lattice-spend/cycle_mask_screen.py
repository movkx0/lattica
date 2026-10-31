#!/usr/bin/env python3
"""Integer algebra screen for PKC 2025's cycle-masked balance relation.

No commitments, rejection sampler, transcript, proof or wire codec are implemented.
All inputs are synthetic public test vectors, not real transaction witnesses.
"""
import hashlib
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parent
CAMPAIGN = ROOT.parents[2]
NATIVE_Q = 167770241
TOY_UPSTREAM_Q = 17112760193


def integer_vector(values, minimum=1, maximum=64):
    if not minimum <= len(values) <= maximum or any(type(v) is not int for v in values):
        raise ValueError("invalid integer vector")
    return tuple(values)


def bit_difference(inputs, outputs, bits=52):
    if type(bits) is not int or not 1 <= bits <= 64:
        raise ValueError("invalid bit width")
    inputs = integer_vector(inputs, 2, 2)
    outputs = integer_vector(outputs, 2, 2)
    if any(not 0 <= v < 1 << bits for v in inputs + outputs):
        raise ValueError("amount outside range")
    return tuple(sum((v >> j) & 1 for v in outputs) - sum((v >> j) & 1 for v in inputs)
                 for j in range(bits))


def weighted_sum(values):
    return sum(v << j for j, v in enumerate(integer_vector(values)))


def cycle_map(interior):
    """d[j] = r[j] - 2*r[j+1], with r[0] = r[k] = 0, over integers."""
    r = (0,) + integer_vector(interior, 0, 63) + (0,)
    return tuple(a - 2*b for a, b in zip(r, r[1:]))


def cycle_preimage(values):
    """Recover the unique integer preimage, rejecting a nonzero endpoint."""
    values = integer_vector(values)
    r = [0] * (len(values) + 1)
    for j in range(len(values) - 1, 0, -1):
        r[j] = values[j] + 2*r[j+1]
    if values[0] != -2*r[1]:
        raise ValueError("vector does not satisfy exact integer balance")
    return tuple(r[1:-1])


def reconstruct_head(tail, bound):
    """Reconstruct the omitted response over Z, without reducing modulo q."""
    tail = integer_vector(tail, 0, 63)
    if type(bound) is not int or bound < 0:
        raise ValueError("invalid coefficient bound")
    head = -sum(v << (j+1) for j, v in enumerate(tail))
    if any(abs(v) > bound for v in (head,) + tail):
        raise ValueError("response coefficient outside bound")
    return head


def modular_packed_check(coefficients, bits, modulus):
    """Algebraic model of upstream Basic.go CheckPackedf, not its execution."""
    coefficients = integer_vector(coefficients, 256, 256)
    if type(bits) is not int or bits <= 0 or 256 % bits:
        raise ValueError("invalid packed geometry")
    if type(modulus) is not int or modulus <= 2:
        raise ValueError("invalid modulus")
    if any(not 0 <= v < modulus for v in coefficients):
        raise ValueError("noncanonical residue")
    stride = 256 // bits
    return all(sum(coefficients[stride*j + lane] << j for j in range(bits)) % modulus == 0
               for lane in range(stride))


def coefficient_packing_probe(modulus):
    """A balanced coefficient-packed vector need not stay balanced after multiplication.

    (2-X^4) * X^252 = 1+2*X^252 in Z[X]/(X^256+1).
    Its lane-zero weighted sum is 1+2^64. The other 43 challenge terms
    do not wrap and contribute zero. No transcript preimage is constructed.
    This models the Go source's coefficient packing, not native partial NTT.
    """
    c = bit_difference((2, 0), (1, 1), 64)
    challenge = [1] * 43 + [0] * (252-43) + [1, 0, 0, 0]
    product = [0] * 256
    for i, x in enumerate(challenge):
        for j, value in enumerate(c):
            power = i+4*j
            product[power % 256] += x*value * (-1 if power >= 256 else 1)
    lanes = [sum(product[4*j+lane] << j for j in range(64)) for lane in range(4)]
    accepted = modular_packed_check([v % modulus for v in product], 64, modulus)
    if weighted_sum(c) != 0 or lanes != [(1 << 64)+1, 0, 0, 0] or accepted:
        raise ValueError("coefficient-packing probe did not reproduce")
    return dict(modulus=modulus, inputs=[2, 0], outputs=[1, 1],
                original_integer_imbalance=0, challenge_nonzero_coefficients=44,
                product_weighted_sums=lanes, modeled_modular_check_accepts=accepted,
                transcript_preimage_constructed=False, native_partial_ntt_modeled=False)


def verify_sources():
    manifest = json.loads((ROOT / "UPSTREAM-cycle-mask.json").read_text())
    for name, digest in manifest["source_files"].items():
        if hashlib.sha256((CAMPAIGN / name).read_bytes()).hexdigest() != digest:
            raise ValueError("reviewed source changed: " + name)
    return manifest


def run_screen():
    provenance = verify_sources()
    # Reproducible public arithmetic cases; this is not a cryptographic sampler.
    rng = random.Random(20261030)
    maximum = (1 << 52) - 1
    cases = [((0, 0), (0, 0)), ((maximum, maximum), (maximum, maximum)),
             ((maximum, 1), (1 << 51, 1 << 51))]
    for _ in range(1024):
        a, b = rng.randrange(maximum+1), rng.randrange(maximum+1)
        out = rng.randrange(max(0, a+b-maximum), min(maximum, a+b)+1)
        cases.append(((a, b), (out, a+b-out)))
    for inputs, outputs in cases:
        c = bit_difference(inputs, outputs)
        carries = cycle_preimage(c)
        r = tuple(rng.randrange(-100000, 100001) for _ in range(51))
        mask = cycle_map(r)
        x = 44  # A scalar algebra test, not a valid native transcript challenge.
        f = tuple(x*v+d for v, d in zip(c, mask))
        expected = cycle_map(tuple(u+x*v for u, v in zip(r, carries)))
        if (weighted_sum(c) != sum(outputs)-sum(inputs) or weighted_sum(f) != 0
                or f != expected or reconstruct_head(f[1:], NATIVE_Q//2) != f[0]):
            raise ValueError("cycle algebra mismatch")
    aliases = []
    for modulus in (NATIVE_Q, TOY_UPSTREAM_Q):
        inputs, outputs = (1, 1), (modulus+1, 1)
        c = bit_difference(inputs, outputs, 64)
        packed = [0] * 256
        for j, value in enumerate(c):
            packed[4*j] = value % modulus
        accepted = modular_packed_check(packed, 64, modulus)
        try:
            reconstruct_head(c[1:], modulus//2)
        except ValueError:
            exact_rejected = True
        else:
            exact_rejected = False
        if not (accepted and exact_rejected and weighted_sum(c) == modulus):
            raise ValueError("modular alias counterexample failed")
        aliases.append(dict(modulus=modulus, inputs=inputs, outputs=outputs,
                            integer_imbalance=weighted_sum(c), all_amounts_fit_52_bits=True,
                            modeled_modular_check_accepts=accepted,
                            exact_bounded_reconstruction_rejects=exact_rejected))
    packing = [coefficient_packing_probe(q) for q in (NATIVE_Q, TOY_UPSTREAM_Q)]
    return dict(schema="cycle-mask-algebra-screen-v1", revision=provenance["revision"],
                balanced_cases=len(cases), modular_aliases=aliases,
                coefficient_packing_probes=packing,
                full_relation=False, proof_generated=False, upstream_executed=False,
                zero_knowledge_established=False, serialized_bytes_measured=False,
                replacement_qualified=False,
                scope="Integer balance identities and a component-check counterexample only; "
                      "not a full proof forgery or a cryptographic implementation.")


if __name__ == "__main__":
    print(json.dumps(run_screen(), indent=2))
