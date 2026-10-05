#!/usr/bin/env python3
"""Conditional algebra model, NOT a lookup protocol or a security certificate.

Investigate hiding cross-table lookup terminals with balanced dummy tuples.
No proof, challenge, production parameter, or prover source is changed here.
"""
from fractions import Fraction
import json

GOLDILOCKS = 2**64 - 2**32 + 1
ZERO = (0, 0, 0)
ONE = (1, 0, 0)


def add(a, b, p):
    return tuple((x + y) % p for x, y in zip(a, b))


def neg(a, p):
    return tuple(-x % p for x in a)


def mul(a, b, p):
    # X^3 = X + 1 and X^4 = X^2 + X, as in the candidate cubic field.
    c = [0] * 5
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            c[i + j] += x * y
    return ((c[0] + c[3]) % p, (c[1] + c[3] + c[4]) % p,
            (c[2] + c[4]) % p)


def power(a, exponent, p):
    result = ONE
    while exponent:
        if exponent & 1:
            result = mul(result, a, p)
        a = mul(a, a, p)
        exponent >>= 1
    return result


def inverse(a, p):
    if a == ZERO:
        raise ZeroDivisionError("zero lookup denominator")
    result = power(a, p**3 - 2, p)
    if mul(a, result, p) != ONE:
        raise ValueError("the selected cubic quotient is not a field")
    return result


def combine(elements, beta, p):
    # Matches p3-lookup 0.6.1 LogUpGadget::combine_elements: Horner order.
    result = ZERO
    for value in elements:
        result = add(mul(result, beta, p), (value % p, 0, 0), p)
    return result


def masking_determinant(beta, p):
    # [tag, edge, r0, r1, r2] has random coefficient columns [beta^2,beta,1].
    columns = (mul(beta, beta, p), beta, ONE)
    a, b, c = zip(*columns)
    return (a[0] * (b[1] * c[2] - b[2] * c[1])
            - a[1] * (b[0] * c[2] - b[2] * c[0])
            + a[2] * (b[0] * c[1] - b[1] * c[0])) % p


def balanced_terminals(terminals, masks, p):
    if len(terminals) != len(masks) or len(terminals) < 2:
        raise ValueError("a mask cycle needs at least two equally sized tables")
    return [add(add(t, masks[i], p), neg(masks[i - 1], p), p)
            for i, t in enumerate(terminals)]


def floor_inverse_bits(error):
    if not 0 < error < 1:
        raise ValueError("expected a nontrivial error upper bound")
    bits = error.denominator.bit_length() - error.numerator.bit_length()
    if (error.numerator << bits) > error.denominator:
        bits -= 1
    return bits


def describe(tables=2, statements=191):
    if tables < 2 or statements < 1:
        raise ValueError("invalid illustrative table/proof count")
    p = GOLDILOCKS
    exceptional_mixer = Fraction(1, p**2)
    mask_zero_events = Fraction(tables, p**3)
    component = statements * (exceptional_mixer + mask_zero_events)
    return {
        "status": "CONDITIONAL_ALGEBRA_ONLY_NOT_A_PROTOCOL",
        "base_modulus": str(p),
        "extension_modulus": "X^3-X-1",
        "illustrative_tables": tables,
        "conservative_statement_count": statements,
        "tuple": ["public_domain_tag", "public_edge_id", "random_base_0", "random_base_1", "random_base_2"],
        "random_coefficient_columns_in_upstream_horner_order": ["beta^2", "beta", "1"],
        "lemma": "For beta outside the base field in a degree-three extension, the three columns form a base-field basis. Independent uniform base coefficients give a uniform extension-field denominator for any fixed alpha/tag/edge.",
        "cycle": "Table i adds delta_i and subtracts delta_(i-1), preserving the total terminal sum. Uniform independent extension masks hide individual terminals subject to that sum.",
        "conditional_component_error_bound": {
            "expression": "statements * (1/p^2 + tables/p^3)",
            "numerator": str(component.numerator),
            "denominator": str(component.denominator),
            "floor_inverse_bits": floor_inverse_bits(component),
        },
        "assumptions": [
            "Irreducible cubic extension; uniform beta independent of hidden mask values.",
            "Three independent full-entropy base-field values per cycle edge.",
            "The unmasked table contributions do not depend on the newly sampled dummy tuples.",
            "Participating tables use the same alpha/beta bus challenges; alpha may include the upstream bus prefix.",
            "All dummy tuples committed before alpha/beta; no adaptive cancellation.",
            "Distinct constrained domain tags separate real wire tuples from dummy masks.",
            "Each edge tuple occurs once positively and once negatively in the complete batch.",
            "The inverse-mask argument accounts for zero denominators as an exceptional event, not a silently accepted proof.",
        ],
        "not_established": [
            "A proof-producing specialized AIR or recursive verifier.",
            "Hiding of the joint PCS/lookup transcript conditional on these public terminals.",
            "Fiat-Shamir dependence, simulator construction, or quantum random-oracle security.",
            "Lookup soundness with wider tuples, multiplicities, challenge sharing, and padding.",
            "Non-mask zero denominators or the existing hiding PCS statistical error.",
            "Complete-tree zero knowledge or soundness.",
            "Performance, proof size, recursion closure, or production readiness.",
        ],
        "implemented_in_prover": False,
        "complete_tree_security_bound": False,
        "production_ready": False,
    }


if __name__ == "__main__":
    print(json.dumps(describe(), indent=2, sort_keys=True))
