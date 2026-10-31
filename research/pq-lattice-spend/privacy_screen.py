#!/usr/bin/env python3
"""Algebraic privacy screen for the pinned ProveKit matrix-opening path.

This is a model of the explicit matrix-evaluation messages in the reviewed
source, not an execution of ProveKit and not a RingCT proof or exploit against
an application. Upstream already documents that these evaluations remain clear.
"""
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Arkworks BN254 scalar modulus. The counterexample holds over any field.
BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def eq_weights(alpha, modulus):
    weights = [1]
    for coordinate in alpha:
        weights = [part for weight in weights for part in
                   (weight * (1-coordinate) % modulus, weight * coordinate % modulus)]
    return weights


def binary_relation(rows):
    # Witness [1, secret], same public relation for secret=0 and secret=1.
    # Every row proves secret * (secret - 1) = 0.
    return ([[0, 1] for _ in range(rows)],
            [[-1, 1] for _ in range(rows)],
            [[0, 0] for _ in range(rows)])


def dot(left, right, modulus):
    if len(left) != len(right):
        raise ValueError("vector length mismatch")
    return sum(a*b for a, b in zip(left, right)) % modulus


def valid_witness(matrices, witness, modulus):
    a, b, c = matrices
    return all((dot(ar, witness, modulus) * dot(br, witness, modulus)
                - dot(cr, witness, modulus)) % modulus == 0
               for ar, br, cr in zip(a, b, c))


def clear_openings(matrices, witness, alpha, modulus):
    # Source path: transpose the three R1CS matrices, multiply by eq(alpha),
    # then dot each resulting covector with the original zero-padded witness.
    weights = eq_weights(alpha, modulus)
    if any(len(matrix) != len(weights) for matrix in matrices):
        raise ValueError("matrix/point dimension mismatch")
    messages = []
    for matrix in matrices:
        covector = [sum(row[column] * weight for row, weight in zip(matrix, weights)) % modulus
                    for column in range(len(witness))]
        messages.append(dot(covector, witness, modulus))
    return messages


def direct_row_evaluations(matrices, witness, alpha, modulus):
    # Independent order of operations: evaluate rows first, then their MLE.
    weights = eq_weights(alpha, modulus)
    return [dot([dot(row, witness, modulus) for row in matrix], weights, modulus)
            for matrix in matrices]


def verify_sources():
    manifest = json.loads((ROOT / "UPSTREAM-privacy-screen.json").read_text())
    source = ROOT / "vendor/provekit-privacy-source"
    hashes = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in source.rglob("*") if p.is_file()}
    if hashes != manifest["source_files"]:
        raise ValueError("reviewed privacy-source hashes changed")
    return manifest


def run_screen():
    provenance = verify_sources()
    relation = binary_relation(8)
    point_count = 0
    witness_checks = 0
    for modulus in (17, BN254_FR):
        points = (itertools.product(range(17), repeat=3) if modulus == 17 else
                  ([int.from_bytes(hashlib.sha256(f"privacy-screen/{i}/{j}".encode()).digest(),
                                   "big") % modulus for j in range(3)] for i in range(128)))
        for alpha in points:
            point_count += 1
            assert sum(eq_weights(alpha, modulus)) % modulus == 1
            for secret in (0, 1):
                witness = [1, secret]
                assert valid_witness(relation, witness, modulus)
                messages = clear_openings(relation, witness, alpha, modulus)
                assert messages == direct_row_evaluations(relation, witness, alpha, modulus)
                assert messages == [secret, (secret-1) % modulus, 0]
                witness_checks += 1
        assert not valid_witness(relation, [1, 2], modulus)
    return {
        "schema": "clear-matrix-opening-privacy-screen-v1",
        "upstream_revision": provenance["revision"],
        "source_files": provenance["source_files"],
        "public_relation": "Eight rows of s*(s-1)=0, witness [1,s], no public s",
        "valid_secret_choices": [0, 1],
        "opening_messages": "[s, s-1, 0] in the field, independent of alpha",
        "challenge_points_checked": point_count,
        "valid_witness_checks": witness_checks,
        "secret_recovered_from_first_message": True,
        "full_zero_knowledge_admissible": False,
        "upstream_prover_executed": False,
        "proof_generated": False,
        "serialized_bytes_measured": False,
        "full_ringct_relation": False,
        "scope": "Algebraic model of the documented clear matrix-evaluation messages; not an end-to-end proof execution or an application exploit.",
    }


if __name__ == "__main__":
    print(json.dumps(run_screen(), indent=2))
