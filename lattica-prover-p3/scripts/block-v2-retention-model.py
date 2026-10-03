#!/usr/bin/env python3
"""Logical storage/transfer model for the pinned v2 geometry, not a speed estimate."""
import argparse
import hashlib
import json
from pathlib import Path

PROFILE = "e90be22347a149b82c2a961cb14a33414b6db2d8221d0eda9fdfc174bf0143be"
GIB = 1 << 30


def geometry(height=524288, main_width=94, preprocessed_width=70,
             permutation_width=21, quotient_chunks=16):
    if height < 8 or height & (height - 1) or height * 32 > 1 << 32:
        raise ValueError("unsupported model height")
    if min(main_width, preprocessed_width, permutation_width, quotient_chunks) <= 0:
        raise ValueError("model widths must be positive")
    domain = height * 2 * 16  # hiding-domain doubling and unchanged blowup16
    folds = height.bit_length()  # log2(height) + 1, binary FRI
    fri_heights = [domain >> i for i in range(1, folds + 1)]
    widths = {
        "main": main_width + 4,
        "preprocessing": preprocessed_width,
        "permutation": permutation_width + 4,
        "quotient": quotient_chunks * (3 + 4),
        "random_round": 3 + 4,
    }
    retained = {k: v * domain * 8 for k, v in widths.items()}
    uploads = {
        "main": (widths["main"] + 4) * domain * 8,
        "permutation": (widths["permutation"] + 4) * domain * 8,
        "quotient": (widths["quotient"] + quotient_chunks * 4) * domain * 8,
        "random_round": (widths["random_round"] + 4) * domain * 8,
        "fri": sum(fri_heights) * (2 * 3 + 4) * 8,
    }
    preprocessing_upload = (preprocessed_width + 4) * domain * 8
    def tree(rows):
        return (2 * rows - 1) * 4 * 8
    fri_trees = sum(tree(rows) for rows in fri_heights)
    cache_hit_trees = 4 * tree(domain) + fri_trees
    retained_trees = cache_hit_trees + tree(domain)
    # Four base commitments, but quotient has one salt matrix per chunk. The
    # existing GPU ProverData stores salts and *all* binary-tree layers on host.
    salt_bytes = (quotient_chunks + 4) * domain * 4 * 8 + sum(fri_heights) * 4 * 8
    return {
        "height": height,
        "lde_height": domain,
        "binary_fri_commits": folds,
        "retained_lde_bytes_by_family": retained,
        "retained_lde_bytes": sum(retained.values()),
        "cache_hit_h2d_bytes_by_family": uploads,
        "cache_hit_h2d_bytes": sum(uploads.values()),
        "cache_miss_h2d_bytes": sum(uploads.values()) + preprocessing_upload,
        "cache_hit_d2h_full_tree_bytes": cache_hit_trees,
        "cache_miss_d2h_full_tree_bytes": retained_trees,
        "host_retained_full_tree_bytes_including_preprocessing": retained_trees,
        "host_retained_salt_bytes_including_preprocessing": salt_bytes,
        "logical_retained_lde_salts_trees_bytes": sum(retained.values()) + retained_trees + salt_bytes,
        "measured_peak_ram": False,
        "omitted": ["allocator and program metadata", "temporary arithmetic/DFT workspaces", "retained FRI input/fold vectors", "coefficient/randomness buffers", "page-cache and mapping residency effects"],
    }


def validate_evidence(evidence, model):
    profile = evidence["profile"]
    expected = {"independently_pinned_id_hex": PROFILE, "common_height": 524288,
                "challenge_extension_degree": 3, "fri_queries": 128,
                "log_blowup": 4, "random_codewords": 4}
    if any(profile.get(k) != v for k, v in expected.items()):
        raise ValueError("evidence is not the independently pinned baseline geometry")
    checked = 0
    for trial in evidence["trials"]:
        for node in trial["nodes"]:
            hit = node["preprocessing_cache_hit"]
            if not isinstance(hit, bool):
                raise ValueError("cache state must be explicit")
            prefix = "cache_hit" if hit else "cache_miss"
            if node["gpu_delta"]["uploaded_bytes"] != model[prefix + "_h2d_bytes"]:
                raise ValueError("upload model differs from measured counters")
            if node["gpu_delta"]["downloaded_bytes"] != model[prefix + "_d2h_full_tree_bytes"]:
                raise ValueError("download model differs from measured counters")
            checked += 1
    if checked != 35:
        raise ValueError("expected the complete five-trial/35-node baseline")
    return checked


def report(evidence_path):
    data = evidence_path.read_bytes()
    baseline = geometry()
    checked = validate_evidence(json.loads(data), baseline)
    # Optimistic structural thought experiment only: one extra column per
    # Poseidon S-box (8 full rounds * 8 words + 22 partial rounds), halved
    # quotient count, unchanged other widths/height. Actual lookup packing and
    # recursive closure MUST be recomputed; this is not an implemented AIR.
    low_degree = geometry(main_width=94 + 86, quotient_chunks=8)
    return {
        "schema_version": 1,
        "status": "SOURCE_AND_TRANSFER_ACCOUNTING_MODEL_NOT_A_PROTOTYPE_OR_BENCHMARK",
        "baseline_evidence": str(evidence_path),
        "baseline_evidence_sha256": hashlib.sha256(data).hexdigest(),
        "baseline_nodes_with_exact_h2d_and_d2h_match": checked,
        "profile_id": PROFILE,
        "baseline": baseline,
        "illustrative_lower_degree_sbox_with_unchanged_other_widths": low_degree,
        "illustrative_change_in_retained_lde_GiB": (low_degree["retained_lde_bytes"] - baseline["retained_lde_bytes"]) / GIB,
        "illustrative_change_in_cache_hit_h2d_GiB": (low_degree["cache_hit_h2d_bytes"] - baseline["cache_hit_h2d_bytes"]) / GIB,
        "interpretation": [
            "The 39 GiB admission figure counts LDEs only, not salts, full host Merkle trees, or temporary workspaces.",
            "The listed LDE/salt/tree storage is not a complete process-memory estimate or measured resident memory and must not be added to cgroup RAM or mapped spill peaks.",
            "At fixed geometry, quotient input and salt uploads dominate H2D volume.",
            "Retaining full trees on the GPU is only a candidate design: it requires aggregate managed-memory admission and lifetime/cancellation tests.",
            "Lower AIR degree alone can increase total polynomial storage; layout, lookup packing and recursive closure must be evaluated together.",
            "No cryptographic parameter, production default, or verifier identity was changed by this model.",
        ],
        "production_ready": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    print(json.dumps(report(args.evidence), indent=2, sort_keys=True))
