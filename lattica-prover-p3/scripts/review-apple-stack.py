#!/usr/bin/env python3
"""Review existing Apple profiles and current code without running benchmarks."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import statistics
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("apple_analysis", ROOT / "scripts/analyze-apple-hardware.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def intervals_union(intervals):
    result = []
    for start, end in sorted(intervals):
        if end < start:
            raise ValueError("Reversed diagnostic interval")
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return result


def seconds(intervals):
    return sum(end - start for start, end in intervals_union(intervals)) / 1e9


def intersection_seconds(a, b):
    a, b = intervals_union(a), intervals_union(b)
    i = j = total = 0
    while i < len(a) and j < len(b):
        total += max(0, min(a[i][1], b[j][1]) - max(a[i][0], b[j][0]))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total / 1e9


def inspect_trace(path):
    commands, waits, checkpoints = {}, [], {}
    quotient_per_checkpoint, quotient_count = [], 0
    for line in Path(path).open():
        if line.startswith("metal_profile "):
            row = json.loads(line[len("metal_profile "):])
            if row["kind"] == "command":
                if row["id"] in commands:
                    raise ValueError("Duplicate command ID")
                if not row["timestamp_valid"]:
                    raise ValueError("Invalid GPU timestamp")
                commands[row["id"]] = row
                quotient_count += row["dispatches"] if row["phase"] == "quotient_eval" else 0
            elif row["kind"] == "wait":
                waits.append(row)
        elif line.startswith("metal_profile_checkpoint "):
            if quotient_count:
                quotient_per_checkpoint.append(quotient_count)
            quotient_count = 0
        elif line.startswith(("bounded_gpu_lde_checkpoint ", "bounded_gpu_opening_checkpoint ",
                              "bounded_gpu_opening_compact_checkpoint ")):
            checkpoints[line.split()[0]] = BASE.fields(line)
    if quotient_count:
        quotient_per_checkpoint.append(quotient_count)
    gpu = [(r["gpu_start_ns"], r["gpu_end_ns"]) for r in commands.values()]
    wait = [(r["start_ns"], r["end_ns"]) for r in waits]
    overlap = intersection_seconds(gpu, wait)
    phases = {}
    for phase in sorted({r["phase"] for r in commands.values()}):
        rows = [r for r in commands.values() if r["phase"] == phase]
        phases[phase] = {
            "command_buffers": len(rows), "dispatches": sum(r["dispatches"] for r in rows),
            "median_command_gpu_us": statistics.median((r["gpu_end_ns"] - r["gpu_start_ns"]) / 1e3 for r in rows),
        }
    return {"gpu_union_seconds": seconds(gpu), "cpu_wait_union_seconds": seconds(wait),
            "cpu_wait_outside_gpu_seconds": seconds(wait) - overlap,
            "gpu_outside_cpu_wait_seconds": seconds(gpu) - overlap,
            "wait_events": len(waits), "phases": phases, "checkpoints": checkpoints,
            "quotient_dispatches_per_nonempty_checkpoint": quotient_per_checkpoint}


def derive(report, run):
    a = report["analysis"]
    traces = {}
    for label in ("reference", "resident"):
        path = run / label / "job-0/worker.log"
        if sha(path) != a[label]["worker_log_sha256"]:
            raise ValueError(f"{label} log differs from original evidence")
        traces[label] = inspect_trace(path)
        if abs(traces[label]["gpu_union_seconds"] - a[label]["gpu_busy_union_seconds"]) > 1e-8:
            raise ValueError("GPU interval calculation differs from original analysis")
        expected = a[label]["phases"]
        for phase, values in traces[label]["phases"].items():
            if (values["command_buffers"], values["dispatches"]) != (expected[phase]["commands"], expected[phase]["dispatches"]):
                raise ValueError("Command/dispatch accounting differs from original evidence")
    programs = a["resident"]["quotient_programs"]
    # All seven evaluations have the same public geometry and instruction count.
    if len(programs) != 7 or len({json.dumps(p, sort_keys=True) for p in programs}) != 1:
        raise ValueError("This review requires the profiled, identical seven quotient geometries")
    h = int(programs[0]["rows"])
    count = a["resident"]["phases"]["quotient_eval"]["dispatches"]
    if count % len(programs):
        raise ValueError("Unequal quotient dispatch count")
    tiles = count // len(programs)
    if traces["resident"]["quotient_dispatches_per_nonempty_checkpoint"] != [tiles] * len(programs):
        raise ValueError("Quotient dispatches differ across proof checkpoints")
    # ceil(h / rows) == tiles: this fixture has exactly one possible integral rows value.
    low, high = (h + tiles - 1) // tiles, (h - 1) // (tiles - 1)
    if low != high:
        raise ValueError("Tile size cannot be uniquely inferred")
    ref, res = (a[k]["last_metal"] for k in ("reference", "resident"))
    return {"traces": traces,
            "quotient": {"rows_per_evaluation": h, "evaluations": len(programs),
                         "dispatches_per_evaluation": tiles, "inferred_rows_per_tile": low,
                         "input_budget_rows": (8 << 20) // 8 // (int(programs[0]["input_columns"]) + 1),
                         "instructions_per_row": int(programs[0]["instructions"]),
                         "interpreted_instructions_total": h * len(programs) * int(programs[0]["instructions"]),
                         "tile_inference": "Code-derived from identical programs and complete dispatch accounting; not an explicitly logged tile dimension."},
            "host_copy": {"reference_bytes": int(ref["host_copy_bytes"]), "resident_bytes": int(res["host_copy_bytes"]),
                          "reference_seconds": int(ref["host_copy_ns"]) / 1e9, "resident_seconds": int(res["host_copy_ns"]) / 1e9,
                          "scope": "Explicit host-copy counters; not total memory traffic or an exclusive wall-time breakdown."},
            "poseidon": {"partial_rounds": 22, "diagonal_general_multiplies_per_round": 8,
                         "removable_general_multiplies_per_permutation": 176,
                         "diagonal": ["-2", "1", "2", "1/2", "3", "-1/2", "-3", "-4"],
                         "scope": "Source-level operation count, not an observed speedup or machine-instruction count."}}


def opportunity(title, classification, evidence, implementation, validation, benefit, integration):
    return {"title": title, "classification": classification, "evidence": evidence,
            "implementation": implementation, "validation": validation,
            "benefit_and_risk": benefit, "integration": integration}


def recommendations():
    return [
        opportunity(
            "Specialize the Poseidon2 diagonal on Metal", "First latency experiment · high confidence in applicability",
            "lde_absorb occupies 60.83s of GPU intervals. Both current Metal variants multiply all eight state words by runtime diagonal values in each of 22 partial rounds. Plonky3's CPU implementation already uses additions, subtraction and field halving for these exact constants.",
            "Port the fixed width-eight internal layer [-2, 1, 2, 1/2, 3, -1/2, -3, -4] into the checked-in shader generator. This removes 176 general field multiplications per permutation. For canonical c, half(c) = (c >> 1) + (c & 1) * ((p + 1) / 2); normalize a redundant representative first. Keep the variant independently selectable from NTT tables, unrolling and queue policy.",
            "Check full-width arithmetic boundaries, random states, CPU permutation known answers, multi-tile sponge boundaries and unchanged commitment/proof bytes under a fixed test seed. Time the existing large-row absorb shape before one full candidate aggregation.",
            "A concrete reduction in expensive exact 64-bit arithmetic. The 176 count is source-level work, not a speedup estimate; compiler optimization, extra normalization and register pressure determine the result.",
            "scripts/metal_kernel_variants.py:61; src/metal_compute/kernels.metal:198; p3-goldilocks 0.6.1/src/poseidon2.rs:708"),
        opportunity(
            "Isolate and tune the existing NTT alternatives", "Second latency experiment · measured hotspot",
            "The reference path spends 57.24s in ntt_tile. Stage fusion, bit-reversal fusion and inverse scaling fusion already exist. The cached-twiddle implementation also exists, but is gated by both resident mode and the broad optimized-kernel switch; the matched full runs used reference kernels.",
            "Expose cached tables and tile geometry as independent choices usable with the winning reference policy. Replace repeated per-thread twiddle exponentiation only where amortized table traffic is cheaper. Avoid reading roots back merely to create a cache key: use immutable transform metadata. Tune one representative large transform and one narrow-column control, preserving 32 KiB local-memory bounds and permutation ownership.",
            "Compare forward/inverse transforms and coset LDEs with CPU results, including unequal heights and multi-group transforms. Record dimensions, padding, table bytes/hits, dispatches and actual pipeline thread limits. Compare device time and total transform time.",
            "The tiny stored kernel screen is not a per-hotspot ablation. The resident run has 3,395 NTT dispatches versus 2,219 reference dispatches, despite fewer command buffers; its 121.11s cannot be attributed solely to launch policy or a slower individual butterfly. Memory-bound comments are hypotheses until counters or controlled measurements support them.",
            "src/block_v2/gpu_hash/engine/lde_execute.rs:149,288; src/metal_compute/resident.rs:93; src/metal_compute/kernels.metal:55,112"),
        opportunity(
            "Separate resident storage from GPU quotient execution", "Resident recovery · first isolate the regression",
            "Enabling resident mode also enables the GPU quotient interpreter. Seven equal programs each evaluate 4,194,304 rows and 22,576 instructions per row: about 662.8 billion interpreted instructions. Complete accounting implies 770-row tiles and 5,448 dispatches per evaluation. GPU quotient intervals total 267.23s; the reference CPU quotient span totals 27.57s, with different timing scopes.",
            "First add an explicit quotient backend policy so shared resident storage can retain CPU/NEON evaluation. For a subsequent GPU version, allocate one word for base temporaries and three for extension temporaries, reuse slots by last-use analysis, and avoid storing expressions used only once. Then consider validated build-time specialized kernels for fixed AIRs, or a more efficient typed interpreter. Keep challenge values as runtime data and retain the generic CPU fallback.",
            "Differentially compare quotient vectors and full proofs across CPU, hybrid and GPU paths on the same domains and transcript challenges. Record live temporary words, rows per tile and instruction counts. Only a component winner earns a full run; do not benchmark three full configurations automatically.",
            "The 128 MiB temporary tile allowance is binding before the 8 MiB input allowance: inputs alone allow 2,978 rows. Increasing memory limits is not the first fix. The 770-row grid suggests limited parallelism; actual occupancy/register spills have not been measured. A six-multiply cubic formula could later replace the current nine-multiply formula, after the larger interpreter/storage issue is addressed.",
            "src/block_v2/gpu_quotient_prover/mod.rs:368; gpu_quotient_prover/metal.rs:122,184,249,359,407; src/metal_compute/quotient.metal:4,20"),
        opportunity(
            "Make resident layouts useful to the next consumer", "Resident recovery · unified-memory dataflow",
            "The resident run reduces explicitly counted host copies from 250.09 GB to 109.33 GB, but host-copy time falls only from 6.08s to 2.19s. It adds 33.02s of prefix_scatter GPU intervals. SharedWords drains the queue for CPU access, and quotient inputs are still gathered and canonicalized on the CPU.",
            "Fuse retained-prefix storage into the final NTT store where row ownership permits, or preserve a tiled prefix layout that quotient/opening consumers can address directly. Pass immutable Metal-backed buffers plus explicit layout metadata to GPU consumers. Pipeline two bounded input/output slots when CPU materialization is unavoidable, waiting for each slot's completion before reuse.",
            "Validate canonical layout, bit reversal, retained-height slicing, aliasing, unwind/drain behavior and CPU-visible lifetime. Measure scatter plus transform time together, peak live bytes and end-to-end latency; a relocated cost is not a saving.",
            "Unified memory makes this ownership model practical, but shared DRAM does not remove synchronization or layout transformations. FrozenWords already provides an immutable CPU view; the missing piece is downstream GPU consumption without repacking. Global NTT-to-sponge fusion needs a separate dependency analysis because workgroups do not share a global barrier.",
            "src/metal_compute/resident.rs:43,61,150; src/block_v2/gpu_hash/prefix_storage.rs:14; engine/lde_execute.rs:666,685; gpu_quotient_prover/metal.rs:410"),
        opportunity(
            "Reduce small-command and opening-marshalling costs selectively", "Follow-up · lower GPU-time ceiling",
            "opening_reduce_compact uses 17,920 command buffers but only 0.61s of GPU intervals. The complete opening wall counter is 18.35s and includes about 13.18s of NTT work, so the difference cannot all be assigned to dispatch overhead. CPU wait outside any recorded GPU interval is 5.68s across the entire reference job.",
            "Cache pipelines and immutable arguments, marshal denominators in larger bounded tiles, and batch compatible dispatches between real dependencies. Per-slot completion events can avoid whole-queue waits. Preserve the existing transcript ordering and error cleanup. Consider Metal 4/argument buffers only after CPU encoding is shown to dominate this narrower region.",
            "Hold input geometry and kernel variant fixed. Compare command counts, CPU encode/marshal time, wait intervals and complete opening latency; check that delayed timing does not lose commands or hide failures.",
            "The wait-gap figure measures time inside recorded waits with no recorded GPU work, not all driver or encoding overhead. Numerous tiny commands justify investigation, but are weaker latency evidence than the large hash and NTT groups.",
            "src/block_v2/gpu_hash/engine/opening_reduce/compact.rs:301; src/metal_compute/mod.rs:1154,1190; src/metal_compute/resident.rs:43"),
        opportunity(
            "Keep CPU work coarse and use the existing NEON path", "Secondary CPU opportunity · profile before extending",
            "NEON-packed Goldilocks is already active. Reference CPU spans include 24.37s preprocessing, 7.41s wrapper compilation and 5.99s batch inversion; these are inclusive wall spans, not additive CPU time. Four short stack samples contain many blocked Rayon workers and do not establish a CPU instruction bottleneck.",
            "Cache immutable compiled topology separately from per-proof challenges, salts and large preprocessing matrices. Keep packed row operations and batch inversion coarse enough to amortize scheduling. For Zig-side field/Poseidon batches, inspect optimized assembly and a production-path profile before adding specialized modular reduction or a batched NEON bridge.",
            "Check cache invalidation against circuit/registry identity; maintain fresh cryptographic randomness. Use one targeted CPU-stage measurement. Distinguish cold proof latency from warm-service throughput and avoid enlarging the preprocessing cache without a memory plan.",
            "Zig field.mul still expresses a u128 remainder, but compiler lowering and production cost are unknown. The C-ABI proof copy is bounded to 2 MiB and is a poor initial target. The SME API path is slower even at one million elements, but canonicalization is timed differently from Plonky3; normalize that contract before attributing the gap to hardware.",
            "src/bin/grouped_common/mod.rs:935; src/block_v2/opening_pcs.rs; ../src/field.zig:34; ../src/poseidon2.zig:93; ../src/ffi.zig:115,257"),
    ]


HARDWARE_ROUTES = [
    {"route": "Metal exact-integer compute", "verdict": "Practical now; highest priority",
     "reason": "Already runs NTT/LDE, Poseidon/Merkle and openings. Specialize known field constants, tune existing transforms and preserve device ownership across consumers. M5 GPU tensor acceleration is a separate route from these integer shader cores."},
    {"route": "NEON / Plonky3 packed arithmetic", "verdict": "Existing CPU baseline",
     "reason": "The selected aarch64_neon module packs two u64 Goldilocks lanes, but multiplication uses interleaved scalar AArch64 mul/umulh assembly; its Poseidon path also uses scalar assembly. NEON is therefore shorthand for this optimized packed backend, not proof of two-lane hardware u64 SIMD multiplication. Keep it for quotient evaluation, reductions and small jobs."},
    {"route": "SME2 / streaming SVE", "verdict": "Conditional, coarse-kernel research only",
     "reason": "This Mac reports SME/SME2; the component uses eight streaming u64 lanes, not ZA. Its million-element API path takes 0.611 ns/element versus the packed CPU path's 0.514, about 19% longer. The harness times SME canonicalization but canonicalizes Plonky3 results after timing: this is not an equal-contract ISA comparison. First equalize that contract; only then consider a whole Poseidon/NTT tile to reuse registers. Use public ACLE, feature detection and fallback. Apple's XNU documentation describes streaming-only SVE access on current implementations; SME detection does not establish ordinary SVE support."},
    {"route": "Accelerate / vDSP / BLAS", "verdict": "No drop-in proof-arithmetic mapping",
     "reason": "Floating-point FFTs do not compute this finite-field NTT, and floating-point GEMM does not perform modular reduction. Exact limb decomposition is possible in principle only with explicit product/accumulator bounds and measured conversion costs. The current Poseidon linear layer is structured additions/halving, not a large dense matrix workload."},
    {"route": "Apple AMX / matrix engines", "verdict": "No direct private-instruction backend recommended",
     "reason": "Public Accelerate APIs may choose implementation-specific hardware, but expose no exact Goldilocks primitive or guaranteed AMX mapping. Private AMX instructions would add maintenance and validation costs without a demonstrated matrix-shaped hotspot. SME's public ZA interface is a separate programming route."},
    {"route": "M5 GPU TensorOps / Metal Performance Primitives", "verdict": "Low-priority exactness feasibility study",
     "reason": "Current Apple APIs include floating-point and quantized low-bit integer tensor formats; this is not a float-only facility. Still, support for quantized ML products does not establish exact u64 modular multiplication. An exact limb mapping would need verified accumulation semantics, overflow bounds, reductions and a dense enough batch to repay packing. No such end-to-end mapping is established here."},
    {"route": "Neural Engine / Core ML", "verdict": "No practical current proof-latency use",
     "reason": "The stack has no ML inference hotspot. Core ML model execution and compute-unit selection do not provide a verified exact Goldilocks/cubic-field primitive. Moving cryptographic arithmetic into a quantized model would create an unproven arithmetic/backend contract. It remains separate from the M5 GPU's tensor acceleration."},
]

EXTRA_SOURCES = [
    {"title": "Apple: CPU/GPU shared-buffer synchronization", "url": "https://developer.apple.com/documentation/metal/synchronizing-cpu-and-gpu-work",
     "use": "Independent resource slots and completion synchronization; unified memory still requires ownership ordering."},
    {"title": "Apple: command-buffer best practices", "url": "https://developer.apple.com/library/archive/documentation/3DDrawing/Conceptual/MTLBestPracticesGuide/CommandBuffers.html",
     "use": "Amortize submission while allowing enough queued work; not a recommendation to remove dependencies."},
    {"title": "Apple: Metal Performance Primitives guide (March 2026)", "url": "https://developer.apple.com/download/files/Metal-Performance-Primitives-Programming-Guide.pdf",
     "use": "Tensor operations, tiling and occupancy considerations. GEMM guidance is not proof that a finite-field NTT is memory-bound."},
]


def review_section(report):
    d = report["stack_review"]["derived"]
    q, c = d["quotient"], d["host_copy"]
    esc = lambda value: html.escape(str(value))
    rows = [
        ("Source freshness", "155 / 155 proof-source hashes match the profile", "Measurements apply to this worktree's current prover, including uncommitted work."),
        ("New first candidate", "176 general multiplies per Poseidon2 permutation are replaceable", "Source-derived arithmetic opportunity; no speedup has been measured."),
        ("Resident quotient tiles", f'{q["inferred_rows_per_tile"]:,} rows per tile; {q["dispatches_per_evaluation"]:,} launches per proof', "Uniquely inferred from equal program geometries, complete dispatch counts and the tile loop; the scratch allowance is binding."),
        ("Dataflow cost", f'{c["reference_bytes"]/1e9:.2f} → {c["resident_bytes"]/1e9:.2f} GB counted host copies; 33.02s resident prefix scatter', "Lower copy volume has not produced lower proof latency."),
        ("Small-command context", "17,920 opening reductions; 0.61s GPU time", "Count alone overstates priority. Opening wall time includes transforms and CPU work."),
        ("SME benchmark contract", "SME canonicalization is inside timing; Plonky3 canonicalization is outside", "The current API comparison is useful, but cannot establish an intrinsic ISA speed difference. Match output contracts before a new SME experiment."),
        ("Production integration", "C ABI → config::proof_to_bytes → CPU make_config", "Metal research runs do not measure a production-node acceleration benefit."),
    ]
    table = ''.join('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in row) + '</tr>' for row in rows)
    return f'''<section id="stack-review"><h2>What the code-level re-analysis changes</h2>
<p>This review reuses the completed matched pair. <b>No additional benchmark runs were conducted.</b> Both configurations already use Metal on the same Mac; the reference bar is not a CPU-only baseline.</p>
<div class="table-scroll"><table><thead><tr><th>Finding</th><th>Evidence</th><th>Implication</th></tr></thead><tbody>{table}</tbody></table></div>
<h3>Two separate delivery paths</h3>
<p><b>Research aggregation latency:</b> start with the existing reference Metal policy, change only the Poseidon diagonal implementation, and then isolate NTT alternatives. Evaluate resident storage with CPU quotient evaluation before investing in a replacement GPU interpreter.</p>
<p><b>Production node acceleration:</b> implement a Metal DFT/MMCS adapter for the existing production HidingFriPcs configuration and an explicit prove-only backend selector. The production GPU configuration is currently under the OpenCL <code>gpu</code> feature; enabling <code>gpu-metal</code> alone does not route production calls to it. Preserve salts, random codewords, FRI parameters, serialization and the frozen C ABI. Keep the existing CPU verifier and test join-split, HTLC and batch proofs through that ABI. The recursive candidate PCS is not a production substitute.</p>
<h3>Smallest useful validation sequence</h3>
<ol><li>Run existing arithmetic, transform, commitment and proof-equivalence checks relevant to the one changed component.</li>
<li>Use one representative large component shape and one small/tail control, with warm-up outside timing and three timed repetitions. Compare the current variant and one candidate; include preparation and layout costs.</li>
<li>Only after a clear component win, run one reference and one candidate aggregation sequentially, each with one worker and 18 threads. Require all seven proofs and the independent CPU audit. Treat one pair as directional evidence; repeat only if the result is marginal or unstable.</li></ol>
<p>Do not restore the 18/24-thread optimization matrix. Record memory pressure and swap as validity evidence. Retain the existing user-selected runtime policy; limiting experiment count does not require a new execution-time or resident-memory hard limit.</p>
<h3>Exactness boundary for matrix accelerators</h3>
<p>For b-bit unsigned limbs and a dot product of length K, <code>K × (2^b − 1)^2 &lt; 2^24</code> is a useful sufficient magnitude bound for exact integer accumulation in true FP32 arithmetic, provided inputs/products are represented exactly and the actual execution path preserves those semantics. This mathematical bound is not an API guarantee: lower-precision intermediate products, quantization/scaling, signed encodings and backend choices need separate analysis. Packing, recombination and modular reduction must also fit the latency budget. Current hotspots do not yet justify this research ahead of ordinary Metal integer kernels.</p>
</section>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    source = run / "analysis.json"
    original = json.loads(source.read_text())
    if original["status"] != "COMPLETE":
        raise ValueError("Review requires a completed profile")
    mismatches = [p for p, h in original["build"]["source_hashes"].items()
                  if not (ROOT / p).is_file() or sha(ROOT / p) != h]
    if mismatches:
        raise ValueError("Prover changed since profiling: " + ", ".join(mismatches))
    report = copy.deepcopy(original)
    report.update(schema="apple-stack-review-v1", generated_utc=datetime.now(timezone.utc).isoformat(),
                  headline="Prioritize exact Metal hashing and transforms; separate resident storage from quotient execution.",
                  summary="The current reference Metal aggregation takes 257.51s; resident takes 568.99s. A new code-level finding makes Poseidon2 diagonal specialization the first focused experiment. Production-node acceleration requires a separate backend integration step.",
                  recommendations=recommendations(), hardware_routes=HARDWARE_ROUTES)
    audited = ["scripts/review-apple-stack.py", "scripts/analyze-apple-hardware.py", "scripts/check-apple-analysis-report.mjs", "scripts/metal_kernel_variants.py",
               "src/config.rs", "src/metal_compute/kernels.metal", "src/metal_compute/resident.rs",
               "src/block_v2/gpu_quotient_prover/metal.rs", "src/block_v2/gpu_quotient_prover/mod.rs",
               "src/block_v2/gpu_hash/engine/lde_execute.rs", "../src/field.zig", "../src/poseidon2.zig",
               "../src/ffi.zig", "../src/prover_abi.zig", "../build.zig"]
    registry_root = ROOT.parents[2] / "cargo/registry"
    package = "p3-goldilocks-0.6.1"
    registry = registry_root / f"src/index.crates.io-1949cf8c6b5b557f/{package}"
    # The shared toolchain lives at the checkout's .tools directory, outside the worktree.
    if not registry.is_dir():
        raise ValueError(f"Missing pinned CPU implementation: {registry}")
    archive = next((registry_root / "cache").glob(f"*/{package}.crate"))
    expected = next(p["checksum"] for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"] if p["name"] == "p3-goldilocks")
    if sha(archive) != expected:
        raise ValueError("CPU dependency archive differs from Cargo.lock")
    cpu_files = ["src/poseidon2.rs", "src/aarch64_neon/packing.rs", "src/aarch64_neon/poseidon2.rs"]
    with tarfile.open(archive) as packed:
        for name in cpu_files:
            if (registry / name).read_bytes() != packed.extractfile(f"{package}/{name}").read():
                raise ValueError(f"Inspected CPU source differs from pinned archive: {name}")
    report["stack_review"] = {
        "input_analysis_path": str(source), "input_analysis_sha256": sha(source), "new_benchmark_runs": 0,
        "proof_source_hashes_matched": len(original["build"]["source_hashes"]),
        "reviewed_source_hashes": {p: sha(ROOT / p) for p in audited},
        "cpu_dependency": {"source_directory": str(registry), "archive_path": str(archive),
                           "archive_sha256": expected, "matches_lock_and_archive": True,
                           "audited_files": {name: sha(registry / name) for name in cpu_files}},
        "derived": derive(report, run),
        "qualification": "Recommendations only; no new acceleration kernel or production backend implemented.",
    }
    report["sources"].extend(EXTRA_SOURCES)
    report["limitations"].extend([
        "New tile-size and operation-count findings are code-derived inferences, not new performance measurements. Hardware occupancy, register spills, memory bandwidth and instruction throughput were not captured.",
        "The paired full runs bundle resident storage, compact retention, quotient backend and queue policy changes. They identify a regression but do not isolate each change causally.",
        "The existing twiddle cache, unrolled permutation and limb-product variants are already implemented experiments; no claim is made that enabling the combined optimized switch is faster.",
        "The SME component times a different output contract: canonical u64 output inside its loop versus Plonky3 normalization after timing. Its API-path timings do not isolate ISA performance. The packed CPU multiply itself uses scalar AArch64 assembly.",
    ])
    report["stack_audit"][1]["finding"] = (
        "Production config::proof_to_bytes selects CPU make_config. config::gpu and its hiding GPU PCS are OpenCL-feature gated; gpu-metal is used by the block-v2 research path. A production Metal adapter and explicit backend selection are needed. The frozen C ABI and existing CPU verifier remain the compatibility boundary.")
    args.out.mkdir(parents=True, exist_ok=False)
    args.html.parent.mkdir(parents=True, exist_ok=True)
    evidence = args.out / "analysis.json"
    evidence.write_text(json.dumps(report, indent=2) + "\n")
    rendered = args.out / "rendered-base.html"
    BASE.render(report, rendered)
    page = rendered.read_text()
    marker = "<h2>The stack and the measured boundary</h2>"
    if page.count(marker) != 1:
        raise ValueError("Analysis renderer layout changed")
    page = page.replace(marker, review_section(report) + marker)
    page = page.replace("Where Apple hardware can help Lattica", "Lattica: Apple acceleration stack review")
    page = page.replace("Lattica · Apple hardware acceleration analysis", "Lattica · Apple acceleration stack review")
    page = page.replace("</style>", "main{overflow-wrap:anywhere}</style>")
    args.html.write_text(page)
    # Keep reproducibility inputs outside the historical run directory.
    (args.out / "review-apple-stack.py").write_bytes(Path(__file__).read_bytes())
    (args.out / "renderer.py").write_bytes((ROOT / "scripts/analyze-apple-hardware.py").read_bytes())
    print(json.dumps({"status": "COMPLETE", "new_benchmark_runs": 0, "matched_proof_sources": len(original["build"]["source_hashes"]),
                      "evidence": str(evidence), "html": str(args.html), "quotient_rows_per_tile": report["stack_review"]["derived"]["quotient"]["inferred_rows_per_tile"]}, indent=2))


if __name__ == "__main__":
    main()
