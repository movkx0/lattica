# Recursion — aggregation-level soundness parameters (R3)

> **Research specification:** Parameters for experimental recursive aggregation; not part of the production C ABI or audit boundary.

> **SUPERSEDED PARAMETER ROADMAP:** [Block-proving v2](block-proving-v2.md) specifies a separate,
> **CANDIDATE / INACTIVE** cubic-extension binary-FRI profile (q128/lb4/cap6/cw4/pow16), not the
> quadratic/q96 experiments below. It is unfrozen pending complete-tree soundness
> and full-depth qualification. The bounded engine has a real two-level recursive
> proof and root-only verification after inner-artifact deletion; see the
> [current measurements](bounded-execution-engine.md). Depth-six/64-transaction
> performance and security gates remain open. Historical v1 parameters are unchanged.

**Status: historical design + measurement, on branch `v3`.** Companion to `docs/recursion-design.md`
and `docs/recursion-verifier-audit.md`. The measurements and monolith feasibility curve below are
retained as research evidence, not as approved v2 parameters, a whole-tree security proof, or an
operator hardware recommendation.

Prerequisite achieved (2026-07-03, commits `165a577` + `7d6a5ad`): the monolith
(`recursion/monolith`) accept-iff-`p3::verify`s a **real production `JoinSplitAir` proof**, both
non-hiding and hiding (`is_zk=1`), through the data-driven symbolic epilogue. So the in-circuit verifier
has standalone research evidence. Bounded self-composition and independent root-only verification
remain unresolved; choosing parameters alone does not implement them.

## 1. Per-proof accounting is not complete-tree soundness

The original roadmap used the minimum per-level FRI bit count as a tree security argument. That is
not sufficient: complete-tree accounting must include all relevant proof instances and composition
losses, transcript/hash assumptions, registered verifier identities, and actual geometry/degree.
The v2 target is at least 100 bits proven for the complete maximum-size tree, not merely each proof.
The candidate profile must not be frozen until that analysis and bounded recursion are established.

The historical monolith must replay every query required by its selected inner verifier; checking
fewer is not an equivalent verification. The q96 figures below describe the legacy per-proof
configuration, not a sufficient v2 tree security claim.

Consequences, from `soundness-budget.md`'s accounting (`p3-uni-stark` / soundcalc):
- Proven unique-decoding ≥100 bits needs **`num_queries = 96` at `log_blowup = 4`**; `≤80` queries sit on
  the 96-bit list-decoding plateau. Grinding does **not** lift the *proven* bound (it lifts conjectured).
- The old proposal used **q96 / lb4 at every level**. Matching these parameters is not a proof that
  the complete chain clears 100 bits. Reduced-query configs (the phase-6/7 monolith milestones)
  remain correctness experiments only, not production-strength feasibility evidence.

So the aggregation tree does **not** reduce per-proof cost: each aggregator must replay `K × 96` inner
queries (K inners × 96 each). What the tree buys is **parallelism** (independent aggregators on separate
machines) and **log-depth** composition + **trustless per-user proving** — not a smaller single proof.

## 2. The cost of replaying 96 queries in-circuit

The monolith lays out one **super-tile per replayed inner query** (a transcript region + `n_queries`
super-tiles), then the AIR height is padded to a power of two. Each super-tile for the real join-split
shape (W=19 → 5-block input leaf, degree-8 → nqc=8, db=12 → log_global=16 / cm_rounds=12) is large.
Measured curve (is_zk=0 — the recursion-path inner shape, since we control inner `is_zk`; width 773;
`phase8_joinsplit_query_curve`, this box: 62 GB RAM / 24-core Arrow Lake, AVX2+LTO):

| inner queries replayed | monolith rows | peak RSS | prove+verify |
|---|---|---|---|
| 4 | 2^16 | 7.1 GB | 17.7 s |
| 8 | 2^16 | 7.2 GB | 17.8 s |
| 12 | 2^17 | 14.5 GB | 35.6 s |
| 16 | 2^17 | 14.7 GB | 35.6 s |

**Rows quantize to powers of two**, so RSS/time track `next_pow2(tr + n_queries · m_period)` in
~2× steps, and there is **free headroom** up to each boundary (2^16 holds ~4–8 queries at ~7 GB; 2^17
holds ~12–16 at ~14.5 GB). `tr + n·m_period` implies `m_period ≈ 6.1k` rows and `tr ≈ 16k`. Extrapolating
by the power-of-two boundaries:

| rows | RSS | inner queries held | note |
|---|---|---|---|
| 2^18 | ~29 GB | ~24–40 | |
| 2^19 | ~58 GB | ~48–80 | **this box's ceiling** |
| 2^20 | ~116 GB | **96** (full wire proof) | production server |
| 2^21 | ~232 GB | ~192 (K=2 aggregator) | production server |

So a **single monolith verifying a full 96-query wire join-split ≈ 2^20 rows / ~116 GB / ~5 min** — a
production-prover (128 GB+) capability, just past this 62 GB dev box. The dev box validates the path at
reduced queries (the correctness milestone, done: `phase8_joinsplit_monolith` /
`phase8_joinsplit_hiding_monolith`); the ≥100-bit-proven full-query proof runs on a server.

## 3. Historical architecture proposal — superseded for v2

The numbered proposal below records the q96/legacy-root design, not the active roadmap. In
particular, its per-proof security claim, unchanged-node seam, and multiple-root block rule must not
be carried into v2. The new target is one final proof for an ordered64 commitment, under the bounded
workstation gates in [block-proving-v2.md](block-proving-v2.md).

1. **Every level is q96 / lb4** (proven-100), per §1 — no reduced-query intermediate levels. The
   reduced-query monoliths are correctness milestones only.
2. **Leaf level:** users prove their own single-tx join-split (today's `lattica_joinsplit_prove`,
   96q/lb4, ~2 s, ~0.4 MB) on their own hardware — *not* the aggregator's cost, and the trustless
   per-user-proving win over the batch (`recursion-design.md` §1).
3. **Aggregator level:** one aggregator instance verifies **K inner proofs** (the monolith tiled ×K,
   `fold` mode, shared transcript per inner) and folds each verified `pvs[0]` into the block tx-root
   (`DOM_TXROOT`, `merge`, IV=0, pow2 pad — byte-identical to `batch_joinsplit_air::batch_root`, so the
   node seam is unchanged). Cost ≈ **K · 2^20 rows** → K=2 ≈ 2^21 / ~232 GB / ~10 min on a 256 GB server.
   Keep K small (2–4) and get width from **tree depth**, not wide tiling, to bound per-proof RAM.
4. **Tree:** aggregator outputs compose as inners to the next level (`monolith-verifies-monolith`,
   self-recursion — R5). The open size-stability question: an aggregator proof is a q96 proof of a
   ~2^21-row AIR, so the level above it replays 96 queries of a *bigger* inner (more commit rounds → a
   bigger super-tile) — the per-level super-tile must not grow unboundedly. This is why K is kept small
   and why a fixed-size **wrap** (re-prove each aggregator output at a canonical small shape) is the
   likely stabilizer; R5 measures whether the monolith is size-stable under self-composition or needs a
   wrap circuit.
5. **`MAX_AGG_TILES`** mirrors `MAX_BATCH_TILES = 64` at the ≥100-bit floor; a block beyond one tree emits
   multiple roots (same as the batch's multiple-proof rule).

**Historical resource projection:** this monolith design suggested a ≥128 GB server (256 GB for
K≥2). That is not a v2 hardware recommendation or measured v2 result. Direct witness batches and
in-block individual-proof containers are excluded deployment paths; they do not carry production
while v2 remains incomplete. The v2 commitment/profile require a new versioned node seam.

## 4. Historical verification checklist (not v2 evidence)

- Soundness: `proven_security_bits` gates each level's config at ≥100 (the same test the batch uses);
  the aggregator config reuses `production_fri` (q96/lb4/pow16/cap6). A `recursion_proven_security_floor`
  test (R4) asserts the aggregator level clears 100 bits at its height.
- Cost: `phase8_joinsplit_query_curve` (this doc's table) is the measured basis; re-run on the target
  server to confirm the 2^20 / ~116 GB single-inner point before deployment.
- The reduced-query milestones (`phase8_joinsplit_monolith` at 4q) stay as the always-runnable
  dev-box correctness gate; the full-query proof is a server-only `--ignored` measurement.

## 5. Tree self-composition (R5) — measured: mechanism works, but NOT size- or degree-stable

§3.4 flagged the open question: do aggregator outputs compose as inners to the next level cheaply, or does
the per-level super-tile grow unboundedly? `phase9_self_recursion_probe` (2026-07-03) measures it directly —
it builds + proves a small inner monolith, then has the generic column-window builder construct **and
self-validate** (full-fold pre-check + window/pz/cap binds) the OUTER witness that verifies it, and reads the
outer geometry. Result:

| | width W | constraints | height | log_nqc | est. blowup LDE |
|---|---|---|---|---|---|
| INNER: a ConstAir **monolith** (the smallest monolith) | 193 | 384 | 2^15 | ≤4 | — |
| OUTER: a monolith **verifying that monolith** | **8520** | 8414 | 2^17 | **7** | **~133 GB** |

**Finding 1 — the mechanism works.** The builder succeeded and self-validated over `MonolithAir`-as-inner: the
in-circuit verifier is genuinely AIR-generic, so a monolith CAN witness verifying another monolith. There is no
wiring blocker to self-recursion.

**Finding 2 — it does not converge.** Verifying the *smallest* monolith (W=193, 384 constraints) yields an
outer that is **~44× wider (W=8520)**, has **~22× the constraints**, and needs **~133 GB** just for the
blow-up LDE — and its constraint-fold over the inner's degree-16 constraints reaches **log_nqc = 7 > log_blowup
4**, so the outer is not even provable at blowup 4. Both axes explode per level: the inner monolith's width
(opened-row carrier + 2·W reduced-opening terms) and its high-degree constraints (which the outer's α-fold
inherits) are each far larger than a leaf join-split's (W=19, 81 constraints, degree ≤9). So a level-N monolith
is strictly bigger and higher-degree than level N−1 — **naive tree self-recursion diverges**, exactly the
concern §3.4 raised.

**Consequence for the approved v2 direction:** implement and validate a bounded, fixed-width,
low-degree **uniform recursive verifier**, substantially different from the inner-specific monolith.
The candidate bounded engine now implements that alternative and demonstrates a
two-level recursive proof; [current evidence](bounded-execution-engine.md) records
the measurements and remaining full-depth/security gates. The formerly suggested curve/SNARK wrap is
excluded by the post-quantum hash/FRI requirement. A flat depth-one aggregate or multiple roots in a
block is not an approved production fallback. The R5 measurements establish the limitation of naive
self-composition, not a working v2 tree or a passed feasibility gate.
