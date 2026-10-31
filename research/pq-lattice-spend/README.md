# Smaller lattice proof research

This isolated experiment investigates a substantially smaller construction than
the validated 47.6 KB native RingCT encoding. It changes no production acceptance
path, existing proof parameters, v1/v2/v3 codec, or existing research profile.

The candidate backend is the pinned Apache-2.0 Labrador implementation identified
in `UPSTREAM.json`. Its explicit zero-knowledge mode is required. Plain Labrador
proof of knowledge is not a privacy substitute. No full RingCT proof is
implemented here yet.

The first executable only screens public parameter feasibility for binary
witness footprints. Its byte counts are the upstream estimator's output, **not
serialized proof sizes**. It neither constructs a private witness nor proves
ownership, membership, ranges, balance, or serial linkage. A successful screen
does not qualify a construction for adoption or establish security equivalence.

The intended research relation retains two inputs, two outputs, 52-bit values,
one hidden choice among ten ordered account pairs, ternary key/commitment
openings, and the original public AES-derived serial relationships. A complete
adapter will need checked non-native arithmetic lifting, exact binary constraints,
integer balance with carries, independent public-statement reconstruction,
context binding, a bounded proof codec, and adversarial verification.

Two open review issues must remain explicit: the backend's transcript profile
uses 128-bit seeds and differs from MatRiCT's; and its proof-size estimator is
not a wire serialization. The upstream implementation itself is research code
without completed production security review. This work does not claim the new
construction is a security-equivalent or deployable RingCT replacement.

Builds and screens run serially under the coordinator's bounded CPU unit. Build
output is outside the source tree. The Makefile uses only the pinned local C
sources and launches no dependency download or GPU work.

## Screening outcome, 2026-10-30

No substantially smaller replacement has been produced. The validated native
v3 median remains **47,631.5 bytes**. The approximately 24,000-byte target is a
research screening target, not a demonstrated result or a changed acceptance
limit. All candidate adoption flags remain false.

| Construction examined | Result | Evidence type |
| --- | --- | --- |
| Latest Labrador, explicit ZK | 114,867–114,869 bytes | Upstream public parameter estimates; no proof |
| Toolkit-paper Labrador revision, explicit ZK | 114,867–114,869 bytes | Same screen at the authors' pinned revision; no proof |
| Original LaZer default linear path, binary-expanded secrets | At least 73,216 bytes in selected estimator terms | Analytical floor for this encoding and default profile; no generated parameters or proof |
| Original Labrador 64-degree path | Not advanced | No explicit ZK mode found in the inspected original pack API; an unhidden proof of knowledge is insufficient |

Both Labrador screens use 104, 404, 512 and 1,024 binary degree-256
polynomials, with exactly the upstream degree, modulus, challenge and security
settings. Each selects a ZK stage and nine reduction rounds. The latest and
toolkit revisions happen to return the same estimates. The 104-polynomial case
accounts only for the binary expansion of existing keys and openings; these
are sizing probes, not complete transaction constraints or synthetic RingCT
proofs. Larger cases are footprint probes, not certified complete relation
sizes. Neither the estimates nor this screen establishes a general lower bound
for Labrador or rules out other encodings.

`linear_size_floor.py` checks the original source hashes and evaluates only
the witness response and message commitment terms from its default estimator.
The 52 degree-256 ternary polynomials contain 13,312 coefficients. Encoding each
as `b0+b1-1` requires 26,624 binary coefficients. The script enumerates all 105
polynomial partitions between the Ajtai and BDLOP commitments, retaining the
original degree-64 proof ring, `gamma1=14`, `eta=140`, modulus-lifting formula
and sampler rounding. Its minimum is 585,728 bits (73,216 bytes), before the
other positive terms, selectors, values and transaction constraints. This is a
floor of those estimator terms, **not a bound on actual compressed wire bytes**
and not an impossibility result for different constructions. SageMath and the
lattice estimator were not run; no security parameters were generated.

## Reproduction and evidence

`UPSTREAM.json`, `UPSTREAM-toolkit.json`, and `UPSTREAM-linear-size.json`
pin revisions, archive hashes, original file hashes and licenses. The four
original LaZer files are an unchanged, licensed sizing-source excerpt, not an
implementation of that library. The original full archives remain in the
campaign's downloads directory.

Build the selected profile with `make -j2 PROFILE=latest` or
`make -j2 PROFILE=toolkit` inside the campaign's guarded CPU unit. The default
build directories are outside the source tree, at
`../../../build-lattice-latest` and `../../../build-lattice-toolkit`.
Keep a separate build directory for each profile. Then run, in that same unit:

```sh
python3 -B screen.py --profile toolkit \
  --binary ../../../build-lattice-toolkit/parameter_screen \
  --output ../../../new-toolkit-screen
python3 -B linear_size_floor.py
python3 -B -m unittest -v test_screen
```

The runner refuses to overwrite a result directory, pins the executable hash,
checks the source census before and after execution, requires matching embedded
revision/profile and cryptographic parameters, and rejects missing ZK flags,
failed backend status, inconsistent byte counts, and false claims of full
relation or wire measurement. Each child has a 60-second timeout; logs are
streamed to disk and bounded before parsing. The operating-system unit enforces
4 GiB host memory, two CPUs, 128 tasks and zero swap. No GPU work is started.
The revision field identifies the build selected by the recorded command; it
is not a cryptographic attestation of arbitrary externally supplied binaries.

Five audit tests pass, including rejection of misleading reports and a
differential check of every coefficient count from 1 through 26,624 against
the original floating-point sizing formulas. These tests validate the screening
tooling, not any cryptographic construction. The campaign keeps the earlier
failed zero-norm probe and every subsequent build/screen log. The zero-norm
probe was corrected to use the upstream binary witness's positive trivial norm
bound. Existing native proof correctness evidence is inherited unchanged.

The campaign-level `RESEARCH-RESULT.json` and `SOURCE-AUDIT.json` bind the
terminal checks, negative screening results, baseline and source archive.
The source-complete snapshot includes the existing v3 work; no production
transaction acceptance code was edited.

## Requirements for another construction

Further implementation needs a materially better credible size result before a
full transaction adapter is warranted. In particular, a promising construction
must handle the following together:

- Exact ternarity for two spending keys and four coin openings, one hidden
  selection among ten ordered pairs shared by both inputs, and the original
  ownership, coin, output and public AES-derived serial equations.
- Original-modulus arithmetic, or checked non-native integer lifting with
  coefficient bounds. An L2 bound alone is insufficient to prevent modular
  aliasing. Values need 52-bit ranges and exact balance; equality modulo the
  candidate's 38-bit field is insufficient for 53-bit totals.
- Independent reconstruction and binding of the context, profile, setup, ring
  order, recipients, output coins and distinct serials. Public preprocessing
  must be recomputed from the trusted statement. Ledger eligibility and spent
  serial checks remain external, as for the existing relation.
- An actual ZK mode, an independently reviewed security profile, a bounded
  wire codec, fresh full-relation proofs, independent verification and negative
  tests before any smaller-proof claim. A non-ZK proof, omitted opening/range
  constraints, lower challenge security or amortized batch size cannot qualify
  as a smaller stand-alone RingCT proof.

The most relevant next investigation is a construction that proves native short
coefficients directly and compresses the ZK response without the binary
expansion examined here. That requires a supported protocol and parameter
analysis, not changing constants in the existing backend. The source screens
do not establish that such a construction meets the target. Production adoption
would additionally require qualified independent cryptographic review.

## Additional construction and privacy screen

The second search examined Binius64, LatticeFold, two Spartan/WHIR
implementations, and the original WHIR component. None has yet supplied a
qualified smaller RingCT proof. The campaign's `ALTERNATIVE-SCREEN.json` pins
the sources and distinguishes source observations from local measurements.

- **Binius64** has a concrete ZK wrapper, but the inspected shipped verifier
  sets `SECURITY_BITS=96`. Its own size table contains much larger proofs,
  including a 154,240-byte minimum among its listed rates for a single
  non-ZK `2^17` oracle. That table is an upstream example, not a measured
  RingCT size or a lower bound for every Binius circuit. Merely increasing its
  query count would not establish a stronger overall soundness bound; its
  query-count function explicitly excludes the other soundness terms.
- **LatticeFold** exposes a folding scheme and describes LatticeFold+ as work
  in progress. Its README alone does not establish a complete ZK spend proof
  with a bounded wire codec. No folding benchmark is counted as a stand-alone
  RingCT proof or privacy result.
- **ethereum/spartan-whir** exposes explicit full-ZK APIs. Its recommended
  configuration is 116-bit and its README reports a 1,838,906-byte compact
  proof in its selected benchmark. Those are upstream claims for that
  benchmark, not local measurements of this spending relation. This screen
  does not exclude different, independently justified configurations.
- **worldfnd/provekit** configures 128-bit WHIR commitments, but its own source
  explicitly distinguishes hiding witness commitments from full proof ZK:
  matrix-derived witness evaluations are still transmitted in the clear.
  The algebraic counterexample below prevents treating that path as a private
  RingCT replacement merely because its commitment mode says `ZeroKnowledge`.
- **WHIR alone** is a polynomial-commitment/low-degree-testing component. A
  small component proof does not establish a private proof of the full spend
  relation. The other located lattice repositories provide parameter scripts
  rather than a measured, complete adapter for this relation.

`privacy_screen.py` models the exact unmasked matrix-evaluation stage reviewed
in the pinned ProveKit source. Consider eight identical R1CS rows
`s*(s-1)=0` with witness `[1,s]`. Both `s=0` and `s=1` satisfy the same public
statement. Multilinear equality weights always sum to one, so opening the
three matrix covectors against the witness sends `[s,s-1,0]`, regardless of the
sumcheck challenge. The first clear message therefore reveals the private bit.
Blinding earlier sumcheck messages or the polynomial commitment does not mask
this later clear message.

This is an algebraic model tied to reviewed source, **not an execution of the
upstream prover, a claim about a deployed application, or a new RingCT proof**.
The limitation is already documented upstream. Four focused tests pass. They
check both valid witnesses, reject a non-binary witness, compare transposed
matrix evaluation with direct row evaluation at all 4,913 points over F17 and
128 BN254 scalar-field points, and reject dimension mismatches. The source
hashes and license are in `UPSTREAM-privacy-screen.json`. Reproduce with:

```sh
python3 -B -m unittest -v test_privacy_screen
python3 -B privacy_screen.py
```

These findings leave the actual objective open: a substantially smaller proof
of the complete RingCT relation, retaining privacy and an adequately justified
security profile. The scripts are rejection screens, not a replacement prover.

## PKC 2025 balance construction investigation

A subsequent search located [Gao et al., PKC 2025](https://doi.org/10.1007/978-3-031-91832-2_5)
and its public `GoldSaintEagle/RingCT_Implementation` prototype. The paper
reports roughly 20% smaller balance proofs in its MatRiCT+ comparison. This is
a component result under the paper's parameters, not a measured reduction of
our 47,631.5-byte proof. No projected full-proof size is claimed here.

The relevant idea is cycle masking: for bitwise amount differences `c[j]`,
exact balance is `sum(2**j * c[j]) = 0` over the integers. Setting
`d[j] = r[j] - 2*r[j+1]`, with both endpoints zero, makes the mask's weighted
sum zero too. The scalar response `f = x*c+d` can omit its first coordinate,
which the verifier reconstructs over the integers and bounds. This may avoid
separate commitments to balance correctors. It still needs a complete proof
of openings and ranges, proper sampling, and integration with packed messages.

`cycle_mask_screen.py` independently implements these integer identities,
the inverse cycle map, and bounded reconstruction. Six tests pass, including
all 65,536 two-input/two-output four-bit combinations, 1,027 balanced 52-bit
cases, coefficient mutations, invalid values, and two source-informed probes:

- The toy `CheckPackedf` reduces the weighted sum modulo `q`. Inputs `(1,1)`
  and outputs `(q+1,1)` have imbalance `q`, although all values fit 52 bits.
  Their bit-difference vector passes that modeled modular check. The paper's
  bounded integer reconstruction rejects it. This is a component predicate
  counterexample, not a complete forged proof.
- The toy's `CRTPackInt` places bits directly in polynomial coefficients.
  A balanced vector `2-X^4`, multiplied by `X^252`, wraps to `1+2*X^252`
  modulo `X^256+1`; its weighted sum is `1+2^64`. The test includes 43
  additional nonwrapping challenge terms. No transcript preimage is found,
  and native partial-NTT packing is not modeled by this probe.

The public code cannot supply a qualifying measurement: it explicitly calls
itself a toy, leaves rejection sampling unfinished, derives challenges from
eight MD5 digest bytes through `math/rand`, and omits the paper's response
norm checks in the reviewed verifier. Its parameters and message packing also
differ from our reference. These observations concern the pinned implementation;
they do not refute the paper's full protocol. The Go implementation and its
unpinned dependency have not been executed or copied into the research source.

The paper's separate linear-sum ring signature relaxes one-hot selection and
uses commitment-derived serials. It is not a drop-in replacement for our shared
selector and AES-derived serial relation. A balance-only adapter would need to
retain those existing obligations, establish a compatible packed operator and
sampling distribution, justify parameters, and then produce complete measured
proofs. This remains an unresolved research direction, not a qualified backend.

`UPSTREAM-cycle-mask.json` pins the paper and reviewed source files in the
campaign's `downloads/pkc2025` and `upstream/pkc2025-ringct` directories. The
screen checks those hashes before running. Reproduction uses the same bounded
CPU runner as the earlier screens:

```sh
python3 -B -m unittest -v test_cycle_mask_screen
python3 -B cycle_mask_screen.py
```

The campaign's `CYCLE-MASK-RESEARCH.json` records the evidence and open work.
No proof, zero-knowledge claim, serialized-size measurement, native verifier
change, GPU run, or production adoption is part of this algebra experiment.

### Native packing check

`native_cycle_screen.py` tests the immediate adapter using the unchanged native
`ntt_q` and `mult_rq` functions, compiled separately as a CPU library. It checks
their output against direct evaluation at the 64 CRT roots for all 256 basis
vectors, 16 public random vectors and the challenges extracted from all 32
validated native proof artifacts. All 304 comparisons agree; all source and
artifact hashes are checked before use.

The scalar cycle identity does not survive multiplication by the native packed
challenge. In CRT slot `j`, the response contains `x[j]*c[j]`, rather than one
common `x*c[j]`. Consider valid amounts with inputs `(2**(j+1),0)` and outputs
`(2**j,2**j)`: their difference has `2` in slot `j` and `-1` in slot `j+1`.
After multiplication, its weighted sum is
`2**(j+1) * (x[j] - x[j+1])`. It vanishes for every such balance only when the
relevant challenge slots agree. A cycle mask with weighted sum zero does not
remove this discrepancy.

The screen executes all 51 adjacent-bit cases for each of the 32 observed
challenges, comparing each native product with the independently computed
product. All 1,632 products agree, and all 1,632 fail the proposed weighted-sum
identity despite balanced amounts. This rules out this immediate adapter, not
the original native proof or every possible adaptation of the paper.

A challenge supported only in coefficient degrees zero through three has equal
CRT slots, but a ternary challenge of that form has at most four nonzero
coefficients. The existing challenge requires eleven in each of four residue
classes, for 44 total. That restriction cannot retain the existing profile.
Alternatively, an unpacked 52-bit cycle response contains 51 degree-256
polynomials, or 13,056 coefficients, before the other proof obligations. This
is geometry only: no valid parameter selection, compressed-byte estimate or
size saving has been established for that alternative.

Reproduce under the same bounded CPU runner, using a fresh campaign directory:

```sh
python3 -B native_cycle_screen.py --output-directory ../../../native-cycle-new-run
```

`NATIVE-CYCLE-SOURCES.json` pins the native sources and baseline evidence. The
campaign's `native-cycle-screen-1/report.json` contains the comparison results.
A smaller qualifying full proof still requires a compatible construction and
security analysis; neither the scalar screen nor these native comparisons
provide one.
