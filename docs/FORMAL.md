# Formal pipelines: three provers on one commit

> Cycle ids this page's numbers come from: `E-0078`, `E-0085`, `E-0093`, `E-0099`, `S-0004`,
> `ADR-0048`, `ADR-0049`, `ADR-0053`. Counters of models and cards are generated into
> [`../lab/INVENTORY.md`](../lab/INVENTORY.md).

On every push to `main` the repository runs `.github/workflows/formal.yml` — four jobs with pinned
versions (`VERUS_VERSION 0.2026.10.18.7d82994`, `KANI_VERSION 0.68.0`,
`LEAN_TOOLCHAIN leanprover/lean4:v4.36.0-rc1`): Verus over the acceptance-arithmetic model
(`lab/proofs/verus/cap_math.rs`), Kani over four harnesses in `crates/vecdht-node/src/admission.rs`, the
Lean guard over five models (`lab/lean/VecDHT/*.lean`) and the product slice (tests + clippy + compiling
the harnesses under a Kani stub). Locally the same contour is three instruments:

```
bash lab/verus-check.sh                # Verus: the model + 5 self-checks with planted defects
bash lab/kani-compile-check.sh         # Kani: the harnesses compile (Kani itself is not installable on Windows)
bash lab/lean-check.sh                 # Lean: proof state, axioms, frozen formulations
VEC_DHT_CI_POLL=1 bash lab/e0099-run.sh # the same contour + the CI numbers into the journal
```

Two honest caveats.

* Every statement is proved **for models**; the correspondence between the models and the code is not
  checked by an executable instrument (the `CONST_MATCH=OK` comparison matches three constants and one
  formula string by text) — this is question 5 of the rubric (`../lab/lean-rubric.md`).
* The CI job log is not readable anonymously (the API answers 403 "Must have admin rights"), so every job
  must print its own numbers as `::notice::` lines, and it is those lines that step 8 of the instrument
  puts into `lab/logs/`.

Numbers of the last measurement and the boundaries of the contour — `E-0099` (`ADR-0053`):
`verified=8 errors=0`, `4 successfully verified harnesses, 0 failures`,
`LEAN_ALL_OK=1 DECLS_TOTAL=115 BROKEN=0`. In run `E-0113` the same block prints
`LEAN_TOTAL=5 DECLS_TOTAL=115 BROKEN=0 SORRY_TOTAL=0 NATIVE_AXIOMS=93 STD_AXIOMS=18 CUSTOM_AXIOMS=0
AXIOM_FREE=4 DIGEST_BAD=0`, `VERUS_TOTAL verified=8 errors=0 files=1 status=OK`,
`VERUS_SELFTEST total=5 passed=5`, `KCC_ANCHORS=4 KCC_HARNESS_FNS=4 KCC_STATUS=OK` — see
[`METRICS.md`](METRICS.md) for the commands that read them out.

## How Lean is used, and how the guard itself is guarded

Lean is applied pointwise and by rubric (`../lab/lean-rubric.md`): review of the semantics of a decision,
mathematical reconnaissance of a hypothesis before the oracle, and exhaustive enumeration of a finite
discrete candidate space (`native_decide`). Time, bytes, packets, real cryptography and the network are
the oracle's business only. The inventory of the models was measured 2026-10-24: 5 models, 115
`theorem`/`lemma` declarations, 0 `sorry`, 0 custom axioms, a warm compile of 15.4 s
(`bash lab/lean-check.sh`, which also stands in the cycle closure so the models do not rot). Those five
are exactly what the guard compiles — `lab/lean-check.sh` walks `lab/lean/VecDHT/*.lean`; a sixth model,
`lab/lean/KernelName.lean`, came with `E-0112` and sits outside that glob, which the generated inventory
prints as `lean_models_outside_guard` (see [`../lab/INVENTORY.md`](../lab/INVENTORY.md)).

The honest caveat: 93 of the 115 are proved by `native_decide`, and `native_decide` is trusted as an
**axiom** — the Lean kernel does not re-check the result. Only `#print axioms` over the proof terms sees
this, not `grep` over the source. Since 2026-10-24 that is a printed number rather than a manual caveat:
`bash lab/lean-check.sh` outputs `LEAN_ENV=`, `DECLS_TOTAL=`, `NATIVE_AXIOMS=`, `STD_AXIOMS=`,
`CUSTOM_AXIOMS=`, `AXIOM_FREE=`, `DIGEST_BAD=`, and `python lab/lean-check.py selftest` checks the guard
itself against twelve planted violations and two controls (`E-0093`, `ADR-0049`). The previous
grep-shaped guard gave a green light with exit 0 on two of those plantings (an axiom in a model, and a
formulation weakened after freezing) — snapshot `lab/logs/e0093-oracle-before-fix.txt`. Where
`native_decide` is replaceable by the kernel `decide` is measured separately: in `Denylist.lean` it is
replaceable entirely (4 s), in `CertLadder.lean` on the 256-vector theorems `decide` does not pass on
recursion depth, and that is not done (`lab/decisions/OPEN-QUESTIONS.md` item 44).

The environment class is named before any model is judged (`E-0150`): the guard compiles a one-line
probe (`import Std` + `#check List`) and prints `LEAN_ENV=ok|partial` together with
`LEAN_ENV_PROBE_EXIT=` and `LEAN_ENV_PROBE_MS=`. On `partial` it names the reason, prints
`LEAN_ENV_REFUSED=1` and `LEAN_ALL_OK=0`, exits with code 3 and prints no `BROKEN=` line at all — a
broken toolchain must not be reported as six broken models. A missing compiler is a third class,
`LEAN_ENV=absent` with code 2. The probe is a necessary condition, not a diagnosis: a failure deeper
than the toolchain still surfaces as a model failure. Measured price: one `lean` run, 1.9–2.0 s per
check. The pinned guard (`4aa7f50`) in the same partial environment printed `BROKEN=6` and no `LEAN_ENV`
line, the new guard prints `LEAN_ENV=partial` with code 3 and zero `BROKEN` lines, and a healthy
toolchain with a deliberately broken model still gives `BROKEN=1` with reason `COMPILE:`
(`lab/logs/e0150-all.log`).

The Verus contour additionally pins the constant bridge: `CONST_MATCH=OK` prints `CONST_OK` for
`CELL_CAP_NUM`, `CLUSTERS_PER_SHARD`, `CELL_CAP_MIN` and the body of the formula, and its self-check
refuses an inverted expectation (`VERUS_SELFTEST total=5 passed=5`). The Kani contour is a compile check
only, because Kani does not install on Windows: the four `#[cfg(kani)]` harnesses are invisible to an
ordinary build, so `lab/kani-compile-check.sh` proves at least that they compile, and the statements
themselves are checked by Kani in CI.
