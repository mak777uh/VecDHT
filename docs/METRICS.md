# Measured numbers, the run that carries them, and the commands that re-shoot them

> Cycle ids this page's numbers come from: `E-0004`…`E-0012`, `E-0077`, `E-0079`…`E-0085`, `E-0088`,
> `E-0090`…`E-0095`, `E-0099`, `E-0102`…`E-0105`, `E-0108`, `E-0111`…`E-0113`, `S-0004`, `S-0005`,
> `ADR-0003`, `ADR-0004`, `ADR-0042`…`ADR-0044`, `ADR-0049`, `ADR-0053`. Inventory counters are not
> printed here: they are generated into [`../lab/INVENTORY.md`](../lab/INVENTORY.md) by
> `python lab/inventory.py`.

This is the only document in the repository that is allowed to carry measured quantities. `README.md`,
`README.ru.md`, `PITCH.en.md` and `ROADMAP.md` link here; they print a number only together with the
cycle id that produced it.

## The method rule

Absolute numbers belong to the host, not to the code (`E-0081`, `E-0082`, `S-0005`). The same binary on
a loaded machine gave `pow_ok` 3.0–3.7 MHash/s instead of 7, ed25519-verify 1 426/s instead of 20 400,
and the "attack is ~13× cheaper than defence" ordering turned out to be an artefact of the debug
profile. So what survives into the spec text are relations and intervals of observation, and the
calibration constant is taken by a saturated cycle on free hardware, with the smaller of two runs going
into the manifest (§15.1).

## Key measured quantities

Full tables and caveats are §19.4, §19.5 and §20.2 of the spec; the cards are in
`../lab/experiments/`.

* **recall@10 (gate §18.1 ii)** — 0.9645 on 50 000 and 0.9790 on 807 596 MS MARCO records at nprobe=16
  and fan-out 16,0/16 on a flat coherent shard map; the previous map `shard = cluster_id / 16` gave
  0.8303 and 0.8892. The price is named: 16 shards × 16 clusters ≈ 25 % of the corpus per query, ×16
  work per node, practical limit ≈100M records (`E-0004`…`E-0012`, `ADR-0003`, `ADR-0004`);
* **index (§8.2, §19.1)** — 436.7 B per live record against a 449 B budget (arena 404.4 MiB + lists
  4.0 + dedup 8.0 + bitmap 0.1), `search` p50 0.066 ms / p95 0.109 ms against a 0.3 ms threshold on
  1104 records; the crash matrix is 10 points plus the property `recover(disk) == replay(all ops)`;
* **live node (§9)** — handoff on primary death = 5 s out of a 10 s threshold, of which 4 s is delivery
  and ~1 s is election; `peer_lost` arrives as a transport event, not as the 90 s lease expiring;
* **adversarial §19.3 / gate P5** — 600 s, 16 threads, 20 bits: 31 891 attempts, 31 680 accepted, 211
  `BUSY`, 0 evictions, legitimate `Find` p50 2.25 ms; the ≤ 64 000 threshold is met with ×2.0 margin,
  and the ceiling is set by the CPU, not by the node budget of 100 admits/s;
* **§19.4 (six price rows)** — classified by `S-0005`: four rows pass as a gate (assign 45.1…49.4
  microseconds against a 150 microsecond threshold; `find end-to-end` p50 56.45…60.29 ms against a
  1 500 ms budget, margin 23.9…66.3×; snapshot; search), two do not: the PoW row (a 2.80 ns window
  against a 19 ns host spread) and the WAL group commit row (group commit does not exist in the product;
  the harness performs it); the §10.4 barrier is ×1.35…1.72 more expensive than streaming;
* **find prices** — 74…81 % of the time is the discovery pump, `search` is ≤ 3.3 %, and one marginal
  shard costs 0.836…0.898 × `poll_interval`: the "~13 RPC" in the spec is 13 poll quanta, not 13 network
  calls (`E-0084`; the decision that moved this into the spec text is `ADR-0042` decision (g) — the
  `E-0084` card names that decision under a reserved number with no file, which is listed in the
  `dangling_ids` counter of `../lab/INVENTORY.md`);
* **PoW** — measured 3.0–7 MHash/s per core instead of the invented 200; difficulty re-shot: 18–24 bits,
  default 20 ≈ 0.15–0.35 s of CPU per publish; the §20.2 operational scale after the release re-shoot is
  602×/533×, not 13.1 (`E-0081`);
* **`poll_interval`** — 25 ms in the product, 5 ms in the stands; every absolute stand timing is
  multiplied by that ratio (§19.5, `ADR-0044` decision 4);
* **the `P1` stand** — 192 cold resolves per run, five runs giving p95 = 257 / 151 / 189 / 185 / 117 ms
  against the 500 ms tolerance, max = 443 / 338 / 387 / 442 / 488 ms; the two **official** pre-registered
  runs are 257 and 151 ms (`E-0105`, `ADR-0060`). Provider bound `64 × 20 = 1 280 < 5 000` records. The
  pre-registered falsifier fired on the wider sweep: 1 miss in 960 probes, in the run where the host was
  squeezed (p50 54 ms against 12–13 ms in clean runs, 1 815 transport refusals against 281–433).

## Run `E-0113` — the identified full verification run

The phrase "the last full run" is not usable in a document: it goes stale every time a cycle closes. So
every reference names a run id, which is the label passed to `lab/workspace-verify.sh` and the block name
in the log. The current identified run:

```
label:   E-0113
block:   ########## E-0113 · workspace-verify · 2026-10-25T12:01:49+03:00 ##########
log:     lab/logs/workspace-verify-2026-10-22.log, block starts at line 90780
```

Its cargo tier, per attempt inside that block (`test result:` lines counted between `TEST_EXIT=` markers):

```
$ awk '/^########## E-0113 ·/{f=1} f&&/^test result:/{c++} f&&/^TEST_EXIT=/{print "slices="c" "$0; c=0}' \
      lab/logs/workspace-verify-2026-10-22.log
slices=3 TEST_EXIT=101
slices=125 TEST_EXIT=0

$ awk '/^########## E-0113 ·/{f=1} f&&/^test result: ok\./{p+=$4; fl+=$6; ig+=$8} \
       f&&/^TEST_EXIT=/{print "passed="p" failed="fl" ignored="ig" "$0; p=0;fl=0;ig=0}' \
      lab/logs/workspace-verify-2026-10-22.log
passed=42 failed=0 ignored=0 TEST_EXIT=101
passed=751 failed=0 ignored=9 TEST_EXIT=0
```

So the green attempt of run `E-0113` is **751 passed / 0 failed / 9 ignored at 125 slices** (115 binaries
+ 10 doc tests), `TEST_EXIT=0`, `CLIPPY_EXIT=0`, and the rest of the block tail:

```
$ tail -n +93350 lab/logs/workspace-verify-2026-10-22.log
TEST_EXIT=0, SECONDS_test=1306, CLIPPY_EXIT=0
LEAN_ALL_OK=1  LEAN_TOTAL=5 DECLS_TOTAL=115 BROKEN=0 SORRY_TOTAL=0 NATIVE_AXIOMS=93 STD_AXIOMS=18
               CUSTOM_AXIOMS=0 AXIOM_FREE=4 DIGEST_BAD=0
LEANGUARD_SELFTEST total=10 passed=10
VERUS_TOTAL verified=8 errors=0 files=1 status=OK   VERUS_SELFTEST total=5 passed=5
KCC_ANCHORS=4 KCC_HARNESS_FNS=4 KCC_STATUS=OK
CYCLEGATE_EXIT=0            (18 planted violations out of 18 refused)
EXPECT_SELFTEST total=8 passed=8    FACTS_SELFTEST total=10 passed=10
LEDGER_SELFTEST total=10 passed=10  REVIEW_SELFTEST total=8 passed=8
REVIEW_EXIT=0  REVIEW_FINDINGS=1  REVIEW_CLOSED_EMPTY=1  REVIEW_REFS_STALE=0  REVIEW_REFS_UNRESOLVED=156
LINT_LATEST_EXIT=0
LIBCHECK records=35 read=35 errors=0 warns=0     LIBCLASSES paper=7 spec=10 impl=18 unknown=0
TEXTGUARD_EXIT=0  (файлов_с_грязью=0, подозрений=3, исключено=1 — advisory channel, does not move the exit code)
DISK_FREE_MB=28073 RAM_FREE_MB=15340 PAGEFILE_PEAK_MB=7660
SECONDS_total=1630  VERIFY_FAIL=0
```

Three honest notes about this block.

* **The block contains a red attempt.** `TEST_EXIT=101` (log line 91701) with 122 `STATUS_DLL_INIT_FAILED`
  lines: the mingw `PATH` linker failure, not a product defect — 3 slices got to run. The block tail is
  `VERIFY_FAIL=0` (line 93514) because the same block re-ran the cargo tier successfully. A reader who
  counts `test result:` lines over the whole block gets 128, which is neither attempt; hence the commands
  above, which split by `TEST_EXIT=`. `lab/workspace-verify.sh` pins `PATH` into itself (line 16:
  `export PATH="/c/Users/Admin/mingw64/bin:$PATH"`), so this failure mode is host-specific and the pin is
  why a foreign host reproduces it differently.
* **`REVIEW_FINDINGS=1`** in this block is `closed-empty-result` on `lab/experiments/E-0113-…` — the card
  was not yet filled when the run was taken; the finding is the instrument working, not a defect of the run.
* **Run `E-0112` is the comparable previous run** (block at line 89091, `########## E-0112 · workspace-verify
  · 2026-10-25T09:57:09+03:00`): 125 slices, 751 / 0 / 9, `TEST_EXIT=0`, `CLIPPY_EXIT=0`,
  `SECONDS_total=1556`, `VERIFY_FAIL=0`. `E-0113` added no Rust test, so the cargo totals are identical;
  the run before that, `DOCS-V9` (block at line 87411), was 124 slices and 750 / 0 / 9 — the one extra
  slice and test in `E-0112` was `tests/v912_axiom_names.rs`, the oracle of cycle `E-0112`. Nine
  `#[ignore]` targets are inherited across all three runs, with each reason in its attribute.

### `workspace-verify.sh` does not print a slice count

Earlier text claimed the script "prints the slice count". It does not: no such token is in its output. The
number is derived from cargo's `test result:` lines, which is exactly what the two `awk` commands above do
and what `bash lab/workspace-verify.sh <run-id> 2>&1 | grep -c '^test result:'` does for a fresh run. The
tokens the script does print per stage are `TEST_EXIT`, `CLIPPY_EXIT`, `LEAN_EXIT`, `VERUS_EXIT`, `KCC_EXIT`,
`CYCLEGATE_EXIT`, `REVIEW_EXIT`, `LIBCHECK_EXIT`, `TEXTGUARD_EXIT`, `SECONDS_*`, and the block verdict
`VERIFY_FAIL`.

## Build and verification commands

Windows builds need a C linker: `blake3` builds native code, and on `x86_64-pc-windows-gnu` the linker also
has to be found. Put a full standalone mingw-w64 next to the tree and put its `bin` in `PATH` ahead of any
other gcc; a miniconda build is not enough (no `libws2_32.a`, linker 2.25 does not take a modern libstd,
test targets with proc-macro DLLs do not link at all):

```
PATH="/c/Users/Admin/mingw64/bin:$PATH" cargo test --workspace
```

### The canonical claim check

One block, identical in `../README.md`, here, and in `../lab/README.md`. Everything in it was executed on
2026-10-25 for this pass; the four cheap guards returned 0, and the fifth is the cargo tier whose numbers
are those of run `E-0113` above.

```
bash lab/check-spec-mirror.sh                                # the readable copy of the spec must equal the repo copy byte for byte
bash lab/check-text-clean.sh --all                           # alphabet and encoding guard over every tracked text (git ls-files)
python lab/inventory.py --date <YYYY-MM-DD> --write lab/INVENTORY.md   # counters are generated, never typed
python lab/xcheck-paid-orders.py docs/PAID_ORDER-VECTORS.md  # hashlib rebuilds statement_hash from the document text
bash lab/workspace-verify.sh <run-id>                        # AGENTS.md's definition of a check: cargo test --workspace +
                                                             # clippy --workspace -D warnings + every lab instrument, append-only
```

Exit codes of the four cheap guards on 2026-10-25: `check-spec-mirror.sh` 0 (both mirrors equal: v8 2229
lines `c8dffd687f19`, v9 550 lines `31461694149e`), `check-text-clean.sh --all` 0
(`файлов_с_грязью=0`, `подозрений=3`, `исключено=1`), `inventory.py` 0, `xcheck-paid-orders.py` 0
(`V9_SPEC_DOC_MISMATCH=0`, `V9_MATRIX_ROWS=10`, all three planted-decoy tokens fired).

The paid-orders tier is defined normatively by §V9.11 of the spec, which names three commands:
`V9_VECTORS_OUT=docs/PAID_ORDER-VECTORS.md cargo test -q -p vecdht-orders -- --nocapture` (prints `V9_*`
and generates the vectors), `python lab/xcheck-paid-orders.py docs/PAID_ORDER-VECTORS.md` and
`bash lab/e0111-run.sh` (the whole cycle). Cycles that edit a rule run their own helper through the same
contour: `bash lab/e0112-run.sh`, `bash lab/e0113-run.sh` (log `lab/logs/e0112-all.log` and the append-only
verification block above).

### Heavy gates are not in `cargo test` by default

They have a time budget and external data (weights, corpus, HF reference) outside git. If a gate did not run
in this environment, that is "not checked here", not "passed":

```
VEC_DHT_P0_FULL=1 cargo test --release -p vecdht-embed --features candle -- --nocapture
RAYON_NUM_THREADS=4 VEC_DHT_MODEL_DIR=<weights> \
  VEC_DHT_P0_CORPUS=<corpus-50k.txt> VEC_DHT_P0_QUERIES=<queries-1k.txt> \
  cargo test --release -p vecdht-embed --features candle gate_ii_real_corpus_recall -- --ignored --nocapture
cargo test -p vecdht-index --test crash_matrix          # matrix §10.5, 10 points + property
cargo test -p vecdht-index --test memory_budget         # 1M records ≤ 428 MB (±5 %)
cargo test --release -p vecdht-index --test search_latency
cargo test -p vecdht-node --test gates_p4 -- --nocapture # model network LocalNet
cargo test -p vecdht-net  --test transport              # 10 scenarios on real libp2p
VECDHT_P5_SECONDS=600 VECDHT_P5_CORES=16 VECDHT_P5_BITS=20 \
  cargo test --release -p vecdht-node --test adversarial p5_gate -- --ignored --nocapture
VEC_DHT_FUZZ_SECS=1800 VEC_DHT_FUZZ_SEED=1 cargo test --release -p vecdht-wire --test fuzz_decode -- --nocapture
VEC_DHT_GOLDEN=1 cargo test --release -p vecdht-artifact --test golden_artifact
```

The three text and mirror guards run before a commit:

```
bash lab/check-spec-mirror.sh          # the readable mirror must be byte-equal to the original (--fix rewrites it)
bash lab/check-text-clean.sh --all     # mixed alphabets and broken encodings, over git ls-files (not over the diff)
python lab/library.py value --cycles 5 # the source contour: the reconciliation window against the literature (ADR-0045)
```
