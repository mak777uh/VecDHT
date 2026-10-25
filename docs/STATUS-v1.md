# Status of v1: gates, what closed them, and what is not there

> Cycle ids this page rests on: `E-0004`…`E-0012`, `E-0077`, `E-0079`…`E-0095`, `E-0099`, `E-0100`,
> `E-0102`…`E-0105`, `E-0108`, `ADR-0003`, `ADR-0004`, `ADR-0042`…`ADR-0051`, `ADR-0054`, `ADR-0057`,
> `ADR-0058`. Measured quantities and their commands: [`METRICS.md`](METRICS.md). Inventory counters:
> [`../lab/INVENTORY.md`](../lab/INVENTORY.md).

Work is driven by a release queue, not by phases P0–P7. The unit of work since 2026-10-23 is the
release gate (`ADR-0044`), which has a measurable ready/not-ready state. The readiness figure quoted
in `../README.md` is an estimate over these five conditions, not a measurement.

## The five v1 conditions and their actual state

| v1 condition | State |
|---|---|
| The four Batch A holes are closed, each leaving a regression oracle | closed 4 of 4, in six closures, because holes 3 and 4 each split into A and B once measured: (1) gossip-path authorization — `E-0087` (`ADR-0043`); (2) per-cluster cap — `E-0088`; (3A) finiteness of the shard provider table — `E-0091` (`ADR-0046`); (3B) the ban surviving a restart and its bound — `E-0092` (`ADR-0047`); (4A) the revoked-key set surviving a restart, its bound and the silence of a revoked node — `E-0094` (`ADR-0050`); (4B) an observable door refusal reason — `E-0095` (`ADR-0051`, 22 names, finite journal, the wire is byte-for-byte the previous one). No Batch A hole is open. Two thresholds inside (4B) are not closed — "a collision is visible on the wire" (`E-0095` thresholds (4) and (6)) — and revocation still has no producer: the CLI does not pass a node directory into `NetConfig.revoked_dir` (Batch C) |
| The `P1` stand (~200 nodes) has been run for the first time and Appendix C metrics were collected before the run | metrics are ready as a snapshot: `E-0104` (`ADR-0059`) — 37 node names, 7+22 transport names, a closed list, no cost attached; the stand was run in release: `E-0105` (`ADR-0060`) — 192 cold resolves, p95 = 117…257 ms against a 500 ms tolerance across five runs (the two official runs gave 257 and 151 ms), protocol bound `64 × 20 = 1 280 < 5 000` records. No hole in the gate, but the pre-registered falsifier fired: 1 probe of 192 found no provider within 3 s at p50 54 ms, so "192/192 always" is not invariant to host load. The tail of that cold-resolve sample is not yet a registered hypothesis. The stand is LAN and in one process; it has no second machine |
| One user scenario end-to-end on different machines, repeatable by a command from the README | not done: the whole network path was verified in one process over real QUIC; there is no two-machine run |
| §18 of the spec rewritten so that every word carries a measurement id or the mark "not implemented" | partial: §4 (the door, revocation consequences and their survivability, refusal names), §7.4 (provider-table finiteness), §9.3, §11.4 (survivability and the bound of the ban and of revocation), §13 (accountability), §14.4 (cell cap), §19.4/§19.5 and Appendix C already carry measurement ids (`E-0079`…`E-0095`, `ADR-0042`…`ADR-0051`); the "word → id" map for §18.9 is in the queue |
| The privacy layer = "what is actually protected", disk audit as a test | the audit is an executable test: `E-0108` (`s13_disk_privacy`) scans the node directory and the artifact directory for text, tokens, f32/f64 blocks and letter-like runs — 0 findings on a live corpus (owner codes and keys found 8 times and 8 times) and against five planted defects; `centroid.bin` is byte-equal to the reference. What this does NOT prove: absence of unknown byte sequences rather than only known ones; the production volume (1M records) was not scanned. Traffic padding is still promised (§13.3, §20.2 row 7) and measured as absent (`E-0077`); the honest v1 wording is that an index node reads what it holds |

Approximate readiness — about 78 % (an estimate over the five conditions, not a measurement). The four
Batch A holes are closed and each left a regression instrument; recomputing `cluster_id` on the publish
path is closed by `E-0103`; the Appendix C metrics snapshot is finite by construction (`E-0104`); the
protocol core, transport and door are built and measured; the `P1` stand ran in release and gives a
measured p95 (`E-0105`); the disk audit is an executable test (`E-0108`). The increase over the
previous estimate comes from exactly those two closures, not from rewording. Missing: a producer of
revocation and the surface that spreads it (the CLI passes no node directory), a metrics endpoint, a
two-machine scenario, traffic padding, a release tag and a binary; v9 exists as a document and a
separate crate and is not in the node's dependency graph. Covering the absence of a number with the
word "ready" is not allowed, so the figure is labelled as an estimate.

`main` contains only what builds and tests. Gates P2–P5 are closed (including transport and the
adversarial set §19.3), the deterministic half of P0, gate (v) on real weights and both measured P0
gates — (i) forward and (ii) recall on a real corpus; gate (ii) closed on a flat coherent shard map
(`E-0012`, `ADR-0004`), with the price named. Since 2026-10-24 every push to main also runs the formal
pipeline — Verus, Kani, Lean and the product slice in one CI job (`.github/workflows/formal.yml`,
numbers and boundaries — `E-0099`, `ADR-0053`); it proves statements about acceptance-arithmetic
models, not about code, and that is said separately in [`FORMAL.md`](FORMAL.md).

## The door, revocation and cache finiteness: what changed after `E-0085`

This is the youngest and the most measured part of the system. Six cycles in a row shot the same place
— the credcheck on handshake (§4.2, §5.3, §9.2, §9.8) — and each time found a promise without a
mechanism:

* **the ladder of reasons** — 8 credcheck bits give a `2^(8−k)` histogram, and `Revoked` is visible
  outward only in 4 of 256 combinations; the live door emits 11 reasons inside one `CERT_INVALID` code
  with zero names on the wire (`E-0085`; the Lean model is `S-0004`, which also carries the
  `[64,192,320,448]` vectors);
* **gossip must pass the same door as a direct frame** — 18 lines in `on_gossip_event`
  (`vecdht-net/src/service.rs`, the block is marked `ADR-0043`): a `Publish`/`Find` from a relaying
  peer that did not pass the door is dropped; before `E-0087` the author's signature was checked but
  the record went into the index with the door closed. This is not Sybil protection: identity is cheap
  (§11.4);
* **the cell cap became an admission policy** — the bound `max(4096, ⌈2·live/16⌉)` holds 4096 at
  `max_live_per_shard = 2 000 000` and 4286 at live 34 286; a cap-bound frame gives exactly one
  eviction by the cheap `pow_bits` or exactly one refusal, the price is O(reservoir) (`E-0088`, the
  form found by enumerating 256 variants in `E-0079`);
* **the shard provider table is finite** — a record is removed by peer death (`forget_peer`), expires
  on `provider_record_ttl = 420 s` on a tick, and is not accepted back by a DHT answer: the distrust
  window lives the same `ttl` and is cleared by the §9.8 counter-proof — a successful handshake. The
  bound is `max_providers_per_key = 20` per shard; the aggregate bound `20 × 64 = 1280` is statically
  tied to the §18.2 gate "< 5k provider records". Before `E-0091` the table was monotone: re-asking the
  DHT returned a dead provider and it immediately became a dial attempt into a corpse
  (`g5_dial_errors = 1`). The boundary stayed: a kad record lives in the storage of whoever holds it
  and our node does not revoke it (`lab/decisions/OPEN-QUESTIONS.md` item 40);
* **the ban survives a restart and has a bound** — `denylist.bin` in the node directory, exactly
  `18 + 32·N` bytes, written on every change (`.partial` → `sync_all` → `rename` → `fsync_dir`), read
  at open before the first accepted frame; the bound is 4096 with **refusal instead of eviction** and
  counters `denylist_refused_at_bound` / `denylist_save_errors`. A corrupt file means the node refuses
  to open, not an empty list: of 227 corrupted vectors (113 truncations + 114 single-bit edits) not one
  decodes to an empty list (`E-0092`, `ADR-0047`). Before that cycle, one restart returned a full quota
  to an injected attacker for free;
* **revocation survives a restart and has a bound** — `revocation.bin` in the node directory
  (`NetConfig.revoked_dir`, default `None` = the previous behaviour), exactly `18 + 16·N` bytes, the
  same write barrier (`.partial` → `sync_all` → `rename` → `fsync_dir`), bound 4096 with **refusal
  instead of eviction** and counters `refused_at_bound` / `save_errors` / `duplicates`; an unreadable
  file is a refusal to start the service, not an empty set. Its own `nonce` in the file gives
  `self_revoked` from the first second, and the silence of a revoked node was verified by a live
  handshake: before `E-0094` one restart returned a revoked key the right to serve
  (`rv_g3_accepted_after_restart=1`, `rv_g6_serves_after_restart=1`), after it — no (`0` and `0`). The
  boundary is named by a number: a node in another revocation directory does not know (`rv_g4_fresh_dir_knows=0`),
  and a subscription to the control topic has no history.

## Boundaries: what is not in v1

Rule 8 of `../AGENTS.md` is "do not invent mechanisms", so here is what is actually absent.

* the `P1` stand had never been run when this list was first written; it has since been run once, by
  us, in release (`E-0105`, see the table above) — what remains unmeasured is a host we do not control,
  and the fan-out decision (§12.1) still has no second-machine evidence;
* relay/DCUtR from §16.3 are not up: addresses are spread by identify/Kademlia, and a path through NAT
  without a direct dial is unverified; there is no "empty DHT answer" promise in the code at all — an
  empty answer never happens, backoff is a fixed step, and there is no "ready to take an episode"
  predicate (`E-0080`);
* the denylist survives a restart since `E-0092`, the set of **revoked credchecks** since `E-0094`:
  `revocation.bin` in the node directory, bound 4096 with refusal instead of eviction. But revocation
  has no producer: `publish_revoke` is called by no product file, and `revoked_dir` is passed by no
  product service constructor (neither `vecdht-cli` nor `vecdht-embed` starts a `NetService`), so
  today survivability is a property of the service and of the oracle, not of the built product;
  spreading revocation is Batch C (`lab/decisions/OPEN-QUESTIONS.md` items 45 and 46);
* a revocation that failed to be written is not applied: decision 6 of `ADR-0050` rolls the insert back
  on a `rename`/`fsync` error, so a broken or full disk temporarily un-applies an already executed
  revocation and the door lets the revoked key through until `CertRevoke` is re-sent. The case never
  arrived in the measurement (`rv_g8_save_errors=0`), so this is expected behaviour, not measured
  (`lab/decisions/OPEN-QUESTIONS.md` item 46);
* the ban survives a restart, the right to serve an epoch does not: `open_with_admission` raises the
  membership chain and `denylist.bin` but not the `lease`, so a primary node after a restart answers
  `EPOCH_STALE` before the admission gate for any key. Ban survivability is observable through the
  `check_publish` decision, not through code on the wire (`E-0092`, `lab/decisions/OPEN-QUESTIONS.md`
  item 42);
* `apply_revoke` tears only the outgoing direction: a connection started by the revoked side stays
  alive and answers `DENIED:0:0` as "frame before handshake" (release blocker 4);
* the node **recomputes** `cluster_id` from `vec_q` and its own centroids and uses its own value; the
  publisher's hint does not choose the cell (`E-0103`, `ADR-0058`), a recomputation into another shard
  is rejected by the existing `SHARD_MISMATCH`, and divergence plus fail-open without an artifact are
  visible by counters (`cluster_reassigned`/`cluster_cross_shard`/`cluster_unverified`). `pow_input`
  still does not cover `cluster_id` — deliberately: the shard is paid for, the cell is chosen by
  geometry. The shipping binary does not load centroids yet — Batch C (`lab/decisions/OPEN-QUESTIONS.md`
  item 53.2). The tail of the cap "a victim in the cell is invisible to the reservoir" is closed by
  `E-0102`: a window of live cell slots with a 256 budget and a cursor; at `live = 34 286` the answer
  changed from `refuse` to `move`;
* search-poisoning protection is not claimed, but its price is measured: on the 50 000 corpus, ten
  copies of the most hub-like texts give 0/1000 top-1 and 0/1000 top-10 through the probe, exactly
  0/1000 and 9/1000 (`E-0090`, `ADR-0057`); hubness is real (asymmetry 1.975, maximum 64, 42 zeros out
  of 5000) but it does not explain the recall drop 0.8303 — the probe truncation does (`TRUE10_IN_PROBE`
  0.8304); a point copy of a query captures top-1 1000/1000 with one record, and there is no protection
  against it;
* there is no "start a node" command: `agent run` raises a listener but there is no semantic layer for
  incoming traffic — `IntentTextRequest` is not served; `node` (a shard machine with membership
  bootstrap and genesis) is P6;
* the SDK does not do weights — only an explicit surrogate with `allow_surrogate=True`;
* paid intents and order search: §5.5 (class `free`/`paid` with a price, direction `buy`/`sell`), §12.7
  (a selection function in search) and `ADR-0052` are specified by the spec, and since `E-0100`
  (`supports`) the mechanism lives in code: TLV tags in `vecdht-wire`, the `slot_attr` byte next to the
  index arena, the predicate before truncation in `search_filtered`, snapshot format 2 (`ADR-0054`). The
  corpus without announcements stayed byte-for-byte the same, the price is not stored, memory grows by
  +1.0 B/record. Three boundaries remain: the node filters by itself and a client cannot machine-check
  that, the price reaches the searcher only in the publisher's signed text, and `recall` under a filter
  is not measured; there are no CLI flags `--class`/`--dir` (Batch C), and there is no settlement,
  escrow or tender in the protocol (§13.2);
* the §18.3 gate "golden vectors matched on two different machines" is not closed: a second host is
  needed; the cross-platform part of P0 (iv) (AVX-512 / AVX2 / NEON) needs three machines;
* there is no penalty/reputation table, no signal of divergence between owners of one cluster, no
  verifiable re-computation of `l2_sq` by an agent; an index node reads what it holds
  (honest-but-curious), cipher-traffic padding is out of scope;
* the authority key-rotation chain is not defined (§20.2 row 8); "sum of occupancies ≤ capacity" (§9.3)
  is marked as not implementable in v1 (`ADR-0042`) and has no mechanism.
