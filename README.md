# VecDHT

Peer-to-peer semantic rendezvous for agents: a node publishes an intent (a short text plus an
embedding), another node finds it **by meaning**, with no central catalog and no operator deciding who
is visible. The protocol core is written once in Rust; language bindings call it instead of
re-implementing byte formats.

Two documents are kept apart from the code on purpose:

| document | what it holds |
|---|---|
[`docs/VecDHT-SPEC-v8.md`](docs/VecDHT-SPEC-v8.md) | the contract and the numbers; a reading mirror is checked for equality by `lab/check-spec-mirror.sh` |
[`lab/`](lab/README.md) | memory between sessions: 93 hypotheses, 93 experiment cards (90 with a verdict, 3 open), 27 architecture decision records |

**Rule of the method (enforced, not aspirational):** a number appears in this README only together with
a measurement id (`E-XXXX`), the command that produced it, and a link to the log. `lab/check-text-clean.sh`
enforces it.

## Status: work proceeds by a release gate, not by phases

Since 2026-10-23 the unit of work is the release gate
[`ADR-0044`](lab/decisions/), which has a measurable done / not-done state. The v1 criterion has five
conditions; this is their actual state.

| v1 condition | state |
|---|---|
Four Batch A correctness holes closed, each leaving a regression oracle | **4 of 4 closed**: gossip-path authorization (`E-0087`, `ADR-0043`); per-cluster cap (`E-0088`); finiteness of the shard provider table (`E-0091`, `ADR-0046`); survival of a ban across restarts and its limit (`E-0092`, `ADR-0047`); survival of the revoked-key set across restarts and silence of a revoked node (`E-0094`, `ADR-0050`); observable reason of a door refusal (`E-0095`, `ADR-0051`, 22 names, finite journal, wire unchanged byte-for-byte) |
Bench `P1` (~200 nodes) run for the first time | not run yet — see Boundaries |
Release artefacts reproducible from a clean clone | in progress |

Two sub-thresholds inside `(4B)` remain open (collision visible on the wire, `E-0095` thresholds 4 and
6), and revocation still has no producer: the CLI does not pass a node catalog into
`NetConfig.revoked_dir` (Batch C).

## What is in `main`

| crate | contents | state |
|---|---|---|
`crates/vecdht-wire` | fixed-LE codec with TLV tail, framing, `Kind` table, all messages, `NodeCert` (§5) | ready: golden vectors + fuzzing |
`crates/vecdht-crypto` | int8 quantization, identifiers, publish-PoW, Ed25519, threshold credential verification (§4, §6, §11) | ready |
`crates/vecdht-artifact` | network artifact: canonical `manifest.json` + frozen centroids, `artifact_hash` / `genesis_hash`, threshold signature (§7.1, §15) | ready |
`crates/vecdht-index` | IVF arena, WAL, snapshot barrier, GC without wall-clock (§8, §10) | ready, P3 gates |
`crates/vecdht-node` | shard machine: epoch chain, primary election, lease/epoch fencing, replication W=2 / R=3, departure and seed snapshot, admission §11.3 (including the cell cap, `E-0088`), durable ban with a limit §11.4 (`E-0092`), durable revoked-key set with a limit §4.2 (`E-0094`), `cluster_id` recomputation from centroids (`E-0103`), node metric snapshot (`E-0104`), rendezvous §12.3, adversarial set §19.3, model network for gates (§9, §11–§13) | ready |

## Build and verify

```bash
cargo build --locked
cargo test --locked
./lab/check-spec-mirror.sh     # spec mirror equals the spec in git
./lab/check-text-clean.sh      # no bare numbers without measurement ids
```

### Formal pipelines: three systems on one commit

Three independent checks run on the same commit, because a single tool is a single point of failure:
Rust tests and gates, the Python lab harness, and a **Lean** model of the door and cache invariants
(`E-0078`, `S-0004`). A check that is skipped is reported as a skip, never as a pass.

## Numbers that live in the spec

Main rule of the method (`E-0081`, `E-0082`, `S-0005`): **absolute numbers belong to the host, not to
the code.** The same binary on a loaded machine reported `pow_ok` 3.0–3.7 MHash/s instead of 7, and
Ed25519 verify 1426/s instead of 20400; the finding "attack is ~13× cheaper than defence" turned out to
be an artifact of the debug profile. Therefore what enters the text is **relations and observed
intervals**, while a calibration number is taken from a saturated run on idle hardware, and the smaller
of the two runs goes into the manifest (§15.1).

Measured quantities (full tables and caveats in §19.4, §19.5, §20.2 of the spec; cards in
`lab/experiments/`):

- **recall@10 (gate §18.1 ii)** — 0.9645 on 50 000 and 0.9790 on 807 596 MS MARCO records at
  `nprobe=16` and fan-out 16.0/16 on an even connected shard map; the previous map
  `shard = cluster_id / 16` gave 0.8303 and 0.8892. The price is stated: 16 shards × 16 clusters ≈ 25%
  of the corpus per query, ×16 work per node, practical ceiling ≈100M records
  (`E-0004`…`E-0012`, `ADR-0003`, `ADR-0004`);
- **index (§8.2, §19.1)** — 436.7 B per live record against a budget of 449 B.

## The door, revocation, and cache finiteness: what changed after `E-0085`

The door is the only place where a node admits an unknown peer. After `E-0085` the reasons for a
refusal became **observable and finite** (22 names, `E-0095`), the ban and the revoked-key set survive a
restart with a bounded journal (`E-0092`, `E-0094`), and a revoked node stays silent instead of
retrying. The wire format did not change byte-for-byte, which is why this could land inside v1.

## Boundaries: what v1 does not have

Rule 8 of [`AGENTS.md`](AGENTS.md) is *do not invent mechanisms*; this is the list of things that do not
exist:

- bench `P1` has never been run: ~200 nodes, p95 < 500 ms, < 5k provider records — **not measured**, so
  the fan-out decision (§12.1) has no evidence yet;
- relay/DCUtR from §16.3 is not up: addresses spread through identify/Kademlia, and the NAT path without
  a direct dial is untested; the code contains no promise of an "empty DHT answer" — an empty answer
  does not exist, backoff is a fixed step, and there is no "ready to take an episode" predicate
  (`E-0080`);
- a denylist survives restart (`E-0092`) and the credential **revocation set** does too (`E-0094`,
  `revocation.bin`, limit 4096 with refusal instead of eviction), but **revocation has no producer**:
  `publish_revoke` is called by no product file, and no product service constructor passes `revoked_dir`
  (neither `vecdht-cli` nor `vecdht-embed` brings up `NetService`), so durability today is a property of
  the service and the oracle, not of the built product; revocation broadcast is Batch C
  (`OPEN-QUESTIONS` item 45).

## Laboratory

Early cycles (shard geometry): `E-0001`…`E-0015`, decisions `ADR-0001`…`ADR-0004`. Then transport and
privacy (§9–§13), the Lean model of the door (`E-0078`, `S-0004`), the price of spec lines
(`E-0081`…`E-0084`, `S-0005`), the door and caches (`E-0085`…`E-0091`). The full list is in
`lab/experiments/`; the agent contract is [`AGENTS.md`](AGENTS.md), the protocol is
[`lab/README.md`](lab/README.md).

## Differences from v7.5

Details and measurements are in the spec appendix "what was removed from v7.5 and why":

- **routing**: the SimHash prefix is replaced by a coarse quantizer taken from the artifact; exactly
  64 shards;
- **identity**: `PeerId` remains what libp2p derives; the role is given by a signed `NodeCert`;
- **index**: PQ is removed, an int8 vector is stored, and recall stops being a function of quantization;
- **PoW**: Argon2id is removed; blake3 with the nonce bound to `(owner, shard, epoch, slot, expiry)`;
  difficulty is measured, not a guessed 200 MHash/s constant;
- **determinism**: a fixed point Δ=1/127 instead of a promise of bit-identical float inference (the
  sensitivity was measured: a 1e-5 perturbation of a coordinate changes 0.17 of 384 coordinates, and
  `cluster_id` changes in none of 2000 records under a uniform shift);
- **privacy**: the wording is honestly weakened — an index node reads what it holds.

## Paid orders (planned, not shipped)

[`docs/PAID_ORDERS.md`](docs/PAID_ORDERS.md) describes a future intent type for machine-verifiable paid
work: a customer publishes a task hash, a verifier image digest and a time budget; anyone submits an
artifact; a deterministic verifier emits a signed receipt; escrow releases the price when and only when
the receipt says `pass`. The spec work for this is in
[`docs/TASK-spec-v9-paid-orders.md`](docs/TASK-spec-v9-paid-orders.md). Nothing in this paragraph is
implemented in `main`.

## Licence

MIT OR Apache-2.0.
