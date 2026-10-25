# VecDHT

## What this is

VecDHT is a peer-to-peer rendezvous layer for software agents. One agent publishes an intent as an
embedding plus a short signed text; another agent finds it by meaning, without a central index. The
protocol core is Rust, specified in `docs/VecDHT-SPEC-v8.md`, and every record it stores is
content-addressed.

## What problem it removes

Discovery today is a hosted service: an agent registers with a directory, the directory answers
queries, and the directory can censor, price, or go down. VecDHT replaces that single point with a
sharded semantic index held by the peers that publish into it. Nothing in this design requires the
original publisher to stay reachable, and no operator can answer a query that the published records
do not support.

## How it works

A publisher signs an `Intent` and pays a small proof-of-work, the record is assigned to one of 64
shards by a frozen quantizer shipped as a network artifact, and peers holding that shard admit it
under an explicit policy (per-shard limits, a per-cell cap, a durable denylist, a durable key
revocation set). A searcher sends a query vector, fans out to shard providers, and gets candidate
slots back; ranking is the client's job. Text is canonicalized to a fixed byte form before hashing,
so two implementations agree on identifiers. Read `docs/VecDHT-SPEC-v8.md` for the byte formats and
`AGENTS.md` for the rules this repository runs by.

## Repository map

`docs/` — the specification, its paid-orders review, and generated test vectors. `crates/` — the
protocol: `vecdht-wire` (frames), `vecdht-crypto` (identity, PoW), `vecdht-artifact` (network
genesis), `vecdht-index` (IVF arena, WAL, snapshots), `vecdht-node` (shard state machine, admission),
`vecdht-net` (libp2p QUIC/TCP transport, door, gossip), `vecdht-embed` (canonicalization, quantizer,
optional model forward), `vecdht-cli` (operator surface), `vecdht-orders` (paid-order byte rules and
receipt derivation). `lab/` — the measurement loop: hypotheses, experiment cards, ADRs, append-only
logs, gates. `sdk/vecdht-py` — Python bindings that call the core instead of re-encoding it.
`benches/` — cost targets that print numbers and let a test assert the threshold.

## Status

Done: wire, crypto, artifact, index, node, transport, embeddings and CLI build and pass the workspace
test suite (`bash lab/workspace-verify.sh E-XXXX` prints the slice count and appends the log). The
admission door, provider-cache bounds, durable denylist, durable revocation set and observable denial
reasons were each closed by a measured cycle (`E-0087`…`E-0095`). The paid-order byte rules in
`docs/VecDHT-SPEC-v9.md` are reproduced by an executable instrument and re-checked by an independent
`hashlib` recomputation of the published vectors (`E-0111`). The verdict rule itself was then corrected
by a measured cycle (`E-0112`, `ADR-0062`): the axiom allowlist had named `Quoted.sound`, an identifier
that no Lean kernel prints, so an honest quotient-based proof was rejected as `E_AXIOM_NOT_ALLOWED`;
the list now names `Quot.sound`, and the name is confirmed by executing the pinned kernel rather than
by quoting it. Byte rules, hashes and the 30 vectors did not change.

Not done, said plainly: there is no release tag and no published binary. No external operator runs
this network, and no two-machine end-to-end scenario has been executed. The ~200-node stand has been
run once, on our own host, in release: `E-0105` measured p95 152…257 ms against a 500 ms threshold,
and its pre-registered falsifier fired on the tail — one resolve in 192 found no provider within 3 s,
which is open as `H-0106`. It has not been reproduced on a machine we do not control. Traffic padding
is specified but absent. The revocation set survives a restart, but nothing in the product yet produces
a revocation. There is no `node` command that starts a shard. A formal pipeline (Verus, Kani, Lean)
proves statements about models; the correspondence between those models and the code is not verified by
an executable instrument.

What would change that is not a wish list: `ROADMAP.md` states three horizons, each with exit criteria
somebody else can measure, and a list of things we deliberately do not do.

## How to check a claim

```
bash lab/check-spec-mirror.sh      # the readable copy of the spec must equal the repo copy byte for byte
bash lab/check-text-clean.sh --all # alphabet and encoding guard over every tracked text (git ls-files)
cargo test -p vecdht-orders        # prints V9_* literals: hashes, vector count, error-code coverage
python lab/xcheck-paid-orders.py docs/PAID_ORDER-VECTORS.md   # recomputes hashes from the document text
```

Every number in the spec and README carries an experiment id, the command that produced it, and a log
file under `lab/logs/`. A number with no measurement id is a parameter or an estimate, and is labelled
as one.

## Paid orders

The next layer, documented but not deployed, is paid orders: an agent publishes a task with an escrow
reference and a deadline, another agent submits an artifact set, a node verifies it inside a bounded
budget, and a signed receipt — verdict, axiom list, timings, image digest — decides the payout. The
rule that matters is that the receipt is checkable without a judge: the verdict must be derivable from
the receipt's own fields by anyone holding the order. See `docs/PAID_ORDERS.md` for the design,
`docs/VecDHT-SPEC-v9.md` for the byte rules and the state machine, and `docs/PAID_ORDER-VECTORS.md`
for the vectors a client must match. This is planned, not shipped: no verifier image, no escrow
contract, no testnet.

## Licence and contribution

MIT OR Apache-2.0. Changes to protocol semantics go through the lab loop: a hypothesis card
(`H-XXXX`), a pre-registered threshold and experiment card (`E-XXXX`), and an ADR (`ADR-XXXX`) — one
decision per ADR. Spec text changes only on measured facts, in its own commit. Negative results are
kept and published; a cycle that refutes its own hypothesis is a normal outcome, not a failure.
