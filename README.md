# VecDHT

**What it is.** A peer-to-peer semantic rendezvous layer for software agents: one node publishes an
intent (an embedding plus a short signed text), another node finds it by meaning, with no mandatory
centre. The protocol core is implemented once, in Rust, and the language bindings call it instead of
re-encoding byte formats.

**What it is not.** Not a released product: no release tag, no published binary, no external operator
running this network. The `node` command that starts a shard machine exists and the two-machine
walkthrough is scripted below; it has been dry-run on one host, not yet run on two. Not a claim of
privacy beyond what is measured: an index node reads what it holds.

Other languages of this document: [Russian, `README.ru.md`](README.ru.md). This file is canonical; where
they disagree, this one wins.

## The problem it removes

Agent discovery today is a hosted chokepoint. Every "agent marketplace" is a central directory: it can
delist a participant, reorder results, throttle a competitor or silently misroute a request, and nobody
outside that company can prove what was served. That is acceptable for a storefront and wrong for an open
network, especially when the participants are autonomous programs that transact without a human in the
loop.

VecDHT replaces that single point with a sharded semantic index held by the peers that publish into it.
Nothing in the design requires the original publisher to stay reachable, and no operator can answer a
query that the published records do not support. Records are content-addressed, so a node can show which
records it was served and a third party can check the claim.

## How it works

A publisher signs an `Intent` and pays a small proof-of-work. The record is assigned to one of 64 shards
by a frozen quantizer shipped as a network artifact, so routing is a property of the artifact rather than
of a live network. Peers holding that shard admit the record under an explicit admission policy: quota,
PoW difficulty, a per-cell cap, a durable denylist and a durable set of revoked keys. A searcher sends a
query vector, fans out to the shard providers resolved through Kademlia, and gets candidate slots back;
ranking is the client's job. Text is canonicalized to a fixed byte form before hashing, and coordinates
are quantized to a fixed point Δ=1/127 — two implementations agree on identifiers because the byte form
is the contract.

The readable byte formats and thresholds are [docs/VecDHT-SPEC-v8.md](docs/VecDHT-SPEC-v8.md); the rules
this repository runs by are [AGENTS.md](AGENTS.md); per-crate detail is
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status: one figure, and what it rests on

**≈ 85 % ready for v1** (estimate, 2026-10-27; it rests on the closures of `E-0105`, `E-0108`, `E-0119`
and `E-0130`, and it is an estimate over five release-gate conditions, not a measurement).

The unit of work is a release gate (`ADR-0044`) with a measurable ready/not-ready state. The five v1
conditions, their actual state and every boundary are in [docs/STATUS-v1.md](docs/STATUS-v1.md). In one
paragraph:

* **done** — wire, crypto, artifact, index, node, transport, embeddings and CLI build and pass the
  workspace test suite; the admission door, provider-cache bounds, durable denylist, durable revocation
  set and observable denial reasons were each closed by a measured cycle (`E-0087`…`E-0095`), and the
  recall gate closed on a coherent shard map with its price named (`E-0012`, `ADR-0004`);
* **measured once, on our own host** — the ~200-node stand ran in release: `E-0105`, 192 cold resolves,
  the two official runs giving p95 = 257 and 151 ms against a 500 ms threshold (five runs: 257/151/189/
  185/117 ms). Its pre-registered falsifier fired on the tail: one probe in 192 found no provider within
  3 s, so "192/192 always" is not invariant to host load; the tail is not yet a registered hypothesis;
* **not done, said plainly** — no release tag or binary: the release kit exists and is now checked by an
  instrument (`E-0126`, `lab/check-release-kit.sh`: 17 flags, `CHANGELOG.md` from v7.5, version `1.0.0`
  in all three carriers, a tag-triggered workflow that runs the lab verification and names its own log
  block), but placing the tag and creating the GitHub Release are owner actions, and the CI run on the
  tag is therefore not yet measured; the two-machine end-to-end scenario is scripted
  (`lab/two-hosts.sh`) and dry-run on one host with all three nodes on 127.0.0.1 (match on owner, slot
  and `d2 = 0`), but it has not been run on two hosts yet; the ~200-node
  stand has not been reproduced on a machine we do not control; traffic padding is specified and measured
  as absent (`E-0077`); the revocation set survives a restart and `revoke` produces a signed revocation,
  but no revocation happens automatically; the formal pipeline (Verus, Kani, Lean)
  proves statements about models, and the model-to-code correspondence is not checked by an executable
  instrument;
* **counters are not in this file** — the number of hypotheses, experiment cards, ADRs, synthesis notes,
  sources and logs is generated into [lab/INVENTORY.md](lab/INVENTORY.md) by `python lab/inventory.py`;
  measured quantities and the run that carries them are in [docs/METRICS.md](docs/METRICS.md).

What would change this figure is not a wish list: [ROADMAP.md](ROADMAP.md) states three horizons, each
with exit criteria somebody else can measure, and a list of things we deliberately do not do.

## Repository map

| Path | What lives there |
|---|---|
| `docs/VecDHT-SPEC-v8.md` | the v1 contract: byte formats, budgets, gates (a readable mirror outside git is checked for equality by `lab/check-spec-mirror.sh`) |
| `docs/VecDHT-SPEC-v9.md`, `docs/PAID_ORDER-VECTORS.md` | the paid-orders delta and the vectors generated from it |
| `docs/ARCHITECTURE.md` | crate-by-crate contents and the diff against v7.5 |
| `docs/STATUS-v1.md` | the five v1 conditions, the door/revocation/cache history, the boundary list |
| `docs/METRICS.md` | every measured number, its cycle id and the commands that re-shoot it |
| `docs/FORMAL.md` | the Verus / Kani / Lean contour and what it does not prove |
| `crates/` | the protocol: `vecdht-wire`, `-crypto`, `-artifact`, `-index`, `-node`, `-net`, `-embed`, `-cli`, `-orders` |
| `sdk/vecdht-py` | Python bindings that call the core instead of re-encoding it |
| `benches/` | cost targets that print numbers; a test asserts the threshold |
| `lab/` | the measurement loop: hypotheses, experiment cards, ADRs, append-only logs, gates |
| `lab/INVENTORY.md`, `ROADMAP.md`, `PITCH.en.md` | generated counters, the release plan, the short pitch |

## Quick start

The commands below are the operator surface that exists today (flag names taken from
`crates/vecdht-cli`):

```
cargo build --workspace
cargo test --workspace                                       # on Windows: prefix PATH=…, see the note below
cargo run -p vecdht-cli -- artifact init --out ./artifact --dev-keys 1     # a dev artifact, one dev signing key
cargo run -p vecdht-cli -- agent run    --artifact ./artifact --seed <32-byte hex> --listen /ip4/0.0.0.0/udp/<port>/quic-v1
cargo run -p vecdht-cli -- agent publish --artifact ./artifact --text "<intent>"  --seed <hex> --bootstrap <addr>
cargo run -p vecdht-cli -- agent find    --artifact ./artifact --text "<question>" --seed <hex> --bootstrap <addr>
```

On `x86_64-pc-windows-gnu` a build needs a real C linker: `blake3` compiles native code, and a standalone
mingw-w64 must come first in `PATH` (`PATH="/c/Users/Admin/mingw64/bin:$PATH" cargo test --workspace`);
the conda toolchain is not enough — no `libws2_32.a`, an old linker, and proc-macro DLL test targets that
do not link at all. Linux and macOS need nothing special.

### A two-machine walkthrough (three nodes, one published card)

`lab/two-hosts.sh` is the scripted form of v1 condition 3: three shard nodes hold shard 0, an agent on
machine 1 publishes a card, an agent on machine 2 finds it. The script prints ASCII `HOSTS_*` lines, so
the comparison does not depend on the console code page. Both machines need the repository and a built
CLI: `cargo build --release -p vecdht-cli`.

On machine 1, build the ceremony (a dev artifact, three node certificates, the genesis of shard 0) and
copy the directory whole to machine 2 — the artifact, genesis, certificates and the dev seeds travel
together:

```
bash lab/two-hosts.sh ceremony /tmp/vecdht-two-hosts
# HOSTS_CEREMONY=1 ... MEMBERS=3 PRIMARY_INDEX=0 PRIMARY_OWNER=...
scp -r /tmp/vecdht-two-hosts <machine2>:/tmp/
```

Start the primary and one replica on machine 1, and the third node on machine 2. Each node is told the
primary's address; replace `<M1>` with machine 1's LAN address and let UDP through:

```
# machine 1
bash lab/two-hosts.sh serve /tmp/vecdht-two-hosts 0 /ip4/0.0.0.0/udp/7771/quic-v1
bash lab/two-hosts.sh serve /tmp/vecdht-two-hosts 1 /ip4/0.0.0.0/udp/7772/quic-v1 /ip4/<M1>/udp/7771/quic-v1

# machine 2
bash lab/two-hosts.sh serve /tmp/vecdht-two-hosts 2 /ip4/0.0.0.0/udp/7771/quic-v1 /ip4/<M1>/udp/7771/quic-v1
```

Each node prints `NODE_READY listen=…` when its listener is up and `NODE_STATUS` afterwards. With all
three up, publish on machine 1 and find on machine 2:

```
# machine 1
bash lab/two-hosts.sh publish /tmp/vecdht-two-hosts /ip4/127.0.0.1/udp/7771/quic-v1 "vec dht two host check 52"

# machine 2
bash lab/two-hosts.sh find /tmp/vecdht-two-hosts /ip4/127.0.0.1/udp/7771/quic-v1 "vec dht two host check 52"
```

The text is not chosen for meaning: under the dev artifact it lands in cluster 9, which is shard 0 — the
only shard this network holds; `ceremony` re-checks that with `encode` and refuses to go on otherwise.
`publish` prints `owner`, `epoch`, `seq` and `slot`; `find` prints `HOSTS_FIND_OK=1` with the same owner
and slot, `d2 0 similarity 1.000000`, plus the full CLI answer. The dev artifact derives the centroids and
the authority keys from one seed: this is a mechanics walkthrough, not a public network, and the artifact
says so itself.

The same script runs the whole scenario on one host, which is how the script itself is checked:

```
bash lab/two-hosts.sh selfcheck     # 39 s on our host: HOSTS_OK=1, publish owner/slot = find owner/slot
```

Known wart, visible in the selfcheck logs and not fixed here: `agent find` asks every provider of the
shard, and when one provider does not answer, the call waits for its full timeout (30 s here) before
returning the match it already has. The answer is correct; the wait is recorded in
`lab/logs/e0122-two-hosts-selfcheck.log`.

## How to check a claim

One canonical block; the same block is printed in [docs/METRICS.md](docs/METRICS.md) and
[lab/README.md](lab/README.md). The four cheap guards below were executed on 2026-10-25 and each returned
exit code 0; the fifth is the full cargo tier.

```
bash lab/check-spec-mirror.sh                                # the readable copy of the spec equals the repo copy byte for byte
bash lab/check-text-clean.sh --all                           # alphabet and encoding guard over every tracked text
python lab/inventory.py --date <YYYY-MM-DD> --write lab/INVENTORY.md   # counters are generated, never typed
python lab/xcheck-paid-orders.py docs/PAID_ORDER-VECTORS.md  # an independent hashlib rebuild of the published vectors
bash lab/workspace-verify.sh <run-id>                        # cargo test --workspace + clippy -D warnings + every lab instrument
```

`<run-id>` is not decorative: it is the label of the appended block in `lab/logs/`, and documents cite runs
by that label. Heavy gates (real weights, the 50k corpus, 1M-record memory budget, the adversarial
600-second run) are not in `cargo test` by default and are listed with their exact commands in
[docs/METRICS.md](docs/METRICS.md). If a gate did not run in your environment, that is "not checked here",
not "passed".

## Paid orders (v9)

The next layer is documented, measured as bytes, and not deployed: an agent publishes a task with an
escrow reference and a deadline, another agent submits an artifact set, a node verifies it inside a bounded
budget, and a signed receipt — verdict, axiom list, timings, image digest — decides the payout. The rule
that matters is that the receipt is checkable without a judge: the verdict must be derivable from the
receipt's own fields by anyone holding the order.

Byte rules and the state machine: [docs/VecDHT-SPEC-v9.md](docs/VecDHT-SPEC-v9.md); the vectors a client
must match: [docs/PAID_ORDER-VECTORS.md](docs/PAID_ORDER-VECTORS.md); the design narrative:
[docs/PAID_ORDERS.md](docs/PAID_ORDERS.md). The vectors were re-checked by an independent `hashlib`
recomputation (`E-0111`), the verdict rule itself was corrected by a measured cycle (`E-0112`,
`ADR-0062`), and a client written from the two documents alone — never reading `crates/` — now rebuilds
the same bytes; before it passed, it had caught seven defects, six in the rule text and one in the
checking instrument itself (`E-0113`, `result:` line of the card). Still: no node accepts an order,
`vecdht-orders` is not in the node's dependency graph, and there is no verifier image, escrow contract
or testnet.

## The lab loop

Architecture changes go through a scientific contour, and it is the only way to change protocol semantics:
a hypothesis (`H-XXXX`) → an experiment card with the threshold fixed **before** the run (`E-XXXX`) → a
decision (`ADR-XXXX`), one decision per ADR.

1. A threshold may not be invented after seeing the result; a changed threshold is a new experiment.
2. A negative result stays in `lab/` with verdict `refutes` — records are append-only.
3. The oracle runs on the pre-fix tree too, and its output is committed, so a prediction is checked by a
   number rather than by memory.
4. A fact is usable in a verdict only if it is identical across two runs of an unchanged tree.
5. Before pre-registration a cycle must pass the prior-art circle (pain → sources → Lean rubric →
   oracle); `python lab/cycle-gate.py H-XXXX` refuses it mechanically.
6. The spec is amended only on measured facts, in its own commit, together with its readable mirror.
7. Numbers generated from the tree belong to a generator, not to prose: `lab/INVENTORY.md` carries
   counters, `docs/METRICS.md` carries measurements, README carries ids and pointers.

Full protocol: [lab/README.md](lab/README.md). Agent contract: [AGENTS.md](AGENTS.md).

## Licence and contribution

MIT OR Apache-2.0. Contributions that change protocol semantics follow the loop above; a pull request that
moves a gate or a threshold without an ADR will not be merged. Bug fixes, docs and bindings that call the
core are normal pull requests.
