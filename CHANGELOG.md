# Changelog

History in this file starts at **v7.5** — the specification document that v8 replaced. The difference
between v7.5 and what is shipped here is at the level of mechanisms, not wording: five of its mechanisms
are physically unrealisable and three places in its own reference code corrupt data, which is argued
line by line in `docs/VecDHT-SPEC-v8.md` §0 and Appendix A. Everything below names the cycle (`E-xxxx`)
or the decision (`ADR-xxxx`) that makes the line true; a line without an id is a promise, and this file
is not for promises.

Dates are the dates the cycle closed, read from its card — not the date a tag is eventually placed.
Versions are newest first.

## [1.0.0] — 2026-10-26

The first release-able tree. The release kit itself — this file, `.github/workflows/release.yml`, a
version number in every carrier — is what cycle `E-0126` measures, and it was deliberately left to the
end of the `ADR-0044` queue rather than taken first: a tag on a tree with open holes would advertise a
network that does not survive its own restart (`ADR-0050`).

### From v7.5 to v1: mechanisms that were replaced

| What v7.5 said | Why it failed | What v1 does | Where |
|---|---|---|---|
| `shard_id = SimHash(embedding)[0:8]` | near neighbours agree in ~95 % of SimHash bits, so the probability of agreeing on all 64 leading bits is negligible; almost every semantically near intent lands in another shard and `find` never sees it | routing is the coarse quantizer of a balanced k-means map, shipped inside the signed artifact, and there are exactly 64 shards; a node recomputes the cell instead of trusting the publisher's claim | spec §0 and §7, `ADR-0058` |
| `peer_id = blake3(pubkey)[..20]` | libp2p derives `PeerId` from a protobuf multihash and QUIC/TLS/Noise derive it from the certificate; the scheme is not reachable without forking libp2p | `PeerId` stays whatever libp2p derives; the node's *role* comes from a signed `NodeCert` | spec §0 and §5 |
| Argon2id PoW, `m = 19 MiB, t = 2`, difficulty sized by an invented 200 MH/s constant | measured cost per attempt is tens of milliseconds, so the announced bit target was days of work for one record; the constant itself belonged to a different input size | blake3 with the nonce bound to `(owner, shard, epoch, slot, expiry)`, difficulty re-shot by measurement instead of by assumption | `E-0081` |
| "one text, one byte-identical fingerprint on every node" | CPU inference is not reproducible across instruction sets and thread counts | fixed-point quantization with Δ = 1/127; sensitivity measured rather than promised | spec §0 and §6, `docs/ARCHITECTURE.md` "What is different from v7.5" |
| `candle 0.8.0` with a ModernBERT checkpoint | the `modernbert` module does not exist in that crate version, so the model cannot be loaded as declared | the backbone is vendored behind the `candle` feature | spec §0, Appendix A |
| recall@10 > 95 % storing PQ codes only | measured PQ ceilings are far below the target and do not move with `nprobe` | int8 vectors are stored and the exact rerank runs against them; recall stops being a function of quantization | spec §0 and §7, Appendix A |
| `gc()` on the local clock with id renumbering; snapshot triggered by a delta counter; memory mutated before `fsync` | replicas applied the same sequence number on different clocks and diverged; the live counter plateaued so the snapshot never fired; a crash left phantom records | write-ahead ordering and snapshot rules are stated as bytes and their price was measured | spec §10, `E-0082`, `E-0083`, `E-0084` |
| `similarity = 1 - dist / max_dist`, with `max_dist` left undefined while the sort order is signed | two implementations produce different signatures over the same records | the byte layout, the terminators and the printed inputs of every hash are given so an independent implementer can rebuild them from the text alone | `ADR-0063`, `E-0113` |
| two different nonce derivations in the same document, a declared 1568-byte record against the 1600 bytes it actually describes, an Ed25519 key reused as X25519 | mutually incompatible implementations, and a key-transport confusion | one little-endian codec, implemented once in Rust; a signature is required at the door but is explicitly *not sufficient*, and every refusal it issues has a name | spec §0, `E-0087`, `ADR-0051` |
| a signature on every frame plus a second canonical protobuf encoder in Python | protobuf is not byte-deterministic, so the second encoder only added an interop risk and a per-frame cost | the Python SDK never encodes or signs by itself; it calls the Rust codec through PyO3 | spec §0, §5.1, §12 |
| rendezvous tokens, eight band keys, an emergency mode, limits enforced by an optional relay | the token had nowhere to live, the eight keys returned the same providers, and an optional relay cannot enforce anything | removed outright | Appendix A |

### The release queue, decision by decision

`ADR-0044` set the queue and the six owner decisions around it; `ADR-0045`…`ADR-0066` are the steps it
actually took. Each line is the decision, not the wish.

* `ADR-0044-release-queue-and-six-owner-decisions` — work is driven by release gates with a measurable
  ready/not-ready state, not by phases P0…P7; five v1 conditions and six owner decisions are named there.
* `ADR-0045-prior-art-contour` — every code cycle has to name the external sources it read, and the
  contour is scored by whether a source changed the design (`E-0089`).
* `ADR-0046-provider-cache-is-finite` — the per-shard provider table has a TTL, a bound and a distrust
  window; a dead peer does not come back through a re-ask (`E-0091`).
* `ADR-0047-denylist-durable-with-bound` — the ban list survives a restart and its bound refuses
  instead of evicting, because eviction is amnesty (`E-0092`).
* `ADR-0048-loop-as-a-gate` — the circle "pain → sources → Lean rubric → oracle" became a mechanical
  gate that fails a cycle, not advice in a document.
* `ADR-0049-lean-model-guards` — the model guard reads proof terms, not text: an axiom or a weakened
  statement inserted after the freeze is now caught (`E-0093`).
* `ADR-0050-revocation-durable-after-restart` — the revoked set survives a restart, has a bound, and a
  revoked node goes silent (`E-0094`).
* `ADR-0051-door-refusal-reason-taxonomy` — every door refusal has a name from a closed taxonomy and a
  local counter; "the record was not stored" is no longer one undifferentiated code (`E-0095`).
* `ADR-0052-intent-class-and-direction` — an announcement carries a paid/free class and a
  buy/sell direction; a paid class has to state its price.
* `ADR-0053-three-provers-on-one-commit` — Verus, Kani and Lean run over the same commit, and the
  boundary of what they cover is written down rather than implied (`E-0099`).
* `ADR-0054-intent-attrs-in-code` — the class and direction of `ADR-0052` became bytes in the code
  (`E-0100`).
* `ADR-0055-own-cert-expiry-policy` — an expired own credential stops the node: fail-stop, its own
  refusal name, its own counter (`E-0098`).
* `ADR-0056-cell-cap-scan-victim` — the victim of the per-cluster cap is searched inside the cell's own
  window, with a scan budget and a cursor (`E-0102`).
* `ADR-0057-hubness-and-blind-poisoning-verdict` — protection against poisoning is decided by a
  measured number rather than by fear; the queue moved on to recomputing `cluster_id` (`E-0090`).
* `ADR-0058-node-recomputes-cluster-id` — a cell is chosen by the geometry of the vector, not by the
  publisher's claim (`E-0103`).
* `ADR-0059-metrics-surface` — the observation surface of Appendix C is a snapshot with a closed list of
  names, and no name is invented at scrape time (`E-0104`).
* `ADR-0060-kad-server-role` — the kad-server role, the QUIC timings and the profile of the ~200-node
  stand; the stand is only valid in release (`E-0105`).
* `ADR-0061-paid-orders` — the byte rules for v9 paid orders: domains, canonical order record, the
  receipt as canonical JSON without floats, a closed list of codes (`E-0111`).
* `ADR-0062-axiom-allowlist-kernel-name` — an allowlist has to name an axiom by the identifier the Lean
  kernel itself prints (`E-0112`).
* `ADR-0063-spec-describes-bytes` — the spec describes bytes: terminators, literal lengths and the
  printed inputs of every hash, so that a third-party implementer can rebuild them from the text
  (`E-0113`).
* `ADR-0064-chain-binding-is-data` — chain binding is data: `term_hash`, a registry of descriptors and a
  signature of the requirement, so the payout path can be assembled outside Rust (`E-0114`).
* `ADR-0065-lease-grant-is-durable` — a signed lease grant lives next to the WAL, so restarting a
  primary no longer forces a shard epoch change (`E-0124`).
* `ADR-0066-cold-resolve-miss-budget` — a rare cold-resolve miss is named by a number (a budget of one
  miss per 960 probes) and the stand contract became p95 plus that budget (`E-0125`).
* `ADR-0067-release-kit-is-checked-not-promised` — this file and the release workflow exist because a
  cycle measures them, not because a plan listed them (`E-0126`).

### Build recipe and how to check the tree

```sh
cargo build --release -p vecdht-cli     # the binary; the same line the release workflow builds
bash lab/workspace-verify.sh <run-id>   # the workspace check whose exit 0 defines "verified"
```

On `x86_64-pc-windows-gnu` a standalone mingw-w64 has to precede any other `gcc` in `PATH` before the
first command; see the "Build" section of [`README.md`](README.md) (the same in
[`README.ru.md`](README.ru.md)). The release workflow runs on `ubuntu-24.04`, so the artifact it
publishes is an `x86_64-unknown-linux-gnu` binary: it proves "this tagged tree builds and its checks
pass on GNU/Linux", not "this is a binary for your machine". The same platform asymmetry is recorded for
Kani's published assets in `L-0018`.

The toolchain is deliberately not pinned in this repository: there is no `rust-toolchain.toml`, on the
host or in CI, because a version nobody in the loop can re-check on their own host is a promise without
an owner. `cargo fmt --check` is likewise absent from CI for a measured reason — `rustfmt` is not
installed on the loop's host, so adding the step would produce a green mark no one can reproduce
locally. Both are recorded in the header of `.github/workflows/verify.yml`.

### What v1 does not have

Stated as absences, because "ready" without a list of what is missing is how v7.5 read.

* There is **no release tag and no published binary**. Placing the tag and creating the GitHub Release
  are owner actions; `E-0126` measures readiness to tag and prints `CK_TAG_EXISTS` as a reading, never
  as a goal. Nothing in this repository was published to the network by the cycles that wrote it.
* **The tag's CI run is not proven by this cycle.** The workflow is written and it parses, and the
  instrument checks that it runs `lab/workspace-verify.sh` with the tag name as the run id
  (`CK_WORKFLOW_RUNID`), but the loop's host has no `gh` and may not place a tag, so "the tag's CI is
  green" is first verified by the run the owner triggers.
* **Two operators on two machines have not run one scenario.** The walkthrough is a command in the
  README, prepared and dry-run on one host with all three nodes on loopback (`E-0122`), and the ~200-node
  stand has been run five times, all on a host we control. Item A5 of `docs/PLAN-v1.md` is the run itself
  and it needs a second machine.
* **The uptime counter exists; the 30 days do not.** Since `E-0130` (`ADR-0071`) a node keeps
  `uptime.bin` — 46 bytes in its state directory — folds the previous session into
  `accumulated_sec` when it restarts with the same `--dir`, and refuses to print seconds when the
  history is missing or corrupt: `vecdht-cli node uptime` exits 2 and names the file instead of
  answering `total_sec=0`. What is still missing is the accumulation itself, which needs the
  long two-operator run (A5), not more code.
* **Traffic padding is specified and measured as absent** (`E-0077`): fan-out costs what it costs, and
  an index node reads what it holds. The privacy wording in the spec is the weakened honest one.
* **Revocation has a producer but no motive.** `vecdht-cli revoke` (`E-0120`) signs and spreads a
  revocation once an authority decides to; nothing in the node decides to revoke by itself. `vecdht-cli node run` passes a state directory, so for that node the
  revoked set and the ban list survive a restart (`E-0094`, `E-0092`), while the library default
  `NetConfig.revoked_dir = None` still means "memory only" — which is what every pre-existing test uses.
  At the bound of 4 096 entries a new revocation is refused rather than evicting an old one, because
  eviction of a revocation is amnesty; the operator's only way out is a manual removal, which is the same
  amnesty. That dead end is recorded in `lab/decisions/OPEN-QUESTIONS.md`, not solved here.
* **No metrics endpoint.** The observation surface of Appendix C is a snapshot with a closed list of
  names (`E-0104`); scraping it from outside the process is not implemented.
* **v9 paid orders exist as a document and a separate crate**; they are not in the node's dependency
  graph, the node accepts no orders, and the escrow has an empty `DEFAULT_TRUSTED_CHAINS`. The testnet
  pilot is horizon H2, after v1.
* **Formal proofs are proofs about models.** Verus, Kani and Lean statements have been checked
  (`E-0093`, `E-0099`); the correspondence between those models and the Rust code is not established by
  an executable instrument, and nothing in the repository should be read as saying the code is proved.
