# VecDHT — peer-to-peer semantic rendezvous for agents (English pitch)

**One line.** A node publishes an intent (a short text plus an embedding); any other node finds it by
meaning, without a central catalog, a registry, or an operator that decides who is visible.

## The problem

Agent discovery today is a chokepoint. Every "agent marketplace" is a central directory: it can delist a
participant, reorder results, throttle a competitor, or silently misroute a request, and nobody outside
that company can prove what was served. That is fine for a storefront and wrong for an open network,
especially when the participants are autonomous programs that transact without a human in the loop.

## What this is

A protocol core written **once in Rust**, with language bindings that call it instead of re-implementing
byte formats. Participants publish an intent (text + embedding); discovery is by semantic similarity;
records are content-addressed, so a node can show which records it was served and a third party can
check the claim.

The project keeps two documents separate from the code, on purpose:

| document | what it holds |
|---|---|
`docs/VecDHT-SPEC-v8.md` | the contract and the numbers; a reading mirror is checked for equality by `lab/check-spec-mirror.sh` |
`lab/` | memory between sessions: hypotheses, experiment cards, architecture decision records (`ADR-*`), append-only logs |

How many of each object `lab/` holds is never typed here: it is generated into
[`lab/INVENTORY.md`](lab/INVENTORY.md) by `python lab/inventory.py`, which exits non-zero if a counter it
prints cannot be computed from the filesystem. A measured number lives only together with the measurement
id (`E-XXXX`) that produced it, the command that ran it, and a link to the log; the full set of measured
quantities and the run that carries them is in [`docs/METRICS.md`](docs/METRICS.md). That rule is enforced
by `lab/check-text-clean.sh`.

## Where it stands (measured, not claimed)

Work proceeds by a **release gate** (`ADR-0044`) with five measurable conditions rather than by phases.
The four correctness holes of Batch A are closed — in six closures, because holes 3 and 4 each split into
A and B once measured — and each closure left a regression oracle:

| hole | fix | oracle |
|---|---|---|
| (1) gossip path authorization | `ADR-0043` | `E-0087` |
| (2) per-cluster cap | — | `E-0088` |
| (3A) finiteness of the shard provider table | `ADR-0046` | `E-0091` |
| (3B) the ban surviving a restart, and its bound | `ADR-0047` | `E-0092` |
| (4A) the revoked-key set surviving a restart, its bound, and the silence of a revoked node | `ADR-0050` | `E-0094` |
| (4B) an observable door refusal reason | `ADR-0051` | `E-0095` |

No Batch A hole is open. Two thresholds inside (4B) are not closed ("a collision is visible on the
wire", `E-0095` thresholds (4) and (6)), and revocation still has no producer: no product file calls
`publish_revoke`, and the CLI passes no node directory into `NetConfig.revoked_dir` (Batch C). The full
table of the five v1 conditions and the boundary list is in
[`docs/STATUS-v1.md`](docs/STATUS-v1.md).

The load condition has one measured answer, on our own host: the ~200-node stand ran in release
(`E-0105`, `ADR-0060`) — 192 cold resolves per run, the two official pre-registered runs giving
**p95 = 257 ms and 151 ms against the 500 ms threshold**; across five runs the same series is
257/151/189/185/117 ms, and the gate held 5 of 5. The card still closes `refutes`, because the frozen
falsifier fired: in the squeezed repeat run one probe of 192 found no provider within the 3 s budget
(1 miss in 960 probes over the five runs), so "192/192 in every run" is not invariant to host load. The
stand is LAN and in one process; there is no second machine, and the tail of that sample is not yet a
registered hypothesis.

Status today: **no release tag**, no published binary, no command that starts a shard node, no
two-machine end-to-end scenario, and no external operator. The honest next step is v1 plus two
independent pilots, not more prototyping.

## Why it matters for an open internet

Removing the central directory means no single party can decide who is discoverable. That property is
worth having precisely where agents negotiate on behalf of people: the discovery layer becomes
auditable instead of trusted.

## What we will not claim

- Not "untraceable" and not "censorship-proof": traffic can still be blocked at the transport.
- Not production-ready: the release gate exists because it is not.
- Not "decentralised" in the marketing sense: it is a P2P protocol with measurable behaviour, and the
  lab publishes negative results — the verdict tally (including open experiments) is generated in
  [`lab/INVENTORY.md`](lab/INVENTORY.md), not typed here.

## Links

- specification: `docs/VecDHT-SPEC-v8.md`, review notes: `docs/VecDHT-v9-REVIEW.md`
- decision records and experiment cards: `lab/`
- release gate: `ADR-0044` in `lab/decisions/`
- related formal work in Lean (accounting-adjacent invariants): https://github.com/mak777uh/audits/blob/main/PROOF_PORTFOLIO.md

## Licence

Apache-2.0 OR MIT (dual), see `LICENSE-APACHE` and `LICENSE-MIT`.
