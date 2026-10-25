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
`lab/` | memory between sessions: 93 hypotheses, 93 experiment cards (90 with a verdict, 3 open), 27 architecture decision records (`ADR-*`) |

A number in this README lives only together with a measurement id (`E-XXXX`), the command that produced
it, and a link to the log. That rule is enforced by `lab/check-text-clean.sh`.

## Where it stands (measured, not claimed)

Work proceeds by a **release gate** (`ADR-0044`) with five measurable conditions rather than by phases.
Four correctness holes of Batch A are closed, each leaving a regression oracle:

| hole | fix | oracle |
|---|---|---|
gossip path authorization | `ADR-0043` | `E-0087` |
per-cluster cap | — | `E-0088` |
finiteness of the shard provider table | `ADR-0040` | `E-0091` |

Status today: **no release tag yet**, no English pitch README before this file, and no external operator.
The honest next step is v1 plus two independent pilots, not more prototyping.

## Why it matters for an open internet

Removing the central directory means no single party can decide who is discoverable. That property is
worth having precisely where agents negotiate on behalf of people: the discovery layer becomes
auditable instead of trusted.

## What we will not claim

- Not "untraceable" and not "censorship-proof": traffic can still be blocked at the transport.
- Not production-ready: the release gate exists because it is not.
- Not "decentralised" in the marketing sense: it is a P2P protocol with measurable behaviour, and the
  lab publishes negative results (3 experiments are open, and verdicts include failures).

## Links

- specification: `docs/VecDHT-SPEC-v8.md`, review notes: `docs/VecDHT-v9-REVIEW.md`
- decision records and experiment cards: `lab/`
- release gate: `ADR-0044` in `lab/decisions/`
- related formal work in Lean (accounting-adjacent invariants): https://github.com/mak777uh/audits/blob/main/PROOF_PORTFOLIO.md

## Licence

Apache-2.0 OR MIT (dual), see `LICENSE-APACHE` and `LICENSE-MIT`.
