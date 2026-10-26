# ROADMAP

Three horizons. Each has exit criteria that somebody else can measure without asking us a question,
and the dependencies that must resolve first. No dates: nothing here is pinned to an external deadline
(a funder's date, a chain upgrade), and a date without a dependency is a wish.

The unit of work is the release gate described in `lab/decisions/ADR-0044`: a gate has a measurable
ready/not-ready state, and the readiness figure in `README.md` is an estimate over those gates, not a
measurement. Measured quantities themselves are not typed in this file: they live in
[`docs/METRICS.md`](docs/METRICS.md) together with the run id that carries them, and inventory counters
are generated into [`lab/INVENTORY.md`](lab/INVENTORY.md). This roadmap does not change that estimate; it
states what would make each horizon exit-able.

## H1 — a v1 that two independent operators run

Make the existing protocol into a release: a tagged binary, a documented operator path, and one
scenario executed by someone who did not write it.

| Exit criterion | How it is measured |
|---|---|
| A release tag exists with a build recipe and a changelog from v7.5 | `git tag` is non-empty; the tag's CI run of `bash lab/workspace-verify.sh <run-id>` exits 0, and the tag names the `<run-id>` block it produced |
| Two operators on different machines complete one publish→find scenario | the scenario is a command in `README.md`; both operators paste the same log shape, and their `order_ref`/record hashes agree with the golden vectors |
| Conformance vectors pass on both machines | `cargo test -p vecdht-wire` golden set plus `python lab/xcheck-paid-orders.py docs/PAID_ORDER-VECTORS.md` exit 0 on each host |
| ≥30 days of uptime across the two operators | each node writes a startup-anchored counter; the report is the counter, not a human claim |
| Zero open P1 bugs | the issue tracker's P1 filter is empty at the tag commit |
| Batch A holes stay closed with a regression instrument each | closed 4 of 4 in six closures — holes 3 and 4 each split into A and B once measured: `E-0087`, `E-0088`, `E-0091`/`E-0092`, `E-0094`/`E-0095` (`docs/STATUS-v1.md`); each closure names the test that would fail if the fix regressed |
| The ~200-node stand has been run on a host we do not control | already run once, by us, in release: `E-0105` — 192 cold resolves per run, the two official runs giving p95 = 257 and 151 ms against the 500 ms threshold (five runs: 257/151/189/185/117 ms). What is missing is a second host. The tail that `E-0105` refuted — one probe of 192 found no provider in 3 s in the squeezed repeat — is now a registered and closed cycle (`H-0125`/`E-0125`, `ADR-0066`): every miss names itself (observer, shard, probe duration, node transport errors) and the gate is p95 plus a miss budget of ≤ 1 per 960 probes, measured over 1 920 probes with one named miss and p95 131…232 ms in 10/10 runs |
| The revocation has a producer | a CLI path writes to a node directory and the running node refuses that key without restart (items 45 and 46 of `lab/decisions/OPEN-QUESTIONS.md`) |

Depends on: the spec freeze for v8 semantics, Python bindings that do not re-encode bytes, a second
host. The two-machine gate (§18.3) and the inter-platform part of P0 (iv) are blocked on hardware we do
not have, not on code.

## H2 — paid orders live in testnet

Run the v9 byte rules against real work and real money that we can lose.

| Exit criterion | How it is measured |
|---|---|
| 10 orders published on a testnet | 10 `order_ref` values visible on-chain or in the gossip journal, each with a submission |
| 5 of them settled by receipt | 5 receipts pass `validate_receipt` on a host that never saw the verifier's memory, and each state reaches `settled` |
| Escrow releases without a human | release is triggered by the receipt alone; the journal line pairs `submission_ref` with the chain event |
| One dispute resolved by the receipt | a case where submitter and verifier disagreed, closed by re-deriving the verdict from receipt fields (§V9.5), no adjudicator |
| Verifier image published, its digest pinned | `verifier.image_digest` in every order resolves by `skopeo inspect`/`docker pull` to that digest |
| Every error code has been observed at least once in the wild, or is listed as unobserved | the instrument table in `docs/PAID_ORDER-VECTORS.md` compared against the node journal |

Depends on: H1; a published verifier image; an escrow contract on a chain we name; `OPEN-V9-1`…`OPEN-V9-8` and (closed 2026-10-25: `OPEN-V9-9` — the spec's state matrix copy is now compared cell-by-cell with the generated document by `lab/xcheck-paid-orders.py`; `OPEN-V9-10` — the axiom allowlist named `Quoted.sound`, an identifier no Lean kernel prints, fixed by cycle `E-0112` under `ADR-0062`)
from §V9.10 resolved or explicitly accepted. The first three of those are outside our repository: an
image we build and sign, a contract we audit, a chain we track.

## H3 — third-party verifiers

Make the receipt an interface other people implement without our code.

| Exit criterion | How it is measured |
|---|---|
| Two independent implementations produce byte-identical receipts on the same 20 vectors | each implementation's `V9_RECEIPT_JSON_SHA` equals the published vector; a judge reads only the two logs |
| Neither implementation links our crate | build manifests of both contain no `vecdht-orders` dependency |
| A hostile reader test passes | a reviewer who has not contributed gets from `README.md` + spec + vectors to a working client without asking us anything (§8 of the task document) |
| The canonical JSON rule survives mutation | planted-decoy run: changing key order, integer form, or escaping changes the sha |

Depends on: H2, and the receipt format being frozen — an implementation count of one is not evidence
that a format is reproducible.

## Not doing

Deliberately refused, not merely unimplemented. Subjective tasks: an order whose acceptance criterion
is "good", "well-written" or "useful" cannot be verified, so it is not an order. Human judging inside
the protocol: no path where a person's opinion changes a payout; a dispute that needs a human is a
dispute that escalates out of the protocol and stops it. Custody of funds: we hold nothing; escrow is a
contract on a chain the node tracks, and an unknown chain fails closed (§V9.7). Reputational
adjudication: no penalty or reputation table is planned for v1. Making the spec's privacy claims true
by writing nicer words: index-node reads what it holds, and padding is measured as absent (`E-0077`).
Bit-identical float inference across platforms: replaced by a fixed-point Δ=1/127 convention.

## Kill criteria

Stop a line when its own measurement says the premise is wrong, and write the negative result into
`lab/`.

* A paid-order horizon dies if a receipt cannot be derived deterministically from the artifact plus the
  order on two hosts: without that, there is no non-judged payout and the whole layer is a marketplace
  with extra steps.
* A verifier image dies as a dependency if a bounded budget (`budget_seconds`) cannot produce a stable
  verdict on the same input; a nondeterministic checker means `E_VERDICT_MISMATCH` at runtime, which we
  will not ship into.
* The fan-out decision (§12.1) is reconsidered if the ~200-node stand shows `p95` above the 500 ms
  threshold and the cost is not in `search` — `E-0084` already showed 74…81 % of find time is discovery,
  so a discovery-dominated failure means changing discovery, not the index.
* A formal model is dropped from the loop if it stops catching planted defects: `E-0093` showed a
  grep-shaped guard passing two planted violations, and the fix was to make the guard read terms.
* Any horizon stalls if its readiness would have to be asserted with a word instead of a number; in that
  case the honest output is `OPEN` with the missing evidence named.

## Reading order

`README.md` → `docs/VecDHT-SPEC-v8.md` (v1 protocol) → `docs/VecDHT-SPEC-v9.md` (paid-order delta) →
`docs/PAID_ORDER-VECTORS.md` (the vectors a client must match) → `docs/STATUS-v1.md` and
`docs/METRICS.md` (state and measured numbers) → `lab/decisions/` (why each rule is that
shape) → `lab/experiments/` (the numbers and their thresholds). The Russian translation of the front map
is `README.ru.md`.
