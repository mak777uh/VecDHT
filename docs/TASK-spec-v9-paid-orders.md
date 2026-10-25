# TASK: extend VecDHT spec to v9 for paid orders (verifiable work market)

**Status:** task for the VecDHT maintainers. Author of the task: auditing/verification track.
**Related document:** [`docs/PAID_ORDERS.md`](PAID_ORDERS.md) (design rationale, task taxonomy, economics).

Коротко по-русски: нужно аккуратно, без фантазий, доработать спецификацию до v9 — добавить тип
интента «платный заказ» с машинной проверкой результата и автоматической выплатой по квитанции.
Ниже — что именно проверить, как описать, какие тест-векторы приложить и по каким критериям
считать работу принятой. Всё, что нельзя проверить на этом коммите, помечать как `OPEN`, а не
додумывать.

---

## 0. Rules of engagement (read first)

1. **Verify before writing.** Every claim you add to the spec must be checkable on this repository:
   a measurement id (`E-XXXX`), a test, or a citation to an existing ADR. If it is not checkable, mark
   it `OPEN` with the reason.
2. **No invented numbers.** Follow the existing rule from `README.md`: a number lives only together
   with its measurement id, the command that produced it, and a link to the log.
3. **Backwards compatibility.** v8 participants must keep working. Any breaking change needs an ADR and
   a migration note; if there is no migration path, the change is out of scope.
4. **One change, one ADR.** Create `lab/decisions/ADR-00XX-paid-orders.md` describing: context, decision,
   alternatives rejected, consequences, and how it is tested.
5. **Do not restate the design doc.** The design rationale is in `PAID_ORDERS.md`; the spec holds
   normative requirements (MUST/SHOULD/MAY), not motivation.
6. **Hostile reader test.** The spec must be implementable by someone who has only the spec and the
   test vectors — without reading our code and without asking us questions.

---

## 1. Deliverables

| # | artifact | acceptance |
|---|---|---|
D1 | `docs/VecDHT-SPEC-v9.md` — spec delta over v8 (normative) | implementable, all fields typed, all state transitions total, error codes enumerated |
D2 | `docs/PAID_ORDER-VECTORS.md` — test vectors (JSON) | at least 12 vectors: happy path, replay, wrong hash, timeout, insufficient escrow, malformed receipt |
D3 | `lab/decisions/ADR-00XX-paid-orders.md` | context/decision/alternatives/consequences/tests |
D4 | `README.en.md` — English README (pitch + map of the repo) | 600–900 words, links to spec, lab, vectors; no marketing superlatives |
D5 | `ROADMAP.md` — product roadmap | 3 horizons with measurable exit criteria, no dates without a dependency |
D6 | spec mirror check updated (`lab/check-spec-mirror.sh`) | `./lab/check-spec-mirror.sh` exits 0 for v9 |
D7 | `lab/experiments/E-XXXX-*.md` cards for each new normative behavior that we actually ran | card format matches existing cards |

---

## 2. The normative change, in one paragraph

A new intent type `paid_order` lets a customer publish a machine-verifiable task with a price; any node
may submit an artifact; a **deterministic verifier** runs inside a pinned image and emits a **receipt**;
an **escrow** releases the price when and only when the receipt says `pass`. VecDHT's role is discovery
and record publication, not verification or payment.

---

## 3. Spec sections to write (and what must be in each)

### 3.1 `paid_order` record

Required fields, with exact types and canonical encoding:

| field | type | must say in spec |
|---|---|---|
`kind` | enum | one of `lean_proof`, `test_conformance`, `repro_run` (v9 scope; anything else is `OPEN`) |
`statement` | bytes | how the statement is canonically encoded (see 3.2) |
`statement_hash` | 32 bytes | algorithm, domain separation string, and whether it covers the kind |
`verifier` | object | `image_digest` (sha256 of the container image), `entrypoint`, `budget_seconds` (uint32), `network` (bool: may the verifier use network — default `false`) |
`reward` | object | `amount` (uint128), `asset` (chain id + token address or `native`), `escrow_ref` |
`deadline` | uint64 | unix seconds, inclusive/exclusive stated explicitly |
`submit_limit` | uint16 | max submissions per order (anti-spam), what happens on exceed |
`publisher` | pubkey | signature over the canonical record |
`nonce` | uint64 | replay protection scope: per publisher or global — decide and write |

Rules that must be stated explicitly (these are where implementations diverge):

- what happens if two different `statement` encodings hash differently but mean the same thing;
- whether `statement_hash` covers `kind` (recommend: yes, domain-separated);
- whether an order can be edited after publication (recommend: no; publish a new order and reference the old);
- what a node MUST do with an order whose `verifier.image_digest` it cannot fetch.

### 3.2 Canonical statement encoding

Write a **normative** procedure:

1. UTF-8, NFC normalization, `\n` line endings, no trailing whitespace;
2. strip comments in the target language **only if** the language defines a comment syntax in the spec —
   otherwise comments are part of the statement;
3. hash = `sha256(domain || 0x00 || kind || 0x00 || normalized_bytes)` with `domain = "vecdht/paid_order/v1"`;
4. publish 3 worked examples with their hashes as test vectors (one Lean statement, one test-suite
   descriptor, one repro manifest).

If you cannot decide 1–3 without trying, write `OPEN` and propose the decision in the ADR — do not
invent silently.

### 3.3 Submission record

Fields: `order_ref` (hash of the order record), `artifact_hash`, `artifact_uri` (content-addressed),
`submitter`, `nonce`, `signature`, `created_at`.

Must state: whether the artifact may be a set (multi-file) and how the set is hashed (recommend:
Merkle root over sorted `path\0sha256` lines, published as a test vector).

### 3.4 Receipt record (the core of the protocol)

| field | must say |
|---|---|
`order_ref`, `submission_ref` | how computed |
`verdict` | enum `pass` / `fail` / `timeout` / `error` |
`image_digest` | must equal the order's, else `error` |
`toolchain` | for `lean_proof`: exact Lean version + mathlib commit (if used) |
`axioms` | for `lean_proof`: the axiom list as reported by the kernel; MUST be empty except for an allowlist defined in the spec |
`wall_clock_ms`, `budget_ms` | measured and declared; `timeout` iff measured > budget |
`exit_code`, `stdout_sha256`, `stderr_sha256` | deterministic capture rules (truncation? trailing newline?) |
`verifier_pubkey`, `signature` | who attests the receipt, and over which canonical bytes |
`deterministic` | bool with the rule used to decide it |

Explicitly define: **a receipt is valid only if it is signed, its image digest matches the order, and its
verdict is derivable from the fields** (write the derivation rule). This is what makes payout automatic
without a judge.

### 3.5 State machine

Draw the full lifecycle as a total function (every state × event has a defined outcome):

```
published → (submission) → verifying → pass|fail|timeout|error → settled|rejected
published → (deadline reached, no submissions) → expired
verifying → (verifier offline past budget×N) → disputed
```

For each transition: who may trigger it, what evidence is required, what is written to the log, and
which state is terminal. Any missing (state, event) pair must be `error`, not undefined behavior.

### 3.6 Escrow handshake

Specify the *interface*, not the chain: `lock(order_ref, reward)`, `release(receipt)`,
`refund(order_ref, reason)`. State clearly:

- release conditions: `verdict == pass` ∧ `receipt valid` ∧ `submission within deadline` ∧ `not already paid`;
- refund conditions: `expired` or `disputed` with a defined resolution;
- what happens if the escrow reference is on a chain the node does not follow (fail closed).

Reference the already-proved escrow invariants in
`mak777uh/audits/proofs/escrow.lean` (hold conserves total, release exactly once, no negative balance,
only owner/protocol may release) and say which of them the implementation must uphold.

### 3.7 Error codes

A closed list (`E_ORDER_MALFORMED`, `E_HASH_MISMATCH`, `E_IMAGE_UNAVAILABLE`, `E_BUDGET_EXCEEDED`,
`E_REPLAY`, `E_SUBMIT_LIMIT`, `E_ESCROW_UNKNOWN`, `E_RECEIPT_INVALID`, …) with the action a node takes
for each: reject, retry, ignore, escalate to `disputed`.

### 3.8 Threat model (one page, honest)

Must cover at least:
- verifier lying about the result — mitigated by signed receipts + independent verifiers + published image digest;
- verifier starving the job (budget too small) — budget is public before submission; submissions must
  check it locally before paying gas;
- garbage-in spec (customer asks a useless question) — out of protocol scope, stated plainly;
- proof farming (`sorry`, extra axioms, `native_decide`, imported axioms) — allowlist + kernel-reported axioms;
- non-determinism (time, randomness, network) — `network=false` default, determinism flag, seed rules;
- replay / double payout — nonce + `order_ref` uniqueness + idempotency key in the journal;
- griefing by mass low-quality submissions — `submit_limit` + submission bond.

For each threat: what the protocol guarantees, and what it explicitly does not.

---

## 4. What to verify against this repository before publishing v9

Do not write "as designed"; write "verified, reference X":

- [ ] every field name in D1 exists in `docs/VecDHT-SPEC-v8.md` or is introduced with a migration note;
- [ ] the hash/canonicalization procedure is reproducible with the 3 worked examples (provide the commands);
- [ ] the state machine has no undefined pair (list the matrix in the spec as a table);
- [ ] receipts from two independent verifier implementations would be byte-identical for the same run
      (state the exact JSON serialization: key order, number formats, no floats);
- [ ] the escrow invariants map 1:1 to the Lean theorems we already proved, with file+theorem names;
- [ ] `lab/check-spec-mirror.sh` passes for v9;
- [ ] `lab/check-text-clean.sh` passes (no numbers without measurement ids);
- [ ] the 12 test vectors in D2 cover every error code in 3.7;
- [ ] the README (D4) has no claim that the spec does not license.

---

## 5. README.en.md — required shape (D4)

1. **What this is** (3 sentences, no adjectives);
2. **What problem it removes** (central discovery chokepoint), one paragraph;
3. **How it works** (publish intent → discover by meaning → records are content-addressed);
4. **Repository map** (spec / lab / sdk / benches, one line each);
5. **Status**: what is done, what is not (no release, no external operator — say it);
6. **How to check a claim** (commands: spec mirror, text clean, one experiment replay);
7. **Paid orders** (one paragraph + link to `PAID_ORDERS.md`), stated as **planned**, not shipped;
8. **Licence** and how to contribute (ADR + experiment card rules).

Rule: if a sentence would need a footnote "not implemented yet", it goes to Status, not to How it works.

---

## 6. ROADMAP.md — required shape (D5)

Three horizons, each with **measurable exit criteria** and explicit dependencies. No dates unless a date
is externally imposed (deadline of a funder, a chain upgrade).

| horizon | goal | exit criteria (measurable) | depends on |
|---|---|---|---|
H1 (v1) | a v1 that two independent operators run | release tag; two operators with ≥30 days uptime; conformance vectors pass on both; zero P1 bugs open | spec freeze, bindings |
H2 | paid orders live in testnet | 10 orders published, 5 settled by receipt, escrow released automatically, one dispute resolved by receipt | H1, verifier image published, escrow contract |
H3 | third-party verifiers | 2 independent verifier implementations produce identical receipts on the same 20 vectors | H2, receipt spec stable |

Also required in D5: a "**not doing**" list (things we deliberately refuse: subjective tasks, human
judging, custody of funds) and a "**kill criteria**" list (conditions under which we stop a line).

---

## 7. Process requirements

- one PR per deliverable; PR description states which acceptance items from §4 are checked and how;
- every normative change gets an ADR; every measured claim gets an experiment card;
- negative results are published (this is a rule from `lab/README.md`, keep it);
- if a decision cannot be made from evidence in the repo, mark `OPEN`, list what evidence would settle it.

## 8. Definition of done

A reviewer who has never seen the project can: read `README.en.md`, open the spec, run the three
verification commands, replay two experiments, and implement a minimal `paid_order` client from the
spec + test vectors alone. If any of those steps requires asking us a question, the task is not done.
