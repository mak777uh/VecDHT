---
id: E-0140
hypothesis: H-0140
status: pre-registered
base_commit: "ad1eb70"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; только bash и python — цикл не исполняет cargo и не
поднимает сеть, потому что измеряет полноту собственного текстового узнавателя; пин-прибор извлекается
`git show <пин>:lab/threshold-lint.py` с перенаправлением во временный каталог, живой индекс и рабочее
дерево не трогаются ни на одном шаге (форма `git checkout <пин> -- файл` отвергнута — пишет в индекс,
круг `E-0139`, ДИАГНОЗ-3); продукт не правится (`RUST_TOUCHED=0`); дата карточки судится по UTC
(`ADR-0070`)"
command: "bash lab/e0140-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0140.tsv run1.txt run2.txt`); PRE_FIX — тот же helper, пин-прибор по одной таблице
на 44 закрытых таблицах; `python lab/threshold-lint.py --selftest`"
threshold: "(1) `python lab/cycle-gate.py gate H-0140` выход 0 (`GATE_H0140_OK=1`), диск ≥ 15 000 МБ
до прогона (`DISK_GE_15000=1`); (2) дыра названа пин-прибором: `PRE_FIX_INSTRUMENT=1`,
`PRE_FIX_PIN_LINES=304`, `PRE_FIX_HAS_SWEEP=0`, `PRE_FIX_SELF_EXCLUDED=1`, `PRE_FIX_TABLES=44`,
`PRE_FIX_SIROT=26`, `PRE_FIX_TABLES_WITH_SIROT=5`, `PRE_FIX_NO_SUMMARY=0`, по таблицам
`PRE_FIX_E0093=6`, `PRE_FIX_E0095=4`, `PRE_FIX_E0099=6`, `PRE_FIX_E0123=4`, `PRE_FIX_E0131=6`, и по
одному представителю каждой формы: `PRE_FIX_KEY_AXIOM=1`, `PRE_FIX_KEY_DR=1`, `PRE_FIX_KEY_VERUS=1`,
`PRE_FIX_KEY_CLAIMMAP=1`, `PRE_FIX_KEY_ALLOWLIST=1`; (3) живой свод читает то же множество:
`LIVE_SWEEP_EXIT=0`, `LIVE_TABLES=44`, `LIVE_CLOSED=44`, `LIVE_KEYS=1924`, `LIVE_SOURCES=363`,
`LIVE_CARRIER=61`, `TABLES_AGREE=1`; (4) каждый ключ закрыт названной формой: `LIVE_FORM_LITERAL=1532`,
`LIVE_FORM_FUNNEL=286`, `LIVE_FORM_RUSTFUNNEL=9`, `LIVE_FORM_TEMPLATE=3`, `LIVE_FORM_LOOP=86`,
`LIVE_FORM_SPLICE=none`, `LIVE_FORM_REPRINT=4`, `LIVE_FORM_TAG=4`, `LIVE_FORM_CARRIER=none`,
`LIVE_FORM_SUM=1924`, `LIVE_SIROT=0`, `LIVE_TABLES_WITH_SIROT=0`, `LIVE_ORPHAN_AXIOM=0`,
`LIVE_ORPHAN_DR=0`, `LIVE_ORPHAN_VERUS=0`, `LIVE_ORPHAN_CLAIMMAP=0`, `LIVE_ORPHAN_ALLOWLIST=0`; (5)
быстрый индекс не меняет вердикт: `LIVE_CROSSCHECKED=427`, `LIVE_DIVERGE=0`; (6) самопроверка прибора:
`SELFTEST_EXIT=0`, `SELFTEST_TOTAL=34`, `SELFTEST_PASSED=34`, `SELFTEST_CYRILLIC=1`,
`SELFTEST_CYRILLIC_NEG=1`; (7) соседние стражи не рассоединились: `SECRETS_EXIT=0`, `REFS_EXIT=0`,
`CLAIMMAP_EXIT=0`, `CLAIMS_EXIT=0`, `CONTOURS_EXIT=0`, `TEXTGUARD_ALL_EXIT=0`,
`TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`, `LINT_LATEST_EXIT=0`,
`LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (8) `RUST_TOUCHED=0`, `WORST_RC=0` и два
исполнения на неизменном дереве печатают один вектор — `STABLE=1`. Порог заморожен до первого
официального прогона `lab/e0140-run.sh`; изменение любого числа — новая карточка. Своя таблица
исключена из PRE_FIX (`PRE_FIX_SELF_EXCLUDED=1`): пин-прибор не печатает `СВЕД_*`, и её ключи — прибор
над прибором; свод читает только таблицы закрытых циклов, поэтому своя же таблица в него не входит."
---

# E-0140 — свод линта порогов по закрытым таблицам

Карточка заведена вместе с прибором (`lab/e0140-run.sh`), режимом свода в `lab/threshold-lint.py` и
таблицей ожиданий `lab/expectations/e0140.tsv`. Утверждение, фальсификатор и оракул — в
`lab/hypotheses/H-0140-threshold-sweep.md`; здесь лежит только замороженный порог.
