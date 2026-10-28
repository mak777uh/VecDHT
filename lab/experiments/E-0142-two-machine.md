---
id: E-0142
hypothesis: H-0142
status: pre-registered
base_commit: "0a34422"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; bash, python и cargo — прибор гоняет три золотых
теста (`golden_vectors` ×2, `golden_artifact`), но не поднимает сеть и не правит продукт
(`RUST_TOUCHED=0`); фикстуры читаются из blob'ов git, а не из рабочей формы, и это отдельный предмет
круга: рабочая форма на этом дереве CRLF (30/66/22), blob — LF; пин-прибор извлекается
`git show <пин>:lab/two-machine.py` с перенаправлением во временный каталог, живой индекс и рабочее
дерево не трогаются ни на одном шаге (форма `git checkout <пин> -- файл` отвергнута — пишет в индекс,
круг `E-0139`, ДИАГНОЗ-3); дата карточки судится по UTC (`ADR-0070`)"
command: "bash lab/e0142-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0142.tsv run1.txt run2.txt`); PRE_FIX — тот же helper, `git show` пина во временный
каталог; `python lab/two-machine.py selftest`"
threshold: "(1) `python lab/cycle-gate.py gate H-0142` выход 0 (`GATE_H0142_OK=1`), диск ≥ 15 000 МБ
до сбора снимка (`DISK_GE_15000=1`); (2) дыра названа отсутствием: `PIN_FOUND=1`,
`PRE_FIX_INSTRUMENT=0`, `PRE_FIX_KEYS=0`, `PRE_FIX_SNAPSHOT=none`; (3) самопроверка сверщика:
`SELFTEST_EXIT=0`, `SELFTEST_TOTAL=24`, `SELFTEST_PASSED=24`; (4) снимок полон: `SNAP_EXIT=0`,
`SNAP_KEYS=35`, `SNAP_OK=1`, `SNAP_ESCAPE=0`, `SNAP_DIRTY=0`, `SNAP_ROOT_NAME=vecdht`,
`SNAP_TESTS_RAN=3`, `SNAP_TESTS_OK=3`; (5) байты вектора — blob, а рабочая форма названа отдельно:
`SNAP_FIXTURE_crypto_BLOB_SHA256=15a4d7f145ff750d7c69142dc47df0291f3e6f11fb10d3dcdc15ba39d7384921`,
`SNAP_FIXTURE_crypto_BLOB_BYTES=4509`,
`SNAP_FIXTURE_wire_BLOB_SHA256=ce0bd8a4db523f941c22a457834cb37ad1bdf5d882c74f77f5cd134ca25ab9c4`,
`SNAP_FIXTURE_wire_BLOB_BYTES=23137`,
`SNAP_FIXTURE_artifact_BLOB_SHA256=411f91b942546bf7d1dd82b47f517a4464cc69f2ba844ae447ae9dcb9c7fcb91`,
`SNAP_FIXTURE_artifact_BLOB_BYTES=11787`, `SNAP_FIXTURE_crypto_WORK_BYTES=4539`,
`SNAP_FIXTURE_wire_WORK_BYTES=23203`, `SNAP_FIXTURE_artifact_WORK_BYTES=11809`,
`SNAP_FIXTURE_crypto_WORK_CRLF=30`, `SNAP_FIXTURE_wire_WORK_CRLF=66`,
`SNAP_FIXTURE_artifact_WORK_CRLF=22`, `SNAP_FIXTURE_crypto_CLEAN=1`, `SNAP_FIXTURE_wire_CLEAN=1`,
`SNAP_FIXTURE_artifact_CLEAN=1`; (6) собственный снимок засчитан: `VERIFY_EXIT=0`, `V_MATCH=9`,
`V_MISMATCH=none`, `V_MISSING=none`, `V_FOREIGN=none`, `V_DUPLICATE=none`, `V_HEAD_MATCH=1`,
`V_TESTS=3`, `V_TESTS_OK=3`, `V_VERDICT=pass`, `V_REASONS=none`; (7) подменённый blob-хеш назван и
отвергнут: `TAMPER_EXIT=1`, `TAMPER_VERDICT=fail`, `TAMPER_MATCH=8`,
`TAMPER_MISMATCH=TM_FIXTURE_wire_BLOB_SHA256`; (8) законное различие рабочей формы не меняет вердикт:
`OTHER_EXIT=0`, `OTHER_VERDICT=pass`; (9) соседние стражи не рассоединились: `SECRETS_EXIT=0`,
`REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `CLAIMS_EXIT=0`, `CONTOURS_EXIT=0`, `TEXTGUARD_ALL_EXIT=0`,
`TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`, `LINT_LATEST_EXIT=0`,
`LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (10) `RUST_TOUCHED=0`, `WORST_RC=0` и два
исполнения на неизменном дереве печатают один вектор — `STABLE=1`. Порог заморожен до первого
официального прогона `lab/e0142-run.sh`; изменение любого числа — новая карточка. Прогон на второй
машине этим кругом не засчитывается: он остаётся за владельцем, а здесь заморожено только «чем сверять
и по какому праву»."
---

# E-0142 — вторая машина как исполняемая процедура

Карточка заведена вместе с прибором (`lab/e0142-run.sh`), самим сверщиком (`lab/two-machine.py`) и
таблицей ожиданий `lab/expectations/e0142.tsv`. Утверждение, фальсификатор и оракул — в
`lab/hypotheses/H-0142-two-machine.md`; здесь лежит только замороженный порог. Снимок называется
`machine-A` — это метка прогона на хосте владельца, а не имя машины в сети.
