---
id: E-0146
hypothesis: H-0146
status: open
verdict: "pending"
base_commit: "ece9ff2"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; cargo и bash; один тест-бинарник
`vecdht-index`, корпус строится в памяти, сеть наружу не используется; PRE_FIX снимается из пина
через `git show`"
command: "bash lab/e0146-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0146.tsv run1.txt run2.txt`); носитель — `cargo test -q -p vecdht-index --test
s19_recall_filter -- --nocapture --test-threads=1`"
threshold: "(1) пин и диск: `PIN_FOUND=1`, `PRE_FIX_TEST=1`, `PRE_FIX_FILTER=1`, `PRE_FIX_ATTR=1`,
`GATE_H0146_OK=1`, `DISK_GE_15000=1`; (2) прибор: `ORACLE_EXIT=0`, `ORACLE_PASSED=1`,
`ORACLE_FAILED=0`, входы `CORPUS_ENTRIES=2048`, `CORPUS_CLUSTERS=16`, `QUERIES=48`, `TOP_K=10`;
(3) тождество и предикат: `IDENTITY_MISMATCHES=0`, `RECALL_EQ_COVERAGE=1`, `FILTER_ADDS_MISSES=0`,
`EMPTY_WITH_ORACLE_2_NP4=0`, `PROBES_EMPTY_2_NP4=0`; (4) контроль «фильтр после усечения» отличим:
`CTRL_LT_300=1`; (5) границы: `WIRE_TOUCHED=0`, `RUST_TOUCHED=1`; (6) соседние стражи зелёные
(`SECRETS_EXIT`, `REFS_EXIT`, `CLAIMMAP_EXIT`, `CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`,
`GATE_AUDIT_EXIT`, `REVIEW_EXIT`, `LINT_LATEST_EXIT`, `TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`),
`LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`; (7) `WORST_RC=0` и два исполнения на неизменном дереве
печатают один вектор — `STABLE=1`. Порог заморожен до первого официального прогона
`lab/e0146-run.sh`; изменение любого числа — новая карточка."
---

# E-0146 — recall@10 под `OnlyPaid` на разреженном корпусе

## Что проверяется

Гипотеза `H-0146`: предикат §12.7 стоит до усечения, поэтому фильтр не теряет ни одного хита
внутри просканированного списка, а потеря полноты при разреженном классе — цена зондирования.
Прибор `crates/vecdht-index/tests/s19_recall_filter.rs` меряет четыре плотности платных
(100/10/2/1 %) и три размера списка зондирования шарда (16/4/1 кластер), сравнивая выдачу
`IvfIndex::search_filtered` с независимым оракулом и с потолком покрытия.

## Почему это не косметика

До круга у §12.7 не было числа: спека честно говорила «recall при `OnlyPaid` не измерен». Без
такого числа нельзя ни обещать полноту, ни решать, нужна ли адаптивность `nprobe` под класс. Круг
не меняет продукт — он закрывает неизвестность и показывает, где именно теряется полнота.

## Границы

Синтетический корпус: 16 кластеров одного шарда, класс не коррелирует с геометрией, направление
не мерялось отдельно. Числа — снимок этого корпуса; переносится отношение «полнота == покрытие».
Узел, провод, подпись `MatchResult` и формат кадров не тронуты.

## Что считается вердиктом

Только факты, названные в пороге. Контроль «сначала `top_k`, потом фильтр» исполняется в том же
прогоне и обязан быть видимо хуже исправного пути; иначе прибор слеп и вердикт не ставится.
