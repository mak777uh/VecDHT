# Инвентарь `lab/` — порождённый, не набранный

> Единственный носитель инвентарных счётчиков репозитория. README, PITCH и ROADMAP
> ссылаются на этот файл и не печатают числа. Измеренные величины живут в
> `docs/METRICS.md` и всегда стоят рядом с id цикла, который их снял.

Переснять: `python lab/inventory.py --date <ГГГГ-ММ-ДД> --write lab/INVENTORY.md`
Дата этого среза: 2026-10-28 (передаётся аргументом, чтобы повтор был воспроизводим).
Прибор выходит ненулём, если хотя бы одно напечатанное число нельзя вычислить из дерева.

| счётчик | значение | как снято |
|---|---|---|
| `hypotheses` | 138 | `ls lab/hypotheses/*.md \| wc -l` |
| `experiments` | 138 | `ls lab/experiments/*.md \| wc -l` |
| `adrs` | 47 | `ls lab/decisions/ADR-*.md \| wc -l` |
| `syntheses` | 5 | `ls lab/notes/S-*.md \| wc -l` |
| `hypothesis_status_total` | 138 | поле `status:` карточек гипотез |
| `hypothesis_status_untagged` | 0 | файлы без поля `status:` |
| `hypothesis_status_closed` | 15 | поле `status:` == closed |
| `hypothesis_status_completed` | 9 | поле `status:` == completed |
| `hypothesis_status_measured` | 3 | поле `status:` == measured |
| `hypothesis_status_pre-registered` | 1 | поле `status:` == pre-registered |
| `hypothesis_status_proposed` | 3 | поле `status:` == proposed |
| `hypothesis_status_refuted` | 18 | поле `status:` == refuted |
| `hypothesis_status_supported` | 88 | поле `status:` == supported |
| `hypothesis_status_testing` | 1 | поле `status:` == testing |
| `experiment_status_total` | 138 | поле `status:` карточек экспериментов |
| `experiment_status_untagged` | 0 | файлы без поля `status:` |
| `experiment_status_closed` | 25 | поле `status:` == closed |
| `experiment_status_completed` | 108 | поле `status:` == completed |
| `experiment_status_done` | 3 | поле `status:` == done |
| `experiment_status_planned` | 2 | поле `status:` == planned |
| `verdict_missing` | 0 | карточки без разбираемого поля `verdict:` |
| `verdict_total` | 138 | сумма разобранного поля `verdict:` по карточкам |
| `verdict_supports` | 109 | первое слово поля `verdict:` == supports |
| `verdict_refutes` | 23 | первое слово поля `verdict:` == refutes |
| `verdict_satisfies` | 3 | первое слово поля `verdict:` == satisfies |
| `verdict_accepted` | 1 | первое слово поля `verdict:` == accepted |
| `verdict_pending` | 2 | первое слово поля `verdict:` == pending |
| `verdict_inconclusive` | 0 | первое слово поля `verdict:` == inconclusive |
| `verdict_other` | 0 | вердикты вне объявленного словаря (аудит, N5) |
| `library_entries` | 43 | непустые строки lab/library/index.jsonl |
| `library_ids` | 43 | непустые различающиеся поля id в индексе источников |
| `logs` | 156 | файлы в lab/logs/ (append-only) |
| `log_dirs` | 0 | подкаталоги lab/logs/ |
| `logs_sha256_unique` | 153 | различающиеся sha256 среди файлов lab/logs/ |
| `logs_sha256_duplicated` | 3 | sha256, встречающиеся в log-файлах более одного раза |
| `verify_log_files` | 1 | файлы lab/logs/workspace-verify-*.log |
| `verify_blocks` | 116 | заголовки прогонов `########## <метка> ·` в них |
| `verify_labels` | 86 | различающиеся метки прогонов, переданные lab/workspace-verify.sh |
| `carrier_sha256_paid_order_vectors` | cc3eae129dcd911f00a97464fe6d4a00555ab0cdcea1cbe823aa2bbdf18497ec | sha256sum docs/PAID_ORDER-VECTORS.md |
| `carrier_sha256_spec_v8` | f96bdd3ac427d70571ececc78c3aa9624abe26cbecb6b0234d35664cb9321d93 | sha256sum docs/VecDHT-SPEC-v8.md |
| `carrier_sha256_spec_v9` | a121878a263fa8a1b1c05915b29ee8cd7fbb8f43a30016a1c387e3e36243dbb3 | sha256sum docs/VecDHT-SPEC-v9.md |
| `carrier_lines_paid_order_vectors` | 352 | `wc -l` по docs/PAID_ORDER-VECTORS.md |
| `carrier_lines_spec_v8` | 2300 | `wc -l` по docs/VecDHT-SPEC-v8.md |
| `carrier_lines_spec_v9` | 634 | `wc -l` по docs/VecDHT-SPEC-v9.md |
| `lean_models_guarded` | 6 | `lab/lean/VecDHT/*.lean` — то, что покрывает `bash lab/lean-check.sh` |
| `lean_models_outside_guard` | 1 | .lean вне `lab/lean/VecDHT/`, их страж моделей не компилирует |
| `lean_frozen` | 6 | файлы заморозки формулировок в lab/lean/frozen/ |
| `verus_files` | 1 | .rs в lab/proofs/verus/ |
| `cycle_helpers` | 129 | lab/e0XXXX-run.sh helper'ов циклов |
| `expectation_files` | 49 | таблицы ожиданий lab/expectations/*.tsv |
| `docs_scanned` | 14 | файлы DOC_SET, перебранные проверкой разрешимости |
| `id_mentions` | 1624 | упоминания `H-`/`E-`/`ADR-`/`L-` в этих документах |
| `dangling_id_mentions` | 27 | названные номера, под которыми нет файла (правило разрешимости, аудит B6) |
| `dangling_ids` | ADR-0014, ADR-0019, ADR-0020, ADR-0021, ADR-0022, ADR-0023, ADR-0024, ADR-0025, ADR-0026, ADR-0027, ADR-0028, ADR-0029, ADR-0030, ADR-0031, ADR-0032, ADR-0033, ADR-0034, ADR-0035, ADR-0037, ADR-0038, ADR-0039, ADR-0040, ADR-0041, E-0014, H-0052, H-0088b, H-0106 | список неразрешённых номеров |
| `dangling_where_ADR-0014` | lab/README.md:2002; lab/README.md:2011; lab/README.md:475 | адреса упоминаний |
| `dangling_where_ADR-0019` | lab/PLAN.md:621; lab/README.md:1863 | адреса упоминаний |
| `dangling_where_ADR-0020` | lab/PLAN.md:621 | адреса упоминаний |
| `dangling_where_ADR-0021` | lab/PLAN.md:621; lab/README.md:1863 | адреса упоминаний |
| `dangling_where_ADR-0022` | lab/PLAN.md:616; lab/PLAN.md:622; lab/PLAN.md:642; lab/PLAN.md:74; lab/README.md:1514; lab/README.md:1844 | адреса упоминаний |
| `dangling_where_ADR-0023` | lab/PLAN.md:616; lab/PLAN.md:622; lab/PLAN.md:642; lab/PLAN.md:74; lab/README.md:1514; lab/README.md:1844 | адреса упоминаний |
| `dangling_where_ADR-0024` | docs/VecDHT-SPEC-v8.md:191; lab/PLAN.md:336; lab/PLAN.md:346; lab/PLAN.md:623; lab/PLAN.md:75; lab/README.md:1448 | адреса упоминаний |
| `dangling_where_ADR-0025` | lab/PLAN.md:623; lab/PLAN.md:75; lab/README.md:1448 | адреса упоминаний |
| `dangling_where_ADR-0026` | lab/PLAN.md:336; lab/PLAN.md:624; lab/PLAN.md:75; lab/README.md:1448 | адреса упоминаний |
| `dangling_where_ADR-0027` | lab/PLAN.md:624; lab/README.md:1424 | адреса упоминаний |
| `dangling_where_ADR-0028` | lab/PLAN.md:624 | адреса упоминаний |
| `dangling_where_ADR-0029` | lab/PLAN.md:625 | адреса упоминаний |
| `dangling_where_ADR-0030` | lab/PLAN.md:625 | адреса упоминаний |
| `dangling_where_ADR-0031` | lab/PLAN.md:626; lab/README.md:1424 | адреса упоминаний |
| `dangling_where_ADR-0032` | lab/PLAN.md:611; lab/PLAN.md:626; lab/PLAN.md:76; lab/README.md:1480 | адреса упоминаний |
| `dangling_where_ADR-0033` | lab/PLAN.md:612; lab/PLAN.md:626 | адреса упоминаний |
| `dangling_where_ADR-0034` | lab/PLAN.md:613; lab/PLAN.md:627 | адреса упоминаний |
| `dangling_where_ADR-0035` | lab/PLAN.md:613; lab/PLAN.md:627; lab/PLAN.md:76; lab/README.md:1480 | адреса упоминаний |
| `dangling_where_ADR-0037` | lab/PLAN.md:417 | адреса упоминаний |
| `dangling_where_ADR-0038` | lab/PLAN.md:175; lab/PLAN.md:79; lab/README.md:1652 | адреса упоминаний |
| `dangling_where_ADR-0039` | lab/PLAN.md:203; lab/PLAN.md:306; lab/PLAN.md:81; lab/README.md:1695; lab/README.md:1817 | адреса упоминаний |
| `dangling_where_ADR-0040` | lab/PLAN.md:242; lab/PLAN.md:316; lab/PLAN.md:82; lab/README.md:1746; lab/README.md:1823 | адреса упоминаний |
| `dangling_where_ADR-0041` | docs/VecDHT-SPEC-v8.md:2145; lab/PLAN.md:346; lab/PLAN.md:418; lab/PLAN.md:83; lab/README.md:1799; lab/README.md:452 | адреса упоминаний |
| `dangling_where_E-0014` | docs/VecDHT-v9-REVIEW.md:235 | адреса упоминаний |
| `dangling_where_H-0052` | lab/README.md:1997; lab/README.md:2005 | адреса упоминаний |
| `dangling_where_H-0088b` | lab/PLAN.md:377; lab/README.md:129 | адреса упоминаний |
| `dangling_where_H-0106` | docs/VecDHT-SPEC-v8.md:1955; lab/PLAN.md:407 | адреса упоминаний |

## Что не является числом

Разрешимость имён (`dangling_id_mentions`) считает документы для чтения из
`DOC_SET` в начале `lab/inventory.py`. Нулевое значение — это выполненное правило
«документ не называет `H-`/`E-`/`ADR-`/`L-` без файла»; ненулевое — список адресов,
по которому видно, какой документ править. Строки прогона и измеренные числа здесь
не появляются намеренно: они принадлежат `docs/METRICS.md`.
