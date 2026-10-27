#!/usr/bin/env bash
# H-0136 / E-0136: отказ носителя `revocation.bin` и забывание отзыва (`ADR-0050`, OPEN-QUESTIONS п. 66).
# Прибор — тест-проба в том же модуле: он печатает пару ветвей (здоровый носитель / отказ), поэтому
# краснота дыры отличается от слепоты пробы. Порог над числом фактов и над вектором значений;
# вердикт этого цикла ничего не чинит — политика «отказываться ли обслуживать при ошибке диска»
# относится к владельцу (красная зона), здесь она только названа числом.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
python lab/cycle-gate.py gate H-0136 >>"$buf" 2>&1 && emit GATE_H0136_OK 1 || emit GATE_H0136_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0
cargo test -p vecdht-node --lib a_write_failure_forgets -- --nocapture >${SCR}test.log 2>&1
emit TEST_EXIT $?
sed -n 's/^FACT \([A-Z_][A-Z0-9_]*\) \(.*\)$/\1=\2/p' ${SCR}test.log >>"$buf"
# Контроль полноты пропечатки: каждый ключ обязан иметь источник и в тесте (`emit_fact`), и в
# экстракторе (`printf FACT`). Девять строк одного и девять другого — единственный способ
# отличить «факт равен нулю» от «факт не напечатан».
emit FACT_EMITTED_BY_TEST "$(grep -c 'emit_fact(' crates/vecdht-node/src/revocation.rs)"
emit FACT_PRINTED_BY_TEST "$(grep -c 'printf "FACT ' crates/vecdht-node/src/revocation.rs)"
emit FACTS_TOTAL "$(sed -n 's/^FACT \([A-Z_][A-Z0-9_]*\) \(.*\)$/\1/p' ${SCR}test.log | wc -l | tr -d ' ')"
emit RUST_TOUCHED "$(git diff --name-only 7590463 -- crates/ | wc -l)"
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
bash lab/check-text-clean.sh >${SCR}text.txt 2>&1; emit TEXTGUARD_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?
SNAP=${TMPDIR:-/tmp}/e0136-post1.facts
Filt() { grep -v -E '^(DISK_FREE_MB|TEST_EXIT)=' "$1"; }
if [ -f "$SNAP" ]; then diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null && emit STABLE 1 || emit STABLE 0; fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
