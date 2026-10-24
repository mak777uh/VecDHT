#!/usr/bin/env bash
# E-0100: класс и направление интента в коде (§5.5, §5.7, §8.2, §8.4, §12.7).
#
# Четыре прибора на настоящем коде, а не на модели:
#   (1) `publish_corpus_digest` — 256 кадров `Publish` БЕЗ объявлений, FNV-1a 64 всего корпуса;
#       тот же тест запускается на дереве PRE_FIX (`9687c32`), и отпечаток обязан совпасть;
#   (2) `intent_attr_tlv` — каноническая форма TLV: 4 круга, 8 отбитых форм, 4 круга фильтров,
#       3 отбитых фильтра;
#   (3) `vecdht-index --lib` — предикат ДО усечения (20 записей, одна платная, `top_k = 1`),
#       направление автора, снапшот формата 2 и отказ формата 1; плюс `memory_budget` — 1M записей;
#   (4) `intent_class_filter` (узел) — атрибут доезжает от `Publish` через WAL до индекса, выбор
#       `Find` работает, а восемь байт цены не встречаются ни в арене, ни в файлах узла.
#
# Уроки метода, встроенные в этот helper:
#  (а) исполняется неизменяемая mktemp-копия; корень репо — через VEC_DHT_ROOT;
#  (б) ресурсы — тройкой чисел (диск, RAM, pagefile peak), потому что свободный диск есть
#      производная от давления на RAM (ДИАГНОЗ-2 из `E-0088`); `cargo clean` не исполняется;
#  (в) каждый прибор идёт дважды на неизменном дереве, вектор сравнивается без колонок времени
#      (правило 7 (е));
#  (г) ожидания живут файлом `lab/expectations/e0100.tsv` и сверяются исполнением, а не памятью;
#  (д) контроль append-only лога берётся от отметки начала блока (ДИАГНОЗ-3 из `E-0087`);
#  (е) PRE_FIX — снимок в репозитории (`lab/logs/e0100-prefix.txt`), снятый в отдельном worktree
#      на коммите `9687c32`; helper только сверяет его с текущим отпечатком.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0100-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0100-all.log"
PREFIX="lab/logs/e0100-prefix.txt"
EXPECT="lab/expectations/e0100.tsv"
DISK_MIN=15000
DIR_TAG=vecdht-e0100
mkdir -p lab/logs

CORPUS_KEYS="PUBLISH_CORPUS_FRAMES PUBLISH_CORPUS_BYTES PUBLISH_CORPUS_FNV1A64"
ATTR_KEYS="INTENT_ATTR_ROUNDTRIP INTENT_ATTR_REJECTED INTENT_FILTER_ROUNDTRIP INTENT_FILTER_REJECTED"
INDEX_KEYS="INDEX_PREDICATE_ONLYPAID_TOP1 INDEX_DIR_BUY INDEX_DIR_SELL INDEX_DIR_ANY SNAP_FORMAT SNAP_ATTR_ROUNDTRIP SNAP_FORMAT1_REJECTED"
NODE_KEYS="NODE_PRICE_ARENA_HITS NODE_PRICE_FILE_HITS NODE_INDEX_ENTRY_BYTES NODE_FILTER_ANY NODE_FILTER_ONLYPAID NODE_FILTER_ONLYFREE NODE_FILTER_SELL NODE_FILTER_FREE_BUY NODE_FILTER_PAID_BUY NODE_SLOT_ATTR_101 NODE_SLOT_ATTR_102 NODE_SLOT_ATTR_103"
MEM_KEYS="MEM_SLOT_ATTR_BYTES MEM_INDEX_ENTRY_BYTES MEM_PER_ENTRY_TENTHS MEM_PER_ENTRY_AT_MOST_PREDICTED_4446 MEM_TOTAL_MIB"
FACT_KEYS="$CORPUS_KEYS $ATTR_KEYS $INDEX_KEYS $NODE_KEYS $MEM_KEYS"

ram_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null | tr -d '\r' | tail -1; }
disk_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1; }
pagefile_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_PageFileUsage).PeakUsage / 1)" 2>/dev/null | tr -d '\r' | tail -1; }

# Ключ ascii, `=`, одно слово; граница перед ключом обязательна; контроль — последнее вхождение.
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }
grab() { local f="$1" s="$2" k; for k in $3; do printf '%s_%s=%s\n' "$k" "$s" "$(val "$f" "$k")"; done; }
strip_run() { sed -E 's/_(r1|r2)=/=/g' "$1"; }

WORST_RC=0
run_to() { # $1=файл шага («-» = временный) $2=label; rest=команда
  local f="$1" label="$2" tmp=""; shift 2
  local rc
  if [ "$f" = "-" ]; then f=$(mktemp); tmp="$f"; fi
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$f" 2>&1; rc=$?
  cat "$f" | tee -a "$LOG"
  [ -n "$tmp" ] && rm -f "$tmp"
  echo "EXIT=$rc" | tee -a "$LOG"
  if [ "$rc" -gt "$WORST_RC" ]; then WORST_RC=$rc; fi
  return $rc
}

C1=$(mktemp); C2=$(mktemp); A1=$(mktemp); A2=$(mktemp)
I1=$(mktemp); I2=$(mktemp); N1=$(mktemp); N2=$(mktemp); M1=$(mktemp); M2=$(mktemp)
VER=$(mktemp); TXT=$(mktemp); F1=$(mktemp); F2=$(mktemp); CORP=$(mktemp)

{ echo
  echo "########## E-0100 · класс и направление интента · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "base_commit: 9687c32"
  echo "RAM_FREE_MB_BEFORE=$(ram_mb) DISK_FREE_MB_BEFORE=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb)"
} >> "$LOG"
BLOCK_START=$(wc -l < "$LOG")
block() { tail -n +"$((BLOCK_START + 1))" "$LOG"; }

# Шаг 0 — PRE_FIX: снимок снят в отдельном worktree на `9687c32` (там же запускался корпусный
# прибор). Helper не пересчитывает дыру, а сверяет отпечаток и печатает нули отсутствия.
{ echo "### ШАГ 0 PRE_FIX (дерево 9687c32, $PREFIX) ###"
  if [ -s "$PREFIX" ]; then
    cat "$PREFIX"
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — пороги (1)…(4) нечем сравнить"
  fi
} >> "$LOG"

DISK_BEFORE=$(disk_mb)
{ echo "### ШАГ 0а диск и RAM до замера ###"
  echo "DISK_FREE_MB=$DISK_BEFORE TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

run_to "$C1" "ШАГ 1а корпус без объявлений, n=1" cargo test -p vecdht-wire --test publish_corpus_digest --no-fail-fast -- --nocapture
echo "corpus1_exit=$(grep -oE 'EXIT=[0-9]+' "$LOG" | tail -1 | cut -d= -f2)" >> "$LOG"
run_to "$C2" "ШАГ 1б корпус без объявлений, n=2" cargo test -p vecdht-wire --test publish_corpus_digest --no-fail-fast -- --nocapture
echo "corpus2_exit=$(grep -oE 'EXIT=[0-9]+' "$LOG" | tail -1 | cut -d= -f2)" >> "$LOG"
grab "$C1" r1 "$CORPUS_KEYS" >> "$LOG"
grab "$C2" r2 "$CORPUS_KEYS" >> "$LOG"

run_to "$A1" "ШАГ 2а канонический TLV, n=1" cargo test -p vecdht-wire --test intent_attr_tlv --no-fail-fast -- --nocapture
run_to "$A2" "ШАГ 2б канонический TLV, n=2" cargo test -p vecdht-wire --test intent_attr_tlv --no-fail-fast -- --nocapture
grab "$A1" r1 "$ATTR_KEYS" >> "$LOG"
grab "$A2" r2 "$ATTR_KEYS" >> "$LOG"

run_to "$I1" "ШАГ 3а индекс: предикат, направление, снапшот, n=1" cargo test -p vecdht-index --lib --no-fail-fast -- --nocapture --test-threads=1
run_to "$I2" "ШАГ 3б индекс: то же, n=2" cargo test -p vecdht-index --lib --no-fail-fast -- --nocapture --test-threads=1
grab "$I1" r1 "$INDEX_KEYS" >> "$LOG"
grab "$I2" r2 "$INDEX_KEYS" >> "$LOG"

run_to "$N1" "ШАГ 4а узел: атрибут в индексе и фильтры Find, n=1" cargo test -p vecdht-node --test intent_class_filter --no-fail-fast -- --nocapture --test-threads=1
run_to "$N2" "ШАГ 4б узел: то же, n=2" cargo test -p vecdht-node --test intent_class_filter --no-fail-fast -- --nocapture --test-threads=1
grab "$N1" r1 "$NODE_KEYS" >> "$LOG"
grab "$N2" r2 "$NODE_KEYS" >> "$LOG"

run_to "$M1" "ШАГ 5а память 1M записей, n=1" cargo test -p vecdht-index --test memory_budget --no-fail-fast -- --nocapture
run_to "$M2" "ШАГ 5б память 1M записей, n=2" cargo test -p vecdht-index --test memory_budget --no-fail-fast -- --nocapture
grab "$M1" r1 "$MEM_KEYS" >> "$LOG"
grab "$M2" r2 "$MEM_KEYS" >> "$LOG"

# Вектор фактов n=1 против n=2: время и шаги сюда не попадают, только напечатанные ключи.
grab "$C1" r1 "$CORPUS_KEYS" > "$F1"; grab "$C2" r2 "$CORPUS_KEYS" > "$F2"
grab "$A1" r1 "$ATTR_KEYS" >> "$F1"; grab "$A2" r2 "$ATTR_KEYS" >> "$F2"
grab "$I1" r1 "$INDEX_KEYS" >> "$F1"; grab "$I2" r2 "$INDEX_KEYS" >> "$F2"
grab "$N1" r1 "$NODE_KEYS" >> "$F1"; grab "$N2" r2 "$NODE_KEYS" >> "$F2"
grab "$M1" r1 "$MEM_KEYS" >> "$F1"; grab "$M2" r2 "$MEM_KEYS" >> "$F2"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (1) инертность корпуса: pre=$(val "$PREFIX" PUBLISH_CORPUS_FNV1A64) post=$(val "$C1" PUBLISH_CORPUS_FNV1A64) same=$( [ "$(val "$PREFIX" PUBLISH_CORPUS_FNV1A64)" = "$(val "$C1" PUBLISH_CORPUS_FNV1A64)" ] && echo совпал || echo РАЗОШЁЛСЯ) расхождений=$( [ "$(val "$PREFIX" PUBLISH_CORPUS_FNV1A64)" = "$(val "$C1" PUBLISH_CORPUS_FNV1A64)" ] && echo 0 || echo 256)/$(val "$C1" PUBLISH_CORPUS_FRAMES)"
  echo "порог (2) канонизация: roundtrip=$(val "$A1" INTENT_ATTR_ROUNDTRIP) rejected=$(val "$A1" INTENT_ATTR_REJECTED) filter_roundtrip=$(val "$A1" INTENT_FILTER_ROUNDTRIP) filter_rejected=$(val "$A1" INTENT_FILTER_REJECTED)"
  echo "порог (3) предикат до усечения: onlypaid_top1=$(val "$I1" INDEX_PREDICATE_ONLYPAID_TOP1) dir_buy=$(val "$I1" INDEX_DIR_BUY) dir_sell=$(val "$I1" INDEX_DIR_SELL) dir_any=$(val "$I1" INDEX_DIR_ANY)"
  echo "порог (4) цена не хранится: arena_hits=$(val "$N1" NODE_PRICE_ARENA_HITS) file_hits=$(val "$N1" NODE_PRICE_FILE_HITS) index_entry_bytes=$(val "$N1" NODE_INDEX_ENTRY_BYTES)"
  echo "порог (5) память: slot_attr_bytes=$(val "$M1" MEM_SLOT_ATTR_BYTES) per_entry_tenths=$(val "$M1" MEM_PER_ENTRY_TENTHS) at_most_predicted=$(val "$M1" MEM_PER_ENTRY_AT_MOST_PREDICTED_4446) total_mib=$(val "$M1" MEM_TOTAL_MIB) delta_tenths=$(( $(val "$M1" MEM_PER_ENTRY_TENTHS) - $(val "$PREFIX" PRE_FIX_MEM_PER_ENTRY_TENTHS) ))"
  echo "MEM_DELTA_TENTHS=$(( $(val "$M1" MEM_PER_ENTRY_TENTHS) - $(val "$PREFIX" PRE_FIX_MEM_PER_ENTRY_TENTHS) ))"
  echo "MEM_PRE_PER_ENTRY_TENTHS=$(val "$PREFIX" PRE_FIX_MEM_PER_ENTRY_TENTHS) MEM_POST_PER_ENTRY_TENTHS=$(val "$M1" MEM_PER_ENTRY_TENTHS)"
  echo "порог (7) снапшот: format=$(val "$I1" SNAP_FORMAT) attr_roundtrip=$(val "$I1" SNAP_ATTR_ROUNDTRIP) format1_rejected=$(val "$I1" SNAP_FORMAT1_REJECTED)"
  echo "порог (9) вектор n=1 против n=2: $(cmp -s "$F1" "$F2" && echo совпал || echo РАЗОШЁЛСЯ)"
  echo "порог (11) ресурсы: disk_free_mb=$DISK_BEFORE disk_ok=$( [ "${DISK_BEFORE:-0}" -ge "$DISK_MIN" ] && echo 1 || echo 0) ram_free_mb=$(ram_mb) pagefile_peak_mb=$(pagefile_mb)"
  echo "порог (12) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c "$DIR_TAG")"
} >> "$LOG"

# Шаг 6 — регрессия воркспейса: cargo + clippy + Lean + Verus + Kani-компиляция и стражи.
run_to "$VER" "ШАГ 6 верификация воркспейса" bash lab/workspace-verify.sh E-0100

# Шаг 7 — стража текста по файлам цикла (пути переданы явно: после пре-регистрации `git diff
# HEAD~1..HEAD` указывал бы не на те файлы).
run_to "$TXT" "ШАГ 7 стража текста" bash lab/check-text-clean.sh \
  crates/vecdht-wire/src/messages.rs \
  crates/vecdht-wire/tests/intent_attr_tlv.rs \
  crates/vecdht-wire/tests/publish_corpus_digest.rs \
  crates/vecdht-index/src/ivf.rs \
  crates/vecdht-index/src/snapshot.rs \
  crates/vecdht-index/src/store.rs \
  crates/vecdht-index/src/entry.rs \
  crates/vecdht-index/tests/memory_budget.rs \
  crates/vecdht-node/src/node.rs \
  crates/vecdht-node/tests/intent_class_filter.rs \
  lab/expectations/e0100.tsv \
  lab/logs/e0100-prefix.txt \
  lab/experiments/E-0100-intent-class-and-direction.md \
  lab/hypotheses/H-0100-intent-class-and-direction-implementation.md

# Шаг 8 — сверка печатных фактов с замороженной таблицей. В корпус идут все файлы шагов и строки
# контроля: ключ ищется на границе токена, поэтому чужая строка ожидание не удовлетворит.
cat "$C1" "$C2" "$A1" "$A2" "$I1" "$I2" "$N1" "$N2" "$M1" "$M2" > "$CORP" 2>/dev/null || true
block >> "$CORP"
{ echo "### ШАГ 8 СВЕРКА: $EXPECT против напечатанных фактов ###"
  python lab/expect.py "$EXPECT" "$CORP"
  echo "СВЕРКА_EXIT=$?"
} >> "$LOG"

{ echo "МЕРЕНО после: RAM_FREE_MB=$(ram_mb) DISK_FREE_MB=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb) TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
  echo "########## E-0100 · конец блока ##########"
} >> "$LOG"

rm -f "$C1" "$C2" "$A1" "$A2" "$I1" "$I2" "$N1" "$N2" "$M1" "$M2" "$VER" "$TXT" "$F1" "$F2" "$CORP"
echo "=== E-0100 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"
