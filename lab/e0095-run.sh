#!/usr/bin/env bash
# E-0095: релиз-блокер (4), часть B — наблюдаемая причина отказа двери (§4.2:181, §14.4 (ii):1250,
# Приложение C:1947 `admit_drops_total{reason}`, ADR-0051). Единица цикла — факт и число (сколько
# проб отказано, сколько РАЗЛИЧНЫХ кодов и кадров на проводе, сколько записей с именем причины
# осталось у сторон, сколько имён живёт в локальном счётчике), не время: временнóго предсказания в
# пороге нет.
#
# Пороги заморожены в `lab/hypotheses/H-0095-door-refusal-reason-observable.md` и в assert'ах двух
# оракулов. Helper ничего из них не пересчитывает: снимает напечатанные ключи `dr_*` и `dc_*`,
# сверяет вектор между прогонами и проверяет ожидания таблицей `lab/expectations/e0095.tsv`
# (`python lab/expect.py`).
#
# Два оракула, а не один, потому что у цикла два contradictory требования: показать дыру числом на
# дереве ДО фикса и остаться зелёным ПОСЛЕ него (гейт (8) совместимости). Файл
# `door_reason_observable.rs` не зовёт ничего, чего до фикса нет, и обязан быть зелёным на обоих
# деревьях; `door_reason_counters.rs` зовёт `door_refusals()` и до правки не компилируется — это
# отсутствие интерфейса, а не красный по построению тест (слово метода из `E-0094`).
#
# Встроенные уроки метода:
#  (а) helper исполняет свою неизменяемую mktemp-копию, корень репо — через VEC_DHT_ROOT;
#  (б) ресурсы меряются до сборки, после каждого прогона и в ИТОГЕ, метки — ASCII; pagefile обязано
#      быть в тройке чисел: свободный диск — производная от давления на RAM (ДИАГНОЗ-2 из `E-0088`);
#  (в) регрессия идёт с `--no-fail-fast` ДО `--` (ДИАГНОЗ-2 из `E-0087`);
#  (г) контроль append-only лога берётся `tail -1` от отметки начала блока (ДИАГНОЗ-3 из `E-0087`);
#  (д) векторы прогонов сравниваются БЕЗ колонок времени и без счётчиков шагов: `dr_g2_steps` на
#      двух прогонах одного дерева дал 3 и 5, поэтому он печатается как цена, но в вектор не входит
#      (правило 7 (е), ДИАГНОЗ из `E-0091`);
#  (е) осевшие каталоги считаются после прогона (ДИАГНОЗ-2 из `E-0085`);
#  (ж) `cargo clean` не исполняется, свободный диск меряется до замера;
#  (з) ожидания живут файлом и сверяются исполнением, а не памятью (правило (к) п. 8в);
#  (и) счётчик под гейтом «ничего не изменилось» обязан иметь классификацию: `dr_frame_digest` и
#      `dc_frame_digest` сравниваются между ДВУМЯ файлами, чтобы общий корпус не мог разъехаться
#      незамеченным (правило (о) п. 8в).
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0095-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0095-all.log"
PREFIX="lab/logs/e0095-oracle-before-fix.txt"
WITNESS=crates/vecdht-net/tests/door_reason_observable.rs
COUNTERS=crates/vecdht-net/tests/door_reason_counters.rs
EXPECT="lab/expectations/e0095.tsv"
DISK_MIN=15000
DIR_TAG=vecdht-e0095
mkdir -p lab/logs

# Ключи свидетеля дыры (оба дерева обязаны дать одни и те же значения — гейт (5) и (8)) и ключи
# счётчика причин (они появляются вместе с фиксом).
DR_KEYS="dr_control_refused dr_probes dr_refused dr_silent dr_distinct_codes
dr_distinct_refusal_frames dr_certinvalid_family dr_probes_with_named_cause
dr_responder_named dr_initiator_named dr_responder_tail_named dr_frame_digest
dr_g2_revocation_count dr_g2_knows dr_g2_revoked_code dr_g2_expired_code
dr_g2_bytes_equal dr_g2_frame_len dr_g2_responder_records dr_g2_responder_named
dr_g2_revoked_named dr_g2_expired_named
dr_g3_inbox_frames dr_g3_error_frames dr_g3_door_authenticated dr_g3_self_revoked
dr_g3_has_own_parse dr_g3_names_expiry dr_g3_healthy_control dr_g1"

DC_KEYS="dc_names_total dc_names_distinct dc_names_sorted_unique dc_corpus_refusals
dc_corpus_entries dc_unspecified_hits dc_sum_equals_refusals dc_probe_delta_ok
dc_collision_sigs_over_name dc_collision_time_order_name dc_below_threshold_count
dc_not_yet_valid_count dc_three_actions_distinct dc_revoked_name dc_expired_name
dc_revoked_counter dc_after_repeats_entries dc_after_repeats_total dc_max_name_len
dc_responder_errors_empty dc_wire_codes dc_frame_digest dc_zero_names
dc_self_cert_revoked_hits dc_shard_not_covered_hits dc_transport_no_owner_hits
dc_unreachable_names dc_decoder_absorbed_probes"

FACT_KEYS="$DR_KEYS $DC_KEYS"

ram_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null | tr -d '\r' | tail -1; }
disk_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1; }
pagefile_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_PageFileUsage).PeakUsage / 1)" 2>/dev/null | tr -d '\r' | tail -1; }

# Экстрактор по подписям печати: ключ ascii, за ним `=`, одно слово значения; граница перед ключом
# обязательна, контроль append-only берётся последним вхождением.
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

W1=$(mktemp); W2=$(mktemp); C1=$(mktemp); C2=$(mktemp)
REGN=$(mktemp); REGD=$(mktemp); F1=$(mktemp); F2=$(mktemp)
{ echo
  echo "########## E-0095 · наблюдаемая причина отказа двери · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "witness: $WITNESS"
  echo "counters: $COUNTERS"
  echo "RAM_FREE_MB_BEFORE=$(ram_mb) DISK_FREE_MB_BEFORE=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb)"
} >> "$LOG"
# Нумерация строк на старте блока: контроль и сверка читают ТОЛЬКО текущий блок, иначе ожидание
# мог бы удовлетворить факт из прошлого прогона (append-only, ДИАГНОЗ-3 из `E-0087`).
BLOCK_START=$(wc -l < "$LOG")
block() { tail -n +"$((BLOCK_START + 1))" "$LOG"; }

# Шаг 0 — предсказание на дереве ДО правки: снимок лежит в репозитории (append-only), helper только
# контролирует, что дыра в нём напечатана числом, а не молчанием.
{ echo "### ШАГ 0 PRE_FIX (дерево до правки, $PREFIX) ###"
  if [ -s "$PREFIX" ]; then
    echo "prefix_test_result=$(grep -E 'test result' "$PREFIX" | tail -1)"
    echo "prefix_exit=$(val "$PREFIX" EXIT)"
    echo "prefix_refused=$(val "$PREFIX" dr_refused)"
    echo "prefix_silent=$(val "$PREFIX" dr_silent)"
    echo "prefix_codes=$(val "$PREFIX" dr_distinct_codes)"
    echo "prefix_certinvalid=$(val "$PREFIX" dr_certinvalid_family)"
    echo "prefix_named_over=$(val "$PREFIX" dr_probes_with_named_cause)"
    echo "prefix_responder_named=$(val "$PREFIX" dr_responder_named)"
    echo "prefix_initiator_named=$(val "$PREFIX" dr_initiator_named)"
    echo "prefix_digest=$(val "$PREFIX" dr_frame_digest)"
    echo "prefix_g3_names_expiry=$(val "$PREFIX" dr_g3_names_expiry)"
    echo "prefix_g3_healthy=$(val "$PREFIX" dr_g3_healthy_control)"
    echo "prefix_counters_exists=$( [ -s "$COUNTERS" ] && echo 1 || echo 0)"
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — порог (1) не может быть проверен"
  fi
} >> "$LOG"

# Диск меряется ДО замера: цикл не вправе начинать сборку, если допуск не выполнен.
DISK_BEFORE=$(disk_mb)
{ echo "### ШАГ 0а диск и RAM до замера ###"
  echo "DISK_FREE_MB=$DISK_BEFORE TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

run_to "$W1" "ШАГ 1а свидетель дыры, прогон n=1" cargo test -p vecdht-net --test door_reason_observable --no-fail-fast -- --nocapture --test-threads=1
echo "witness1_exit=$?" >> "$LOG"
{ echo "### ВЕКТОР СВИДЕТЕЛЯ n=1 ###"; grab "$W1" r1 "$DR_KEYS"; } >> "$LOG"

run_to "$W2" "ШАГ 1б свидетель дыры, прогон n=2" cargo test -p vecdht-net --test door_reason_observable --no-fail-fast -- --nocapture --test-threads=1
echo "witness2_exit=$?" >> "$LOG"
{ echo "### ВЕКТОР СВИДЕТЕЛЯ n=2 ###"; grab "$W2" r2 "$DR_KEYS"; } >> "$LOG"

run_to "$C1" "ШАГ 2а счётчик причин, прогон n=1" cargo test -p vecdht-net --test door_reason_counters --no-fail-fast -- --nocapture --test-threads=1
echo "run1_exit=$?" >> "$LOG"
{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$C1" r1 "$DC_KEYS"; } >> "$LOG"

run_to "$C2" "ШАГ 2б счётчик причин, прогон n=2 (порог (9): вектор обязан совпасть)" cargo test -p vecdht-net --test door_reason_counters --no-fail-fast -- --nocapture --test-threads=1
echo "run2_exit=$?" >> "$LOG"
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$C2" r2 "$DC_KEYS"; } >> "$LOG"

grab "$W1" r1 "$DR_KEYS" > "$F1"
grab "$W2" r2 "$DR_KEYS" > "$F2"
grab "$C1" r1 "$DC_KEYS" >> "$F1"
grab "$C2" r2 "$DC_KEYS" >> "$F2"

# Шаг 3 — регрессия по соседям (порог (10)): `vecdht-net` целиком (там стенды двери `E-0085`,
# parity gossip `E-0087`, переживаемость отзыва `E-0094` — фикс добавляет им новый модуль и поля в
# сервис) и `vecdht-node` (там `NetConfig` и тесты узла).
run_to "$REGD" "ШАГ 3а регрессия: vecdht-node (--no-fail-fast)" cargo test -p vecdht-node --no-fail-fast
run_to "$REGN" "ШАГ 3б регрессия: vecdht-net (--no-fail-fast)" cargo test -p vecdht-net --no-fail-fast

{ echo "### РЕГРЕССИЯ ###"
  grep -E "^test result|^error" "$REGN" | tail -40
  echo "reg_net_failed=$(grep -oE '[0-9]+ failed' "$REGN" | awk '{s+=$1} END {print s+0}')"
  echo "reg_net_passed=$(grep -oE '[0-9]+ passed' "$REGN" | awk '{s+=$1} END {print s+0}')"
  echo "reg_net_ignored=$(grep -oE '[0-9]+ ignored' "$REGN" | awk '{s+=$1} END {print s+0}')"
} >> "$LOG"
echo "reg_node_failed=$(grep -oE '[0-9]+ failed' "$REGD" | awk '{s+=$1} END {print s+0}')" >> "$LOG"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (1) дыра до правки: prefix_exit=$(val "$PREFIX" EXIT) dr_refused=$(val "$PREFIX" dr_refused) dr_distinct_codes=$(val "$PREFIX" dr_distinct_codes) dr_responder_named=$(val "$PREFIX" dr_responder_named) dr_initiator_named=$(val "$PREFIX" dr_initiator_named)"
  echo "порог (5)(8) провод и записи не изменились: witness1=$(grep -E 'test result' "$W1" | tail -1) | witness2=$(grep -E 'test result' "$W2" | tail -1)"
  echo "порог (5) digest одного корпуса в двух файлах: dr=$(val "$W1" dr_frame_digest) dc=$(val "$C1" dc_frame_digest) same=$( [ "$(val "$W1" dr_frame_digest)" = "$(val "$C1" dc_frame_digest)" ] && echo совпал || echo РАЗОШЁЛСЯ)"
  echo "порог (2)…(7) оракул счётчика зелёный: n1=$(grep -E 'test result' "$C1" | tail -1) | n2=$(grep -E 'test result' "$C2" | tail -1)"
  echo "порог (9) repro_вектор=$(cmp -s <(strip_run "$F1") <(strip_run "$F2") && echo совпал || echo РАЗОШЁЛСЯ)"
  echo "порог (10) регрессия: reg_node_failed=$(grep -oE '[0-9]+ failed' "$REGD" | awk '{s+=$1} END {print s+0}') reg_net_failed=$(grep -oE '[0-9]+ failed' "$REGN" | awk '{s+=$1} END {print s+0}') ignored=$(grep -oE '[0-9]+ ignored' "$REGN" | awk '{s+=$1} END {print s+0}')"
  echo "порог (12) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c "$DIR_TAG") disk_ok=$( [ "${DISK_BEFORE:-0}" -ge "$DISK_MIN" ] && echo 1 || echo 0)"
  echo "порог (13) contour=$(python lab/library.py value --cycles 5 2>/dev/null | grep LIBVALUE | tail -1)"
} >> "$LOG"

# Шаг 4 — сверка печатных фактов с замороженной таблицей. В корпус идут оба вывода обоих оракулов
# и строки контроля helper'а: ключ ищется токеном, поэтому чужая строка ожидание не удовлетворит.
CORP=$(mktemp)
cat "$W1" "$W2" "$C1" "$C2" > "$CORP" 2>/dev/null || true
block >> "$CORP"
{ echo "### ШАГ 4 СВЕРКА: $EXPECT против напечатанных фактов ###"
  python lab/expect.py "$EXPECT" "$CORP"
  echo "СВЕРКА_EXIT=$?"
} >> "$LOG"

{ echo "МЕРЕНО после: RAM_FREE_MB=$(ram_mb) DISK_FREE_MB=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb) TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
  echo "########## E-0095 · конец блока ##########"
} >> "$LOG"

rm -f "$W1" "$W2" "$C1" "$C2" "$REGN" "$REGD" "$F1" "$F2" "$CORP"
echo "=== E-0095 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"
