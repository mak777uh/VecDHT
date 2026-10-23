#!/usr/bin/env bash
# E-0085: §4.2 — лесенка отказов двери и три неизмеренные ветки живой двери (`left valid_from`,
# `capacity = 0`, отзыв), плюс правило суммы §9.2 и четыре факта отзыва в одном стенде.
#
# Цикл не правит продуктовый код, wire, крипто, спеку и чужие пороги: в репозитории два новых
# тестовых таргета (`crates/vecdht-crypto/tests/s42_cert_ladder.rs`,
# `crates/vecdht-net/tests/s53_door_branches.rs`), Lean-модель `lab/lean/VecDHT/CertLadder.lean`
# и этот helper.
#
# Пороги заморожены в пре-регистрации (`lab/hypotheses/H-0085-cert-ladder-and-live-door.md`) и в
# assert'ах оракулов; helper ничего из них не пересчитывает и не двигает — он снимает вектор
# `gate_*` и свёртки таблиц (`*_digest`, blake3), уже напечатанные оракулом.
#
# Единица цикла — имя отказа и факт, не время, поэтому правило 7 (запас против разброса) здесь
# не применяется; его роль исполняют воспроизводимость свёрток: (10) debug против release по
# каждому digest, (11) два вызова одного прогона против другого. Расхождение — ДИАГНОЗ, пороги не
# двигаются.
#
# Уроки, встроенные в метод: (а) экстрактор берёт значение сразу после `=` по ascii-подписи
# печати, границы гейтов в helper'е — строки, а не проза (ДИАГНОЗ-4 из `E-0082`); значения с
# пробелами оракул печатает токеном (`answer_token`), иначе число теряется на середине (это же
# место поправлено в этом цикле до пре-регистрационного коммита); (б) helper исполняет свою
# неизменяемую mktemp-копию (ДИАГНОЗ-6 из `e0079`), корень репо — через VEC_DHT_ROOT; (в) ресурсы
# — часть метода (указание владельца): свободные RAM и диск меряются до прогона, после каждого
# прогона и в ИТОГЕ, допуск ≥ 15 000 МБ диска и ≥ 4 000 МБ RAM, числа уходят в репозиторий вместе
# с логом, локальные черновики удаляются после коммита, `cargo clean` без объявления не делается.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0085-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0085-all.log"
BASE="${VEC_DHT_BASE:-bc6abbc}"

CSRC=crates/vecdht-crypto/tests/s42_cert_ladder.rs
NSRC=crates/vecdht-net/tests/s53_door_branches.rs
LEAN=lab/lean/VecDHT/CertLadder.lean

# Ключи криптового оракула: таблица лесенки, гистограмма видимости, маскирование отзыва, пробы
# «прямой вызов против провода», порядок `ZeroCapacity`.
CKEYS="ladder_rows ladder_names ladder_refusal_set ladder_ok ladder_revoked_rows
ladder_revoked_visible ladder_digest ladder_vis_0 ladder_vis_1 ladder_vis_2 ladder_vis_3
ladder_vis_4 ladder_vis_5 ladder_vis_6 ladder_vis_7 ladder_vis_8
gate2 gate3 gate4_probes gate4_control gate7 probe_rung_0_direct probe_rung_0_wire
probe_rung_3_direct probe_rung_3_wire probe_rung_7_direct probe_rung_7_wire
probe_rung_9_direct probe_rung_9_wire probe_control_direct probe_control_wire
zero_capacity_unsigned zero_capacity_signed collapse_names_same"

# Ключи сетевого оракула: живая дверь (один код на все причины), ветки `valid_from`,
# `capacity = 0`, правило суммы и пять фактов отзыва.
NKEYS="door_probes door_refused door_distinct_codes door_responder_logged door_digest
probe_version_code probe_genesis_code probe_capacity_zero_code probe_shards_65_code
probe_not_yet_valid_code probe_expired_code probe_below_threshold_code probe_sigs_17_code
probe_from_after_until_code probe_other_peer_id_code probe_agent_with_cert_code
gate5 gate6a_refused gate6b_hidden gate6b_responder_logged gate6c_answered gate6c_code
gate6d_stored notyet_digest
gate7_signed_code gate7_unsigned_code gate7_direct_name zerocap_digest
sum_rule_capacity sum_rule_load_per_shard sum_rule_shard7 sum_rule_shard9
sum_rule_over_single_shard_excluded gate8
revoke_handshake_done provider_seen_before provider_count_before gate9a_forgotten
victim_self_revoked_before_b gate9b_reset_send gate9b_reset_answer gate9b_reset_data
gate9b_reset_victim_auth gate9b gate9e_reason_local gate9e_form_distorted gate9e_new_send
gate9e_new_answer gate9e_new_data provider_count_after gate9c gate9d_send gate9d_gossip
gate9d_logged gate9d_refuses_handshake gate9a_refuser_silent revoke_digest"

# Вектор порогов (2)…(11) печатается блоком «ВЕКТОР ПОРОГОВ» и блоками сверки свёрток: имена
# строк там — подписи печати оракулов, поэтому расхождение helper'а с оракулом видно как пустое
# значение, а не как подмена числа.

WORST_RC=0

run_to() { # $1=файл шага («-» = временный, удаляется после tee) $2=label; rest=полная команда
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

free_ram_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null \
    | tr -d '\r' | tail -1
}

free_disk_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1
}

# Экстрактор по подписям печати: ключ ascii, за ним `=` и одно слово значения. Граница перед
# ключом обязательна: без неё `gate9b` матчился бы внутри `gate9b_reset_send` (тот же класс
# ошибки, что ДИАГНОЗ-4 в `E-0082`). `-f2-` оставляет значение целиком — имена отказов сами
# содержат `=` (`BelowThreshold(have=0)`).
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }

grab() { # $1=файл шага $2=суффикс прогона $3=список ключей
  local f="$1" s="$2" k
  for k in $3; do
    printf '%s_%s=%s\n' "$k" "$s" "$(val "$f" "$k")"
  done
}

get() { grep "^$1=" "$2" | head -1 | cut -d= -f2-; }

eq() { # $1=a $2=b → 1/0 побайтовое совпадение (свёртки таблиц)
  if [ -n "$1" ] && [ "$1" = "$2" ]; then echo 1; else echo 0; fi
}

check_nums() { # самопроверка экстракторов: пустое значение = потерянная транскрипция
  local pair v
  for pair in "$@"; do
    v=${pair#*=}
    [ -z "$v" ] && echo "ВНИМАНИЕ: экстрактор «${pair%%=*}» вернул пустоту — подпись печати сверять до пре-регистрации"
  done
}

{ echo "=== E-0085 прогон $(date +%FT%T%:z) — §4.2: лесенка отказов и живой двери три ветки ==="
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "gcc: $(gcc --version | head -1)"
  echo "cargo: $(cargo --version)"
  echo "lean: $(lean --version 2>/dev/null || echo нет)"
  echo "RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
  echo "ЯДЕР: $(nproc)"
  echo "RAM СВОБОДНО до прогона, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО до прогона, МБ: $(free_disk_mb)"
} | tee -a "$LOG"

# --- Допуск к прогону (техника безопасности, не порог замера) ---
DISK0=$(free_disk_mb)
RAM0=$(free_ram_mb)
{ echo "### ДОПУСК ### $(date +%FT%T%:z)"
  echo "диск $DISK0 МБ, RAM $RAM0 МБ"
} | tee -a "$LOG"
if [ "${DISK0:-0}" -lt 15000 ]; then
  { echo "### ДОПУСК: ОТКАЗ ### $(date +%FT%T%:z)"
    echo "свободного диска $DISK0 МБ < 15 000 МБ — прогон остановлен, объявить владельцу"
  } | tee -a "$LOG"
  exit 86
fi
if [ "${RAM0:-0}" -lt 4000 ]; then
  { echo "### ДОПУСК: ОТКАЗ ### $(date +%FT%T%:z)"
    echo "свободной RAM $RAM0 МБ < 4 000 МБ — прогон остановлен, объявить владельцу"
  } | tee -a "$LOG"
  exit 87
fi

# --- Порог (0): стоимость метода и нетронутость продукта ---
{ echo "### СТОИМОСТЬ ### $(date +%FT%T%:z)"
  echo "-- оракул 1/2 (лесенка): строк $(wc -l < "$CSRC"), тестов $(grep -c '#\[test\]' "$CSRC")"
  echo "-- оракул 2/2 (живая дверь): строк $(wc -l < "$NSRC"), тестов $(grep -c '#\[test\]' "$NSRC")"
  echo "-- продуктовый код (crates/*/src) и спека этим циклом не тронуты (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- crates/*/src docs/VecDHT-SPEC-v8.md
  echo "-- тронутые тесты:"
  git diff --stat "$BASE"..HEAD -- crates/*/tests
  echo "-- зависимостей добавлено не было (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- Cargo.toml Cargo.lock crates/*/Cargo.toml
  echo "-- константы, замороженные в исходниках оракулов:"
  grep -E '^const ' "$CSRC" | sed 's/^/   [крипто] /'
  grep -E '^const ' "$NSRC" | sed 's/^/   [сеть]   /'
} | tee -a "$LOG"

# --- Порог (14): Lean-модель ---
LEAN_FILE=$(mktemp)
LEAN_ERR=$(mktemp)
LEAN_RC=0
lean "$LEAN" >"$LEAN_FILE" 2>"$LEAN_ERR"; LEAN_RC=$?
{ echo "### LEAN (порог (14)) ### $(date +%FT%T%:z)"
  echo "LEAN_EXIT=$LEAN_RC"
  echo "ошибок в выводе: $(grep -c 'error' "$LEAN_ERR")"
  echo "теорем: $(grep -c '^theorem' "$LEAN")"
  echo "строк модели: $(wc -l < "$LEAN")"
  echo "sorry: $(grep -c 'sorry' "$LEAN")"
  echo "native_decide: $(grep -c 'native_decide' "$LEAN")"
  echo "-- вывод модели (обязан совпасть с числами криптового оракула):"
  sed 's/^/   /' "$LEAN_FILE"
  cat "$LEAN_ERR"
} | tee -a "$LOG"
echo "LEAN_ERR_LINES=$(wc -l < "$LEAN_ERR")" | tee -a "$LOG"

# --- Порог (0): сборка и clippy обоих таргетов в release ---
BUILD_T0=$(date +%s%N)
run_to - "RELEASE BUILD --no-run (крипто)" cargo test -j 2 --release -p vecdht-crypto --test s42_cert_ladder --no-run
run_to - "RELEASE BUILD --no-run (сеть)" cargo test -j 2 --release -p vecdht-net --test s53_door_branches --no-run
BUILD_T1=$(date +%s%N)
echo "BUILD_MS=$(( (BUILD_T1 - BUILD_T0) / 1000000 ))" | tee -a "$LOG"
run_to - "CLIPPY vecdht-crypto --all-targets -D warnings" \
  cargo clippy -j 2 --release -p vecdht-crypto --all-targets -- -D warnings
run_to - "CLIPPY vecdht-net --all-targets -D warnings" \
  cargo clippy -j 2 --release -p vecdht-net --all-targets -- -D warnings

CEXE=$(ls -t target/release/deps/s42_cert_ladder-*.exe 2>/dev/null | head -1)
NEXE=$(ls -t target/release/deps/s53_door_branches-*.exe 2>/dev/null | head -1)
{ echo "### БИНАРИ ### $(date +%FT%T%:z)"
  echo "крипто: $CEXE  sha256=$(sha256sum "$CEXE" 2>/dev/null | cut -d' ' -f1)"
  echo "сеть:   $NEXE  sha256=$(sha256sum "$NEXE" 2>/dev/null | cut -d' ' -f1)"
} | tee -a "$LOG"

C1=$(mktemp); C2=$(mktemp); C3=$(mktemp)
N1=$(mktemp); N2=$(mktemp); N3=$(mktemp)
G1=$(mktemp); G2=$(mktemp); G3=$(mktemp)

DIGESTS="ladder_digest door_digest notyet_digest zerocap_digest revoke_digest"

# --- Release: прогон 1 и прогон 2 одного бинаря (пороги (1)…(9), (11)) ---
R1T0=$(date +%s%N)
run_to "$C1" "ORACLE 1/2 (крипто) RELEASE RUN 1" \
  cargo test --release -p vecdht-crypto --test s42_cert_ladder -- --nocapture --test-threads=1
run_to "$N1" "ORACLE 2/2 (сеть) RELEASE RUN 1" \
  cargo test --release -p vecdht-net --test s53_door_branches -- --nocapture --test-threads=1
R1T1=$(date +%s%N)
{ echo "### ЧИСЛА ПРОГОНА 1 (release) ### $(date +%FT%T%:z)"
  echo "строк таблицы лесенки в шаге: $(grep -c 'МЕРЕНО ladder_row ' "$C1")"
  grab "$C1" 1 "$CKEYS"
  grab "$N1" 1 "$NKEYS"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших каталогов vecdht-s53-* в %TEMP%: $(ls -d "$TEMP"/vecdht-s53-* 2>/dev/null | wc -l)"
} > "$G1"
cat "$G1" | tee -a "$LOG"

R2T0=$(date +%s%N)
run_to "$C2" "ORACLE 1/2 (крипто) RELEASE RUN 2 (тот же бинарь, воспроизводимость)" \
  cargo test --release -p vecdht-crypto --test s42_cert_ladder -- --nocapture --test-threads=1
run_to "$N2" "ORACLE 2/2 (сеть) RELEASE RUN 2 (тот же бинарь, воспроизводимость)" \
  cargo test --release -p vecdht-net --test s53_door_branches -- --nocapture --test-threads=1
R2T1=$(date +%s%N)
{ echo "### ЧИСЛА ПРОГОНА 2 (release, воспроизводимость) ### $(date +%FT%T%:z)"
  echo "строк таблицы лесенки в шаге: $(grep -c 'МЕРЕНО ladder_row ' "$C2")"
  grab "$C2" 2 "$CKEYS"
  grab "$N2" 2 "$NKEYS"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших каталогов vecdht-s53-* в %TEMP%: $(ls -d "$TEMP"/vecdht-s53-* 2>/dev/null | wc -l)"
} > "$G2"
{ echo "-- ПОРОГ (11): свёртки таблиц двух release-прогонов (1 = совпали побайтово):"
  for k in $DIGESTS; do
    echo "   gate11_$k=$(eq "$(get "${k}_1" "$G1")" "$(get "${k}_2" "$G2")")"
  done
  echo "-- расхождения всего вектора чисел между прогонами (пусто = совпало всё):"
  for k in $CKEYS $NKEYS; do
    a=$(get "${k}_1" "$G1"); b=$(get "${k}_2" "$G2")
    [ "$a" != "$b" ] && echo "   расхождение $k: n=1 «$a» n=2 «$b»"
  done
  echo "   (пусто выше = расхождений нет)"
  check_nums "ladder_rows=$(get ladder_rows_2 "$G2")" "ladder_names=$(get ladder_names_2 "$G2")" \
             "ladder_digest=$(get ladder_digest_2 "$G2")" "door_digest=$(get door_digest_2 "$G2")" \
             "revoke_digest=$(get revoke_digest_2 "$G2")" "gate8=$(get gate8_2 "$G2")" \
             "gate5=$(get gate5_2 "$G2")" "gate9b=$(get gate9b_2 "$G2")" "gate9c=$(get gate9c_2 "$G2")"
} | tee -a "$LOG"
echo "RUST_MS_1=$(( (R1T1 - R1T0) / 1000000 )) RUST_MS_2=$(( (R2T1 - R2T0) / 1000000 ))" | tee -a "$LOG"

# --- Порог (12): КОНТРОЛЬ — юнит-тесты тех же крейтов в том же профиле ---
run_to - "КОНТРОЛЬ --release -p vecdht-crypto --lib" cargo test -j 2 --release -p vecdht-crypto --lib
run_to - "КОНТРОЛЬ --release -p vecdht-net --lib" cargo test -j 2 --release -p vecdht-net --lib

# --- Debug: тот же вектор фактов в другом профиле (пороги (1), (10)) ---
run_to "$C3" "ORACLE 1/2 (крипто) DEBUG" \
  cargo test -p vecdht-crypto --test s42_cert_ladder -- --nocapture --test-threads=1
run_to "$N3" "ORACLE 2/2 (сеть) DEBUG" \
  cargo test -p vecdht-net --test s53_door_branches -- --nocapture --test-threads=1
{ echo "### DEBUG ЧИСЛА ### $(date +%FT%T%:z)"
  echo "строк таблицы лесенки в шаге: $(grep -c 'МЕРЕНО ladder_row ' "$C3")"
  grab "$C3" 3 "$CKEYS"
  grab "$N3" 3 "$NKEYS"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
} > "$G3"
{ echo "-- ПОРОГ (10): свёртки таблиц debug против release (1 = совпали побайтово):"
  for k in $DIGESTS; do
    echo "   gate10_$k=$(eq "$(get "${k}_3" "$G3")" "$(get "${k}_2" "$G2")")"
  done
  echo "-- расхождения всего вектора чисел между профилями (пусто = совпало всё):"
  for k in $CKEYS $NKEYS; do
    a=$(get "${k}_3" "$G3"); b=$(get "${k}_2" "$G2")
    [ "$a" != "$b" ] && echo "   расхождение $k: debug «$a» release «$b»"
  done
  echo "   (пусто выше = расхождений нет)"
  echo "-- структурные свёртки debug (печать, не assert — правило 6 про время здесь не при чём):"
  for k in gate2 gate3 gate4_probes gate5 gate8 gate9b gate9c; do
    echo "   ${k}: debug=$(get "${k}_3" "$G3") release=$(get "${k}_2" "$G2")"
  done
} | tee -a "$LOG"
cat "$G3" | tee -a "$LOG"

# --- Вектор порогов (2)…(9): то, что обязан напечатать оракул (release, n=2 — решающий) ---
{ echo "### ВЕКТОР ПОРОГОВ (release n=2) ### $(date +%FT%T%:z)"
  echo "   gate2  (512 строк, 8 имён, гистограмма 2^(8−k), Ok=1): rows=$(get ladder_rows_2 "$G2") names=$(get ladder_names_2 "$G2") ok=$(get ladder_ok_2 "$G2") vis=$(get ladder_vis_0_2 "$G2")/$(get ladder_vis_1_2 "$G2")/$(get ladder_vis_2_2 "$G2")/$(get ladder_vis_3_2 "$G2")/$(get ladder_vis_4_2 "$G2")/$(get ladder_vis_5_2 "$G2")/$(get ladder_vis_6_2 "$G2")/$(get ladder_vis_7_2 "$G2")/$(get ladder_vis_8_2 "$G2") → $(get gate2_2 "$G2")"
  echo "        таблица имён: $(get ladder_refusal_set_2 "$G2")"
  echo "   gate3  (Revoked виден в 4 из 256): rows=$(get ladder_revoked_rows_2 "$G2") visible=$(get ladder_revoked_visible_2 "$G2") → $(get gate3_2 "$G2")"
  echo "   gate4  (4 расхождения + контроль): probes=$(get gate4_probes_2 "$G2") control=$(get gate4_control_2 "$G2")"
  echo "   gate5  (11 причин — один код, отказавший молчит): probes=$(get door_probes_2 "$G2") refused=$(get door_refused_2 "$G2") distinct=$(get door_distinct_codes_2 "$G2") responder_logged=$(get door_responder_logged_2 "$G2") → $(get gate5_2 "$G2")"
  echo "   gate6a..d (ветка valid_from): refused=$(get gate6a_refused_2 "$G2") hidden=$(get gate6b_hidden_2 "$G2") responder_logged=$(get gate6b_responder_logged_2 "$G2") answered=$(get gate6c_answered_2 "$G2") code=$(get gate6c_code_2 "$G2") stored=$(get gate6d_stored_2 "$G2")"
  echo "   gate7  (ZeroCapacity до порога, подписанный и нет): unsigned=$(get zero_capacity_unsigned_2 "$G2") signed=$(get zero_capacity_signed_2 "$G2") door=$(get gate7_signed_code_2 "$G2")/$(get gate7_unsigned_code_2 "$G2") direct=$(get gate7_direct_name_2 "$G2") → $(get gate7_2 "$G2")"
  echo "   gate8  (правило суммы не реализовано): capacity=$(get sum_rule_capacity_2 "$G2") load=$(get sum_rule_load_per_shard_2 "$G2") shard7=$(get sum_rule_shard7_2 "$G2") shard9=$(get sum_rule_shard9_2 "$G2") excluded=$(get sum_rule_over_single_shard_excluded_2 "$G2") → $(get gate8_2 "$G2")"
  echo "   gate9a (отказавший молчит, носитель забыт): forgotten=$(get gate9a_forgotten_2 "$G2") refuser_silent=$(get gate9a_refuser_silent_2 "$G2")"
  echo "   gate9b (соединение сброшено, данных нет, таблица носителя не знает): send=$(get gate9b_reset_send_2 "$G2") answer=$(get gate9b_reset_answer_2 "$G2") data=$(get gate9b_reset_data_2 "$G2") victim_auth=$(get gate9b_reset_victim_auth_2 "$G2") → $(get gate9b_2 "$G2")"
  echo "   gate9c (provider_peers не сократился): before=$(get provider_count_before_2 "$G2") after=$(get provider_count_after_2 "$G2") → $(get gate9c_2 "$G2")"
  echo "   gate9d (отозванный замолчал и не аутентифицирует): send=$(get gate9d_send_2 "$G2") gossip=$(get gate9d_gossip_2 "$G2") logged=$(get gate9d_logged_2 "$G2") handshake=$(get gate9d_refuses_handshake_2 "$G2")"
  echo "   gate9e (форма отказа искажена, причина локальна): reason_local=$(get gate9e_reason_local_2 "$G2") distorted=$(get gate9e_form_distorted_2 "$G2") new_answer=$(get gate9e_new_answer_2 "$G2") new_data=$(get gate9e_new_data_2 "$G2")"
  echo "   свёртки: $(for k in $DIGESTS; do printf '%s=%s ' "$k" "$(get "${k}_2" "$G2")"; done)"
} | tee -a "$LOG"

# --- СООТВЕТСТВИЕ Lean ↔ Rust (порог (14), репорт) ---
{ echo "### СООТВЕТСТВИЕ LEAN ↔ RUST ### $(date +%FT%T%:z)"
  echo "   Lean гистограмма (1-я строка вывода модели): $(sed -n '1p' "$LEAN_FILE")"
  echo "   Rust гистограмма: [$(get ladder_vis_0_2 "$G2"), $(get ladder_vis_1_2 "$G2"), $(get ladder_vis_2_2 "$G2"), $(get ladder_vis_3_2 "$G2"), $(get ladder_vis_4_2 "$G2"), $(get ladder_vis_5_2 "$G2"), $(get ladder_vis_6_2 "$G2"), $(get ladder_vis_7_2 "$G2"), $(get ladder_vis_8_2 "$G2")]"
  echo "   Lean векторы видимого отзыва (2-я строка): $(sed -n '2p' "$LEAN_FILE")  → Rust: visible=$(get ladder_revoked_visible_2 "$G2") из rows=$(get ladder_revoked_rows_2 "$G2")"
  echo "   Lean имена ступеней, индексы (3-я строка): $(sed -n '3p' "$LEAN_FILE")"
  echo "   Rust: различных имён $(get ladder_names_2 "$G2") — таблица $(get ladder_refusal_set_2 "$G2")"
} | tee -a "$LOG"

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "осевших каталогов vecdht-s53-* в %TEMP% (порог (13) требует 0): $(ls -d "$TEMP"/vecdht-s53-* 2>/dev/null | wc -l)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали)"
} | tee -a "$LOG"
rm -f "$C1" "$C2" "$C3" "$N1" "$N2" "$N3" "$G1" "$G2" "$G3" "$LEAN_FILE" "$LEAN_ERR"
exit "$WORST_RC"
