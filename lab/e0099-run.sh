#!/usr/bin/env bash
# E-0099 (`H-0099`, слово владельца от 2026-10-24 про формальные конвейеры): три независимых
# прибора доказывают утверждения о продукте, и каждый из них обязан (а) исполняться и печатать
# числа, (б) краснеть на посаженном дефекте, (в) не притворяться зелёным, когда тулчейна нет.
#
# Единица цикла — факт и число, а не время: `VERUS_MS` и `LEAN_MS_TOTAL` печатаются как цена,
# гейт на них не ставится (правило: цена прогона не является вердиктом).
#
# Пороги заморожены в `lab/hypotheses/H-0099-formal-pipelines-in-use.md` и читаются таблицей
# `lab/expectations/e0099.tsv` через `python lab/expect.py`. Helper ничего из них не пересчитывает.
#
# Встроенные уроки метода:
#  (а) helper исполняет свою неизменяемую mktemp-копию, корень репо — через VEC_DHT_ROOT;
#  (б) ресурсы меряются до сборки и в ИТОГЕ тремя числами (диск, RAM, pagefile), метки — ASCII;
#  (в) векторы двух прогонов сравниваются БЕЗ колонок времени (ДИАГНОЗ-6 из `E-0093`);
#  (г) контроль append-only лога берётся `tail -1`, блок нумеруется от старта (ДИАГНОЗ-3 из `E-0087`);
#  (д) `cargo clean` не исполняется; гейт (9) по диску обязан напечататься числом до замера;
#  (е) каждый ключ порога инвариантен к расписанию шагов (ДИАГНОЗ из `E-0091`): здесь все ключи —
#      коды возврата, счётчики приборов и булевы метки, ни одного счётчика доставки кадров;
#  (ж) прибор без тулчейна обязан отличать SKIP от OK — это отдельный шаг с подставным путём, а не
#      рассуждение; на этом хосте Kani не ставится вовсе, и helper обязан сказать это числом
#      (`KANI_LOCAL=нет`), а не промолчать;
#  (з) CI-числа не извлекаются из памяти: шаг 8 берёт их из API и пишет в журнал, только когда
#      включён `VEC_DHT_CI_POLL=1` (иначе офлайн-прогон был бы красным по причине сети).
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0099-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0099-all.log"
PREFIX="lab/logs/e0099-prefix.txt"
EXPECT="lab/expectations/e0099.tsv"
DISK_MIN=15000

ram_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null | tr -d '\r' | tail -1; }
disk_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1; }
pagefile_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_PageFileUsage).PeakUsage / 1)" 2>/dev/null | tr -d '\r' | tail -1; }
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }

mkdir -p lab/logs
{ echo
  echo "########## E-0099 · формальные конвейеры в работе · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "verus_bin: ${VEC_DHT_VERUS:-по_умолчанию_в_приборе}"
  echo "kani_local: $(command -v cargo-kani >/dev/null 2>&1 && echo есть || echo нет)"
  echo "lean_local: $( { command -v lean >/dev/null 2>&1 || [ -x /c/Users/Admin/.elan/bin/lean ]; } && echo есть || echo нет)"
  echo "RAM_FREE_MB_BEFORE=$(ram_mb) DISK_FREE_MB_BEFORE=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb)"
} >> "$LOG"
BLOCK_START=$(wc -l < "$LOG")
block() { tail -n +"$((BLOCK_START + 1))" "$LOG"; }

# Шаг 0 — PRE_FIX: на дереве до правки в журналном контуре нет ни одного числа Verus, предпосылка
# переполнения капа не названа в коде, и каталог `.github/workflows` пуст. Снимается grep'ом по
# append-only журналам и по продукту на дереве base_commit; печать идёт в stdout, чтобы снимок
# можно было переложить в $PREFIX и больше к нему не возвращаться.
if [ -n "${VEC_DHT_PREFIX_SHOOT:-}" ]; then
  echo "### ШАГ 0 PRE_FIX (дерево $(git rev-parse --short HEAD), снят по VEC_DHT_PREFIX_SHOOT) ###"
  echo "prefix_verus_log_files=$(grep -rlE 'VERUS_TOTAL|VERUS_VERIFIED' lab/logs 2>/dev/null | wc -l)"
  echo "prefix_cell_cap_max_live=$(grep -c 'CELL_CAP_MAX_LIVE' crates/vecdht-node/src/admission.rs)"
  echo "prefix_verus_check_script=$( [ -f lab/verus-check.sh ] && echo есть || echo нет)"
  echo "prefix_kani_check_script=$( [ -f lab/kani-compile-check.sh ] && echo есть || echo нет)"
  echo "prefix_workflows=$(ls .github/workflows 2>/dev/null | wc -l)"
  echo "prefix_ci_workflows_total=$(curl -s --max-time 30 'https://api.github.com/repos/mak777uh/VecDHT/actions/workflows' | python -c 'import json,sys;print(json.load(sys.stdin).get("total_count"))' 2>/dev/null)"
  echo "prefix_ci_runs_total=$(curl -s --max-time 30 'https://api.github.com/repos/mak777uh/VecDHT/actions/runs' | python -c 'import json,sys;print(json.load(sys.stdin).get("total_count"))' 2>/dev/null)"
  exit 0
fi

{ echo "### ШАГ 0 PRE_FIX из $PREFIX ###"
  if [ -s "$PREFIX" ]; then
    grep -E '^prefix_' "$PREFIX" | tail -12
  else
    echo "prefix_ОТСУТСТВУЕТ=1 — пороги (11)…(12) не могут быть проверены"
  fi
} >> "$LOG"

DISK_BEFORE=$(disk_mb)
{ echo "### ШАГ 0а диск и RAM до замера ###"
  echo "DISK_FREE_MB=$DISK_BEFORE TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

V1=$(mktemp); V2=$(mktemp); VS=$(mktemp); KC=$(mktemp); KS=$(mktemp)
LC=$(mktemp); LS=$(mktemp); REQ=$(mktemp); SKP=$(mktemp); REGT=$(mktemp); REGC=$(mktemp)
CORP=$(mktemp); F1=$(mktemp); F2=$(mktemp); CIJ=$(mktemp)
cleanup() { rm -f "$V1" "$V2" "$VS" "$KC" "$KS" "$LC" "$LS" "$REQ" "$SKP" "$REGT" "$REGC" "$CORP" "$F1" "$F2" "$CIJ"; }
trap cleanup EXIT

run_to() { # $1=файл $2=метка; rest=команда
  local f="$1" label="$2"; shift 2
  local rc
  echo "### $label ### $(date +%FT%T%:z)" >> "$LOG"
  "$@" >"$f" 2>&1; rc=$?
  cat "$f" >> "$LOG"
  echo "EXIT=$rc" >> "$LOG"
  return $rc
}

VERUS_KEYS="VERUS_VERIFIED VERUS_ERRORS VERUS_STATUS"

# Экстрактор ключей Verus. Замороженная таблица называет ключи `VERUS_VERIFIED/ERRORS/STATUS`, а
# прибор печатает их одной строкой `VERUS_TOTAL verified=8 errors=0 files=1 status=OK` — имени
# ключа в ней нет, и прежний `val` выдавал пустоту: сверка показала 6 расхождений при двух зелёных
# прогонах (rc=0) и `repro=совпал` по двум пустым векторам, то есть воспроизводимость была
# посчитана по молчанию. ДИАГНОЗ того же класса, что и ДИАГНОЗ-1 из `E-0088`: имена ключей обязано
# проверять исполнением экстрактора до боевого прогона, а не памятью о формате вывода.
# Пустое поле теперь отличается от числа словом `НЕВЫДЕЛЕНО`, и такое значение не может совпасть с
# ожиданием молча.
vfield() { # $1=файл $2=поле внутри строки VERUS_TOTAL
  local v
  v="$(grep 'VERUS_TOTAL' "$1" | tail -1 | tr ' ' '\n' | grep -E "^$2=" | head -1 | cut -d= -f2-)"
  [ -n "$v" ] && echo "$v" || echo НЕВЫДЕЛЕНО
}
grab() { local f="$1" s="$2" k v; for k in $3; do
  case "$k" in
    VERUS_VERIFIED) v="$(vfield "$f" verified)" ;;
    VERUS_ERRORS)   v="$(vfield "$f" errors)" ;;
    VERUS_STATUS)   v="$(vfield "$f" status)" ;;
    *)              v="$(val "$f" "$k")" ;;
  esac
  printf 'n%s_%s=%s\n' "$s" "$k" "$v"
done; }

# Шаг 1 — Verus на боевом дереве, дважды (гейт (8): вектор обязан совпасть).
run_to "$V1" "ШАГ 1 Verus, прогон n=1" bash lab/verus-check.sh --quiet
echo "verus_check_rc=$?" >> "$LOG"
run_to "$V2" "ШАГ 2 Verus, прогон n=2" bash lab/verus-check.sh --quiet
echo "verus_check2_rc=$?" >> "$LOG"

{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$V1" 1 "$VERUS_KEYS"; echo "n1_const_match=$(val "$V1" CONST_MATCH)"; } >> "$LOG"
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$V2" 2 "$VERUS_KEYS"; echo "n2_const_match=$(val "$V2" CONST_MATCH)"; } >> "$LOG"

# Шаг 3 — самопроверки приборов (гейты (2) и (5)): посадки обязаны отбиваться, а не молчать.
run_to "$VS" "ШАГ 3а Verus selftest" bash lab/verus-check.sh selftest
echo "verus_selftest_rc=$?" >> "$LOG"
run_to "$KC" "ШАГ 3б kani-compile-check" bash lab/kani-compile-check.sh
echo "kcc_rc=$?" >> "$LOG"
run_to "$KS" "ШАГ 3в kani-compile-check selftest" bash lab/kani-compile-check.sh selftest
echo "kcc_selftest_rc=$?" >> "$LOG"

# Шаг 4 — честность разрешённого молчания (гейт (4)): без бинаря SKIP при REQUIRED=0 и падение при 1.
run_to "$SKP" "ШАГ 4а Verus без бинаря, REQUIRED=0" env VEC_DHT_VERUS=/nonexistent/verus.exe VEC_DHT_VERUS_REQUIRED=0 bash lab/verus-check.sh
echo "skip_rc=$?" >> "$LOG"
run_to "$REQ" "ШАГ 4б Verus без бинаря, REQUIRED=1" env VEC_DHT_VERUS=/nonexistent/verus.exe VEC_DHT_VERUS_REQUIRED=1 bash lab/verus-check.sh
echo "req_rc=$?" >> "$LOG"

# Шаг 5 — Lean-контур обязан остаться зелёным после появления соседей (гейт (6)).
run_to "$LC" "ШАГ 5а lean-check" bash lab/lean-check.sh --quiet
echo "lean_rc=$?" >> "$LOG"
run_to "$LS" "ШАГ 5б lean-check selftest" python lab/lean-check.py selftest
echo "lean_selftest_rc=$?" >> "$LOG"

# Шаг 6 — регрессия продукта (гейт (10)): тесты crate'а и clippy с -D warnings.
run_to "$REGT" "ШАГ 6а cargo test -p vecdht-node (--no-fail-fast)" cargo test -p vecdht-node --no-fail-fast
echo "node_test_rc=$?" >> "$LOG"
run_to "$REGC" "ШАГ 6б clippy -p vecdht-node --all-targets -- -D warnings" cargo clippy -p vecdht-node --all-targets -- -D warnings
echo "clippy_rc=$?" >> "$LOG"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (1)…(2) verus: n1=$(grep -oE 'VERUS_TOTAL[^#]*' "$V1" | tail -1) | selftest=$(grep -oE 'VERUS_SELFTEST[^#]*' "$VS" | tail -1)"
  echo "порог (5) kcc: check=$(grep -E '^KCC_' "$KC" | tr '\n' ' ') | selftest=$(grep -oE 'KCC_SELFTEST[^#]*' "$KS" | tail -1)"
  echo "порог (4) молчание: skip_status=$(val "$SKP" VERUS_STATUS) skip_rc=$(val "$LOG" skip_rc) req_label=$(val "$REQ" VERUS_REQUIRED_BUT_MISSING) req_rc=$(val "$LOG" req_rc)"
  echo "порог (6) lean: lean_all_ok=$(val "$LC" LEAN_ALL_OK) decls=$(val "$LC" DECLS_TOTAL) broken=$(val "$LC" BROKEN) digest_bad=$(val "$LC" DIGEST_BAD) selftest=$(grep -oE 'LEANGUARD_SELFTEST[^#]*' "$LS" | tail -1)"
  echo "порог (9) disk_before=$(val "$LOG" DISK_FREE_MB) disk_min=$DISK_MIN disk_ok=$( [ "${DISK_BEFORE:-0}" -ge "$DISK_MIN" ] && echo 1 || echo 0)"
  echo "порог (10) регрессия: node_test_rc=$(val "$LOG" node_test_rc) clippy_rc=$(val "$LOG" clippy_rc) failed=$(grep -oE '[0-9]+ failed' "$REGT" | awk '{s+=$1} END {print s+0}')"
  echo "порог (12) kani_локально=$(command -v cargo-kani >/dev/null 2>&1 && echo есть || echo нет) — харнеси проверяются только компиляцией (KCC), модель-проверка в CI"
} >> "$LOG"

grab "$V1" 1 "$VERUS_KEYS" > "$F1"; echo "n1_const_match=$(val "$V1" CONST_MATCH)" >> "$F1"
grab "$V2" 2 "$VERUS_KEYS" > "$F2"; echo "n2_const_match=$(val "$V2" CONST_MATCH)" >> "$F2"
{ echo "### ШАГ 7 воспроизводимость вектора ###"
  echo "repro=$(cmp -s <(sed 's/^n1_/n_/' "$F1" | grep -oE '^[a-z_0-9]+=.*' ) <(sed 's/^n2_/n_/' "$F2" | grep -oE '^[a-z_0-9]+=.*') && echo совпал || echo РАЗОШЁЛСЯ)"
} >> "$LOG"

# Шаг 8 — CI. Числа берутся из API, а не из памяти; по умолчанию шаг выключен, чтобы офлайн-прогон
# не краснел из-за сети.
if [ "${VEC_DHT_CI_POLL:-0}" = "1" ]; then
  { echo "### ШАГ 8 CI (GitHub Actions, публичный API без токена) ###"
    # Печатать `ключ=значение` без пробела: `val` ищет токен `ключ=`, а `print('ключ=', x)`
    # вставляет пробел, и `RUN_ID` оказывался пустым — то есть весь разбор работ молча
    # пропускался. Это второй за цикл случай того же класса дефекта (первый — ключи Verus выше),
    # и он пойман не сверкой, а ручным прогоном шага 8: отсюда обязательная метка
    # `ci_run_id_НЕ_РАЗОБРАН` ниже — пустой `RUN_ID` обязан быть слышен, а не выглядел как «CI
    # просто не участвовал».
    curl -s --max-time 40 "https://api.github.com/repos/mak777uh/VecDHT/actions/workflows" \
      | python -c "import json,sys;d=json.load(sys.stdin);print('ci_workflows_total=%s' % d.get('total_count'));print('ci_workflow_names=%s' % ','.join(sorted(w['name'] for w in d.get('workflows',[]))))" 2>/dev/null
    curl -s --max-time 40 "https://api.github.com/repos/mak777uh/VecDHT/actions/runs?per_page=1" \
      | python -c "import json,sys;d=json.load(sys.stdin);r=(d.get('workflow_runs') or [{}])[0];print('ci_run_id=%s' % r.get('id'));print('ci_run_status=%s' % r.get('status'));print('ci_run_conclusion=%s' % r.get('conclusion'));print('ci_run_head_sha=%s' % str(r.get('head_sha'))[:7])" 2>/dev/null
  } >> "$LOG"
  RUN_ID=$(val "$LOG" ci_run_id)
  { echo "ci_head_local=$(git rev-parse --short HEAD)"
    echo "ci_run_matches_head=$( [ -n "$RUN_ID" ] && [ "$(val "$LOG" ci_run_head_sha)" = "$(git rev-parse --short HEAD)" ] && echo 1 || echo 0)"
    [ -n "$RUN_ID" ] || echo "ci_run_id_НЕ_РАЗОБРАН=1 — шагу 8 нечего брать из API"
  } >> "$LOG"
  if [ -n "$RUN_ID" ]; then
    # Порог (12) требует, чтобы в журнале лежал ВЫВОД каждой из четырёх работ, а не только их цвета.
    # ЖУРНАЛ работы анонимно недоступен (`/jobs/{id}/logs` отдаёт 403 «Must have admin rights», а
    # страница требует входа — это проверено и на API, и на HTML), поэтому вывод берётся из двух
    # анонимно читаемых источников: пошаговые коды работ (`/runs/{id}/jobs`) и аннотации, которые
    # сам workflow печатает строками `::notice::` (`/check-runs/{job_id}/annotations`).
    curl -s --max-time 40 "https://api.github.com/repos/mak777uh/VecDHT/actions/runs/$RUN_ID/jobs?per_page=30" > "$CIJ" 2>/dev/null
    python - "$CIJ" >> "$LOG" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for j in d.get("jobs", []):
    tag = j.get("name", "?").split("—")[0].strip().lower().replace(" ", "_")
    print("ci_job=%s job_id=%s name=%s status=%s conclusion=%s" %
          (tag, j.get("id"), j.get("name"), j.get("status"), j.get("conclusion")))
    for s in j.get("steps", []):
        if s.get("name", "").startswith(("Post ", "Set up", "Complete")):
            continue
        print("  ci_step=%s n=%s name=%s conclusion=%s" %
              (tag, s.get("number"), s.get("name"), s.get("conclusion")))
PY
    for JID in $(block | grep -oE 'ci_job=[^ ]+ job_id=[0-9]+' | sed 's/.*job_id=//'); do
      curl -s --max-time 40 "https://api.github.com/repos/mak777uh/VecDHT/check-runs/$JID/annotations" \
        | python -c "
import json, sys
d = json.load(sys.stdin)
# Измерено на этом же API: эндпоинт check-runs/{id}/annotations отдаёт ГОЛЫЙ СПИСОК аннотаций,
# а не объект с полем annotations (в отличие от runs/{id}/jobs). Читался бы только dict — и шаг
# молчал бы, показав пустоту там, где сервер вернул шесть строк.
a = d if isinstance(d, list) else (d.get('annotations') or [])
for x in a:
    lvl = x.get('annotation_level')
    if lvl == 'notice':
        print('ci_ann job=$JID :: ' + (x.get('message') or '').strip())
if not a:
    print('ci_ann job=$JID пусто — workflow не напечатал ни одной метки')
" >> "$LOG" 2>/dev/null
    done
  fi
fi

# Шаг 9 — сверка напечатанных фактов с замороженной таблицей (корпус = все выводы приборов + блок).
{ echo "### КЛЮЧИ ДЛЯ СВЕРКИ ###"
  echo "verus_selftest=$(grep -oE 'passed=[0-9]+' "$VS" | tail -1 | cut -d= -f2)"
  echo "verus_selftest_total=$(grep -oE 'VERUS_SELFTEST total=[0-9]+' "$VS" | tail -1 | cut -d= -f2)"
  echo "kcc_anchors=$(val "$KC" KCC_ANCHORS) kcc_harness_fns=$(val "$KC" KCC_HARNESS_FNS) kcc_status=$(val "$KC" KCC_STATUS)"
  echo "kcc_selftest_passed=$(grep -oE 'KCC_SELFTEST total=[0-9]+ passed=[0-9]+' "$KS" | tail -1 | sed 's/.*passed=//')"
  echo "kcc_selftest_total=$(grep -oE 'KCC_SELFTEST total=[0-9]+' "$KS" | tail -1 | sed 's/.*total=//')"
  echo "skip_status=$(val "$SKP" VERUS_STATUS) req_rc=$(val "$LOG" req_rc) skip_rc=$(val "$LOG" skip_rc)"
  echo "req_missing=$(grep -c VERUS_REQUIRED_BUT_MISSING "$REQ")"
  echo "lean_all_ok=$(val "$LC" LEAN_ALL_OK) decls_total=$(val "$LC" DECLS_TOTAL) broken=$(val "$LC" BROKEN) digest_bad=$(val "$LC" DIGEST_BAD) sorry_total=$(val "$LC" SORRY_TOTAL)"
  echo "lean_selftest_passed=$(grep -oE 'LEANGUARD_SELFTEST total=[0-9]+ passed=[0-9]+' "$LS" | tail -1 | sed 's/.*passed=//')"
  echo "lean_selftest_total=$(grep -oE 'LEANGUARD_SELFTEST total=[0-9]+' "$LS" | tail -1 | sed 's/.*total=//')"
  echo "node_failed=$(grep -oE '[0-9]+ failed' "$REGT" | awk '{s+=$1} END {print s+0}') node_passed=$(grep -oE '[0-9]+ passed' "$REGT" | awk '{s+=$1} END {print s+0}') node_ignored=$(grep -oE '[0-9]+ ignored' "$REGT" | awk '{s+=$1} END {print s+0}')"
} >> "$LOG"

cat "$V1" "$VS" "$KC" "$KS" "$SKP" "$REQ" "$LC" "$LS" > "$CORP" 2>/dev/null || true
block >> "$CORP"
{ echo "### ШАГ 9 СВЕРКА: $EXPECT против напечатанных фактов ###"
  python lab/expect.py "$EXPECT" "$CORP"
  echo "СВЕРКА_EXIT=$?"
} >> "$LOG"

{ echo "МЕРЕНО после: RAM_FREE_MB=$(ram_mb) DISK_FREE_MB=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb) TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
  echo "########## E-0099 · конец блока ##########"
} >> "$LOG"
tail -32 "$LOG"
echo "=== E-0099 готов; журнал $LOG ==="
