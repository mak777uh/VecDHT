#!/usr/bin/env bash
# E-0023 (`H-0022`): двухстадийный скан — оценкой кандидата служит product quantization-код
# (m Б на запись), точный int8 считается только для глобальных top-R.
#
# Множество кандидатов менять нельзя: отбор ячеек (COHERENT-карта `E-0012`), fan-out ≤ 16
# владельцев (§7.5) и ground truth остаются протокольными, поэтому каждая рука печатается вместе
# с немодифицированной int8-кривой того же прогона — контроль инертности 0,9645 @ 12 558,8 и
# 0,9790 @ 204 715,6. В PQ-режиме обе кривые доходят только до nprobe=16: условия гипотезы
# проверяются в точке гейта, а полный скан 64 ячеек 807k корпуса ничего не измеряет.
#
# Руки: m=24 (код 24 Б) при R ∈ {32, 100, 256, 1024} и лестница точности m=48 (код 48 Б) при
# R=100. Кодобук кэшируется на диске (corpus-*.pq{m}), переобучение между руками не повторяется.
#
# Исполняемый файл собирается ОДИН раз до первой руки и дальше запускается напрямую: `cargo test`
# на каждой руке пересобирает стенд, и правка исходников между руками породила бы цепочку, где
# разные руки меряны разными бинарниками (это уже делало прогон 807k недействительным).
#
# Запуск: ./lab/e0023-run.sh 50k | 807k | all   (по умолчанию all)
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

WHICH=${1:-all}
TEST=gate_ii_real_corpus_recall
# Лог прогона живёт в репозитории (`lab/logs/`), а не в /tmp: числа из записи `E-0023` должны
# сверяться с тем же файлом, что коммится вместе с ней.
LOG=${E0023_LOG:-lab/logs/e0023-$WHICH.log}
mkdir -p "$(dirname "$LOG")"
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_PQ=1
)
C50=C:/Users/Admin/models/p0-msmarco/corpus-50k.txt
C807=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt
Q1K=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

echo "########## BUILD (один бинарник на все руки) ##########" | tee -a "$LOG"
cargo test --release -p vecdht-embed --features candle --no-run >>"$LOG" 2>&1 || exit 1
EXE=$(ls -t target/release/deps/p0_real_corpus-*.exe 2>/dev/null | head -1)
[ -n "$EXE" ] || { echo "не найден исполняемый файл теста" | tee -a "$LOG"; exit 1; }
echo "########## EXE $EXE (md5 $(md5sum "$EXE" | cut -c1-12)) ##########" | tee -a "$LOG"

run_step () {
  local name="$1"; shift
  echo "########## STEP ${name} ##########" | tee -a "$LOG"
  env "${BASE_ENV[@]}" "$@" "$EXE" "$TEST" --ignored --nocapture >>"$LOG" 2>&1
  local rc=$?
  echo "########## STEP ${name} DONE (exit $rc) ##########" | tee -a "$LOG"
}

if [ "$WHICH" = "50k" ] || [ "$WHICH" = "all" ]; then
  for R in 32 100 256 1024; do
    run_step "1-50k-m24-R$R" \
      VEC_DHT_P0_PQ_M=24 VEC_DHT_P0_PQ_R=$R VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"
  done
  run_step "5-50k-m48-R100" \
    VEC_DHT_P0_PQ_M=48 VEC_DHT_P0_PQ_R=100 VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"
fi

if [ "$WHICH" = "807k" ] || [ "$WHICH" = "all" ]; then
  for R in 32 100 256 1024; do
    run_step "1-807k-m24-R$R" \
      VEC_DHT_P0_PQ_M=24 VEC_DHT_P0_PQ_R=$R VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
  done
  run_step "5-807k-m48-R100" \
    VEC_DHT_P0_PQ_M=48 VEC_DHT_P0_PQ_R=100 VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
fi

echo "########## E-0023 COMPLETE — лог: $LOG ##########"
grep -E "режим PQ|КОНТРОЛЬ ИНЕРТНОСТИ|^PQ \(|  \(1\)|  \(2\)|  \(3\)|  справочно|STEP" "$LOG"
