#!/usr/bin/env bash
# E-0021 (`H-0020`): сколько стоит резка скана ниже кластера — третий уровень IVF при 16 владельцах.
#
# Карта протокольная (64 ячейки по 16 кластеров, транспортная задача E-0012), выбор ячеек — правило
# гейта §7.5.1, лестница идёт по s = число сканируемых подсписков на кластер (m = 8). Контроль
# s = m обязан повторить E-0012. Форвард не повторяется: кеши E-0004 (50k) и E-0006 (807k).
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

LOG=${E0021_LOG:-/tmp/e0021.log}
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_SUB=1
  VEC_DHT_P0_SUBM=8
)
C50=C:/Users/Admin/models/p0-msmarco/corpus-50k.txt
C807=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt
Q1K=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

run_step () {
  local name="$1"; shift
  echo "########## STEP ${name} ##########" | tee -a "$LOG"
  env "${BASE_ENV[@]}" "$@" \
    cargo test --release -p vecdht-embed --features candle gate_ii_real_corpus_recall -- \
    --ignored --nocapture >>"$LOG" 2>&1
  local rc=$?
  echo "########## STEP ${name} DONE (exit $rc) ##########" | tee -a "$LOG"
}

run_step "1-50k-sub" \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

run_step "2-807k-sub" \
  VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

echo "########## E-0021 COMPLETE — лог: $LOG ##########"
grep -E "SUB|ЦЕНА ОТБОРА|^ *[0-9]+ +0\.|STEP" "$LOG"
