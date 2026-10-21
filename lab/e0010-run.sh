#!/usr/bin/env bash
# E-0010 (`H-0010`, групповая заявка по кластерам) и E-0011 (`H-0011`, ровная карта шардов
# через рекурсивное деление). Гейт и порог прежние; forward не повторяется (кеши E-0004/E-0006).
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
)
C50=C:/Users/Admin/models/p0-msmarco/corpus-50k.txt
C807=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt
Q1K=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

run_step () {
  local name="$1"; shift
  local extra_env=("$@")
  echo "########## STEP ${name} ##########"
  env "${BASE_ENV[@]}" "${extra_env[@]}" \
    cargo test --release -p vecdht-embed --features candle gate_ii_real_corpus_recall -- \
    --ignored --nocapture
  echo "########## STEP ${name} DONE (exit $?) ##########"
}

# --- E-0010: групповая заявка на измеренной связной карте (E-0007) ---
run_step "1-50k-grouped-coarse" \
  VEC_DHT_P0_GROUPED=1 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

# --- E-0011: ровная карта (рекурсивное деление), полный скан шарда ---
run_step "2-50k-balanced" \
  VEC_DHT_P0_BALANCED=1 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

# --- ровная карта + групповая заявка (протокольная геометрия и дешёвая политика сразу) ---
run_step "3-50k-balanced-grouped" \
  VEC_DHT_P0_BALANCED=1 VEC_DHT_P0_GROUPED=1 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

# --- те же два на 807 596 ---
run_step "4-807k-grouped-coarse" \
  VEC_DHT_P0_GROUPED=1 \
  VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

run_step "5-807k-balanced-grouped" \
  VEC_DHT_P0_BALANCED=1 VEC_DHT_P0_GROUPED=1 \
  VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

echo "########## E-0010/E-0011 COMPLETE ##########"
