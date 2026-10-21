#!/usr/bin/env bash
# E-0015 (`H-0014`): цена потолка §7.5 в 16 владельцев при дешёвой политике (групповая заявка
# по кластерам) на ровной связной карте шардов. Forward не повторяется (кеши E-0004/E-0006).
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_GROUPED=1
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

# --- Шаг 1: 50 000, групповая заявка на ровной связной карте (гейт H-0014) ---
run_step "1-50k-grouped" \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

# --- Шаг 2: 807 596, то же (контрольная точка) ---
run_step "2-807k-grouped" \
  VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

echo "########## E-0015 COMPLETE ##########"
