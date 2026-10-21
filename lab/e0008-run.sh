#!/usr/bin/env bash
# E-0008 (H-0008): та же двухуровневая карта, но в протокольном виде — ровно 16 кластеров на
# шард (перебалансировка). Гейт и порог те же, что в E-0007; forward не повторяется.
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_EXACT_SHARDS=1
)

run_step () {
  local name="$1"; shift
  local extra_env=("$@")
  echo "########## STEP ${name} ##########"
  env "${BASE_ENV[@]}" "${extra_env[@]}" \
    cargo test --release -p vecdht-embed --features candle gate_ii_real_corpus_recall -- \
    --ignored --nocapture
  echo "########## STEP ${name} DONE (exit $?) ##########"
}

# Шаг 1: гейтный, 50k на кеше E-0004.
run_step "1-50k" \
  VEC_DHT_P0_CORPUS=C:/Users/Admin/models/p0-msmarco/corpus-50k.txt \
  VEC_DHT_P0_QUERIES=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

# Шаг 2: гейтный, 807 596 на кеше E-0006.
run_step "2-807k" \
  VEC_DHT_P0_CORPUS=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt \
  VEC_DHT_P0_QUERIES=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

echo "########## E-0008 COMPLETE ##########"
