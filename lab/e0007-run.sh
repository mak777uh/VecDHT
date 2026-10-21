#!/usr/bin/env bash
# E-0007 (H-0007): двухуровневая карта шардов — прогон в пред-регистрированном порядке.
# Шаг 0 — пред-полёт на corpus-3k (проверка кода, не гейт); шаги 1-2 — гейтные.
# Кеши эмбеддингов уже записаны (E-0004 и E-0006), поэтому forward не повторяется.
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
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

# Шаг 0: пред-полёт. Малое число текстов ослабляет порог размера, но не порог recall —
# это проверка кода карты, а не измерение §18.1.
run_step "0-smoke-3k" \
  VEC_DHT_P0_ALLOW_SMALL=1 \
  VEC_DHT_P0_CORPUS=C:/Users/Admin/models/p0-msmarco/corpus-3k.txt \
  VEC_DHT_P0_QUERIES=C:/Users/Admin/models/p0-msmarco/queries-100.txt

# Шаг 1: гейтный, 50k на кеше E-0004.
run_step "1-50k" \
  VEC_DHT_P0_CORPUS=C:/Users/Admin/models/p0-msmarco/corpus-50k.txt \
  VEC_DHT_P0_QUERIES=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

# Шаг 2: гейтный, 807 596 на кеше E-0006.
run_step "2-807k" \
  VEC_DHT_P0_CORPUS=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt \
  VEC_DHT_P0_QUERIES=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

echo "########## E-0007 COMPLETE ##########"
