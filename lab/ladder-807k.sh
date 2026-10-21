#!/usr/bin/env bash
# Лестница §8.6 на 807k, пред-регистрированная в E-0006 («Прогон», шаги 1-2).
# Кеш эмбеддингов уже записан (1183 МБ), поэтому forward не повторяется.
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_CORPUS=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt
  VEC_DHT_P0_QUERIES=C:/Users/Admin/models/p0-msmarco/queries-1k.txt
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

# Шаг 1: полный скан выбранных шардов на 807k, nlist=1024.
run_step "1-shard-complete-nlist1024" VEC_DHT_P0_SHARD_COMPLETE=1
# Шаг 2a: nlist=512, обычный IVF.
run_step "2a-nlist512" VEC_DHT_P0_NLIST=512
# Шаг 2b: nlist=512 + shard-complete (вариант «± shard-complete» из пре-регистрации).
run_step "2b-nlist512-shard-complete" VEC_DHT_P0_NLIST=512 VEC_DHT_P0_SHARD_COMPLETE=1
echo "########## LADDER COMPLETE ##########"
