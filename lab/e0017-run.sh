#!/usr/bin/env bash
# E-0017 (`H-0016`): цена запроса ограничена владельцами, а не размером шарда — co-hosting.
#
# Карта — транспортная задача при ёмкости 8 (`E-0013`), но ячейки собраны в пары: владелец держит
# 2 шарда, бюджет §7.5 считается владельцами. Лестница nprobe = бюджеты владельцев 1/2/4/8/12/16.
# Форвард не повторяется: кеши `E-0004` (50k) и `E-0006` (807k).
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

LOG=${E0017_LOG:-/tmp/e0017.log}
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_CLUSTERS_PER_SHARD=8
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

run_step "1-50k-owner2" \
  VEC_DHT_P0_OWNER_CELLS=2 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

run_step "2-807k-owner2" \
  VEC_DHT_P0_OWNER_CELLS=2 \
  VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

run_step "3-50k-owner4" \
  VEC_DHT_P0_OWNER_CELLS=4 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

echo "########## E-0017 COMPLETE — лог: $LOG ##########"
grep -E "OWNERS:|режим OWNERS|recall@10 =|^ *[0-9]+ +0\.|STEP" "$LOG"
