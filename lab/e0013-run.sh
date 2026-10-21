#!/usr/bin/env bash
# E-0013 (`H-0013`): размер шарда как цена полного скана — 8 кластеров вместо 16 (и 4 справочно).
#
# Гейт и порог прежние (`E-0012`), меняется только ёмкость ячейки: карта строится тем же
# библиотечным решателем `shardmap::build_shard_map`, но с `per_shard = cps`. Форвард не
# повторяется: кеши `E-0004` (50k) и `E-0006` (807k).
#
# Шаг 0 — контроль, что параметризация инертна: при cps=16 обязан повториться числа `E-0012`
# (recall 0,9645 на 50k и разброс 4 494 664). Шаги с провалом порога завершаются assert'ом
# (exit 101) — это и есть сработавший фальсификатор `H-0013`, поэтому `set -e` здесь выключен.
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

LOG=${E0013_LOG:-/tmp/e0013.log}
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
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

# 0 — контроль инертности: cps=16 обязан дать числа E-0012.
run_step "0-50k-cps16-control" \
  VEC_DHT_P0_CLUSTERS_PER_SHARD=16 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

# 1 — главный шаг: 50 000, карта 128×8.
run_step "1-50k-cps8" \
  VEC_DHT_P0_CLUSTERS_PER_SHARD=8 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

# 2 — 807 596, карта 128×8 (контрольная точка порога).
run_step "2-807k-cps8" \
  VEC_DHT_P0_CLUSTERS_PER_SHARD=8 \
  VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

# 3 — справочно: ещё вдвое меньше шард (256×4) на 50k.
run_step "3-50k-cps4" \
  VEC_DHT_P0_CLUSTERS_PER_SHARD=4 \
  VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

echo "########## E-0013 COMPLETE — лог: $LOG ##########"
grep -E "ГЕОМЕТРИЯ ВНЕ ПРОТОКОЛА|COHERENT \(транспортная|разброс внутри|recall@10 =|nprobe  recall|STEP" "$LOG"
