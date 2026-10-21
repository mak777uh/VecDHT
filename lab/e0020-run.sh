#!/usr/bin/env bash
# E-0020 (`H-0019`): сколько стоит facet-фильтр на протокольном скане ≤16 ячеек.
#
# Карта и политика скана — гейтные (`E-0012`: 64 ячейки ровно по 16 кластеров, выбор §7.5.1,
# полный скан выбранных ячеек, fan-out ≤ 16). Отличается одно: до вычисления расстояния запись
# проверяется на совпадение корзины с фильтром запроса. Ground truth — brute-force по корзине.
# Две руки: text (дециль длины пассажи — facet видит геометрию) и random (splitmix64 от id —
# не видит); разница между ними изолирует вклад корреляции. Контроль инертности — немодифицированная
# кривая того же прогона при nprobe=16 обязана повторить `E-0012` (0,9645 / 0,9790).
# Форвард не повторяется: кеши `E-0004` (50k) и `E-0006` (807k).
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

LOG=${E0020_LOG:-/tmp/e0020.log}
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_FACET=1
  VEC_DHT_P0_FACET_BUCKETS=10
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

run_step "1-50k-text" \
  VEC_DHT_P0_FACET_ARM=text VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

run_step "2-50k-random" \
  VEC_DHT_P0_FACET_ARM=random VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"

run_step "3-807k-text" \
  VEC_DHT_P0_FACET_ARM=text VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

run_step "4-807k-random" \
  VEC_DHT_P0_FACET_ARM=random VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"

echo "########## E-0020 COMPLETE — лог: $LOG ##########"
grep -E "режим FACET|FACET:|КОНТРОЛЬ FACET|FACET \(|ЦЕНА ФИЛЬТРА|^ *16 +0\.|STEP" "$LOG"
