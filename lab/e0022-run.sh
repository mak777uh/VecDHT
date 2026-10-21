#!/usr/bin/env bash
# E-0022 (`H-0021`): facet-осознанный отбор ячеек — возвращает ли он фильтрованному запросу
# recall@10 ≥ 0,95 внутри бюджета §7.5 (≤16 владельцев).
#
# От `E-0020` отличается ровно одним правилом: ячейка оценивается по целочисленному центроиду
# нужной корзины внутри ячейки, а не по грубому центроиду всей ячейки. Скан внутри выбранной
# ячейки, предикат до l2_sq, contract-сортировка и фильтрованный ground truth — те же, поэтому
# числа сравнимы напрямую. Контроль инертности — немодифицированная кривая того же прогона
# (0,9645 @ 12 558,8 и 0,9790 @ 204 715,6 = `E-0012`). Форвард не повторяется: кеши `E-0004`/`E-0006`.
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

LOG=${E0022_LOG:-/tmp/e0022.log}
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_FACET=1
  VEC_DHT_P0_FACET_AWARE=1
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

echo "########## E-0022 COMPLETE — лог: $LOG ##########"
grep -E "режим FACET-AWARE|FACET-AWARE|КОНТРОЛЬ FACET|FACET \(|ЦЕНА ФИЛЬТРА|STEP" "$LOG"
