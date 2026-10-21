#!/usr/bin/env bash
# E-0027 (`H-0026`): произведение двух уже измеренных рычагов — ротации геометрии (`E-0025`,
# доля скана = 256/nlist) и co-hosting'а (`E-0017`, владелец держит N смежных ячеек, бюджет §7.5
# считается владельцами). Ни один прогон их вместе не запускал: режимы живут в одном оракуле и
# сцеплены только assert'ом `owner_cells` требует `coarse`.
#
# Руки, в этом порядке:
#   1. контроль инертности — nlist=1024, CLUSTERS_PER_SHARD=8, OWNER_CELLS=2, 807k. Обязана
#      повторить `E-0017`: recall@10 = 0,9767 при 203 567,1 кандидатах (|Δrecall| ≤ 5·10⁻⁵,
#      |Δкандидатов| ≤ 0,5). Стоит первой: оракул после `E-0017` правился дважды (assert `nlist`
#      в `E-0025` и печать геометрии), и только совпадение с уже измеренной связкой доказывает,
#      что механика co-hosting'а не тронута;
#   2. основная — nlist=4096, cps=16, OWNER_CELLS=2: условия (1) точка лестницы владельцев
#      ≤ 16 с recall ≥ 0,95, (2) средний скан ≤ 13 % корпуса, (3) скан на владельца ≤ 50 % от
#      12 794,7 кандидатов `E-0012`;
#   3. справочно — nlist=4096, OWNER_CELLS=4: штраф связки как функция числа ячеек на узле
#      (повтор `E-0017` на другой геометрии, порогом не является);
#   4. справочно — nlist=8192, OWNER_CELLS=2: куда идёт кривая «владельцев ≤16, доля → 0»;
#   5. 50k, nlist=4096, OWNER_CELLS=2: ~12 записей на кластер — вне применимости разбиения,
#      печатается как масштабный эффект `ADR-0003`/`E-0013`, не как опровержение.
#
# Лестница в режиме OWNERS идёт по числу владельцев (1/2/4/8/12/16 — зашито в оракуле), fan-out
# ≤ 16 владельцев, скан, ground truth (exact brute-force) и контракт сортировки `(l2_sq, id)` не
# меняются физически: стенд для этой гипотезы править не нужно, нужны только env-переключатели.
#
# Exit 101 на руках вне гейта — штатное поведение assert'а гейта (ii): лестница печатается до
# ассерта, поэтому числа условий (1)–(3) в логе есть всегда.
#
# Запуск: ./lab/e0027-run.sh 50k | 807k | all   (по умолчанию all)
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

WHICH=${1:-all}
TEST=gate_ii_real_corpus_recall
LOG=${E0027_LOG:-lab/logs/e0027-$WHICH.log}
mkdir -p "$(dirname "$LOG")"
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

echo "########## BUILD (один бинарник на все руки) ##########" | tee -a "$LOG"
cargo test --release -p vecdht-embed --features candle --no-run >>"$LOG" 2>&1 || exit 1
EXE=$(ls -t target/release/deps/p0_real_corpus-*.exe 2>/dev/null | head -1)
[ -n "$EXE" ] || { echo "не найден исполняемый файл теста" | tee -a "$LOG"; exit 1; }
echo "########## EXE $EXE (md5 $(md5sum "$EXE" | cut -c1-12)) ##########" | tee -a "$LOG"

run_step () {
  local name="$1"; shift
  echo "########## STEP ${name} ##########" | tee -a "$LOG"
  env "${BASE_ENV[@]}" "$@" "$EXE" "$TEST" --ignored --nocapture >>"$LOG" 2>&1
  local rc=$?
  echo "########## STEP ${name} DONE (exit $rc) ##########" | tee -a "$LOG"
}

if [ "$WHICH" = "807k" ] || [ "$WHICH" = "all" ]; then
  # 1. контроль инертности — дословная рука `E-0017`
  run_step "807k-ctl1024-cps8-own2" VEC_DHT_P0_NLIST=1024 VEC_DHT_P0_CLUSTERS_PER_SHARD=8 \
    VEC_DHT_P0_OWNER_CELLS=2 VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
  # 2. основная рука — условия (1)–(3)
  run_step "807k-nlist4096-own2" VEC_DHT_P0_NLIST=4096 VEC_DHT_P0_OWNER_CELLS=2 \
    VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
  # 3. справочно: штраф связки по числу ячеек на узле
  run_step "807k-nlist4096-own4" VEC_DHT_P0_NLIST=4096 VEC_DHT_P0_OWNER_CELLS=4 \
    VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
  # 4. справочно: третья точка семейства
  run_step "807k-nlist8192-own2" VEC_DHT_P0_NLIST=8192 VEC_DHT_P0_OWNER_CELLS=2 \
    VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
fi

if [ "$WHICH" = "50k" ] || [ "$WHICH" = "all" ]; then
  run_step "50k-nlist4096-own2" VEC_DHT_P0_NLIST=4096 VEC_DHT_P0_OWNER_CELLS=2 \
    VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"
fi

echo "########## E-0027 COMPLETE — лог: $LOG ##########"
grep -E "ГЕОМЕТРИЯ ВНЕ ПРОТОКОЛА|режим OWNERS|^COARSE-OWNERS|STEP" "$LOG"
