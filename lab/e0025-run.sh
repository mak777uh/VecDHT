#!/usr/bin/env bash
# E-0025 (`H-0024`): цена скана как функция геометрии. Бюджет §7.5 не трогается (16 ячеек =
# 16 владельцев = 256 мелких кластеров на запрос), а меняется nlist — число мелких кластеров,
# которые k-means строит над тем же корпусом. Доля корпуса в скане равна 256/nlist, поэтому она
# обязана падать пропорционально росту nlist: 25 % при 1024, 6,25 % при 4096, 3,125 % при 8192.
#
# Руки: nlist = 1024 (контроль инертности — обязан повторить `E-0012`: 0,9790 @ 204 715,6 на 807k
# и 0,9645 @ 12 558,8 на 50k), nlist = 4096 (условия (1)–(3)), nlist = 8192 (справочная вторая
# точка кривой «качество за долю»). Условие (2) «при равной работе» читается из тех же логов:
# nlist=1024 при nprobe=4 и nlist=4096 при nprobe=16 сканируют по 64 и 256 кластеров, то есть
# ≈6,25 % корпуса, — сравниваются recall этих двух точек.
#
# Скан, ground truth (exact brute-force), контракт сортировки `(l2_sq, id)` и fan-out ≤ 16 при
# этом физически не меняются: единственный рычаг стенда — assert, не пускавший nlist выше
# протокольного NLIST (контракт файла `centroid.bin`, а не свойство измерения).
#
# Исполняемый файл собирается ОДИН раз (см. причину в `lab/e0023-run.sh`).
#
# Запуск: ./lab/e0025-run.sh 50k | 807k | all   (по умолчанию all)
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

WHICH=${1:-all}
TEST=gate_ii_real_corpus_recall
LOG=${E0025_LOG:-lab/logs/e0025-$WHICH.log}
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

for NL in 1024 4096 8192; do
  if [ "$WHICH" = "807k" ] || [ "$WHICH" = "all" ]; then
    run_step "807k-nlist$NL" VEC_DHT_P0_NLIST=$NL VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
  fi
done

if [ "$WHICH" = "50k" ] || [ "$WHICH" = "all" ]; then
  run_step "50k-nlist1024" VEC_DHT_P0_NLIST=1024 VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"
  run_step "50k-nlist4096" VEC_DHT_P0_NLIST=4096 VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"
fi

echo "########## E-0025 COMPLETE — лог: $LOG ##########"
grep -E "ГЕОМЕТРИЯ ВНЕ ПРОТОКОЛА|ЛЕСТНИЦА|КОНТРОЛЬ ИНЕРТНОСТИ|^COARSE-COHERENT|STEP" "$LOG"
