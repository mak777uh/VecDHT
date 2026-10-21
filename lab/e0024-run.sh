#!/usr/bin/env bash
# E-0024 (`H-0023`): точная отсечка. Скан не меняется — считается, сколько записей в 16 выбранных
# ячейках можно было не читать, потому что нижняя оценка блока заведомо превышает 10-е точное
# расстояние того же запроса. Отсечка идеализирована: порог (10-е exact расстояние) известен заранее,
# поэтому измеренная доля — потолок выигрыша, а не обещанное ускорение (это зафиксировано в `H-0023`).
#
# Четыре отсечки: {кластер, ячейка} × {оценка по max‖x‖ (н1), оценка по померной рамке min/max (н2)}.
# Порог успеха ≥ 50 % для н2 на кластерах, фальсификатор < 25 % на обоих корпусах при любом виде.
# Контроль инертности: немодифицированная кривая того же прогона при nprobe=16 обязана повторить
# `E-0012` (0,9645 @ 12 558,8 и 0,9790 @ 204 715,6). Контроль механизма: тот же проход при пороге,
# подменённом нулём, — если и он нулевой, молчит кодировка, а не отсечка.
#
# Исполняемый файл собирается ОДИН раз (см. причину в `lab/e0023-run.sh`): правка исходников между
# руками сделала бы руки несопоставимыми.
#
# Запуск: ./lab/e0024-run.sh 50k | 807k | all   (по умолчанию all)
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

WHICH=${1:-all}
TEST=gate_ii_real_corpus_recall
LOG=${E0024_LOG:-lab/logs/e0024-$WHICH.log}
mkdir -p "$(dirname "$LOG")"
: >"$LOG"

BASE_ENV=(
  RAYON_NUM_THREADS=4
  VEC_DHT_MODEL_DIR=C:/Users/Admin/models/granite-embedding-97m-r2
  VEC_DHT_P0_COARSE=1
  VEC_DHT_P0_COHERENT=1
  VEC_DHT_P0_BOUND_PRUNE=1
)
C50=C:/Users/Admin/models/p0-msmarco/corpus-50k.txt
C807=C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt
Q1K=C:/Users/Admin/models/p0-msmarco/queries-1k.txt

echo "########## BUILD (один бинарник на оба корпуса) ##########" | tee -a "$LOG"
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

if [ "$WHICH" = "50k" ] || [ "$WHICH" = "all" ]; then
  run_step "1-50k-bound" VEC_DHT_P0_CORPUS="$C50" VEC_DHT_P0_QUERIES="$Q1K"
fi

if [ "$WHICH" = "807k" ] || [ "$WHICH" = "all" ]; then
  run_step "2-807k-bound" VEC_DHT_P0_CORPUS="$C807" VEC_DHT_P0_QUERIES="$Q1K"
fi

echo "########## E-0024 COMPLETE — лог: $LOG ##########"
grep -E "режим BOUND|КОНТРОЛЬ ИНЕРТНОСТИ|^BOUND" "$LOG"
