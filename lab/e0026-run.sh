#!/usr/bin/env bash
# E-0026 (`H-0025`): байты приложения на границе узла за один запрос — ось, на которой внешний
# архитектурный отзыв построил «Метод В» («bytes transferred per query; если > 5–10 МБ архитектура
# не выживет») и которую спека держала как строку таблицы §5.4 (`MatchResult (top-32)` ~1.3 КБ) и
# как слова §13.1 («запрос раскрывает ~14 узлам»).
#
# Сеть не поднимается: байты считают настоящие энкодеры (vecdht_wire::Codec + vecdht_net::codec),
# подписи настоящие ed25519 и проверяются, тексты — реальные из того же корпуса. Пороги зафиксированы
# в H-0025 до прогона и здесь не меняются.
#
# Запуск: ./lab/e0026-run.sh   (лог — lab/logs/e0026.log; корпус текстов — VEC_DHT_EGRESS_CORPUS)
set -u
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
cd /c/Users/Admin/Documents/Qoder/2026-10-18/72891a09/VecDHT || exit 1

LOG=${E0026_LOG:-lab/logs/e0026.log}
mkdir -p "$(dirname "$LOG")"
: >"$LOG"

echo "########## BUILD ##########" | tee -a "$LOG"
cargo test --release -p vecdht-net --test egress_per_query --no-run >>"$LOG" 2>&1 || exit 1
EXE=$(ls -t target/release/deps/egress_per_query-*.exe 2>/dev/null | head -1)
[ -n "$EXE" ] || { echo "не найден исполняемый файл теста" | tee -a "$LOG"; exit 1; }
echo "########## EXE $EXE (md5 $(md5sum "$EXE" | cut -c1-12)) ##########" | tee -a "$LOG"

echo "########## STEP egress ##########" | tee -a "$LOG"
RAYON_NUM_THREADS=4 "$EXE" egress_bytes_per_query --nocapture --exact >>"$LOG" 2>&1
rc=$?
echo "########## STEP egress DONE (exit $rc) ##########" | tee -a "$LOG"

echo "########## E-0026 COMPLETE — лог: $LOG ##########"
grep -E "УСЛОВИЯ H-0025|ФАЛЬСИФИКАТОР|ИТОГ|сноска|STEP" "$LOG"
