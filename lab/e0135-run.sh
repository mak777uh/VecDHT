#!/usr/bin/env bash
# H-0135 / E-0135 (гейт §18.3 «fuzz-декод 30 мин без panic»): носитель, а не проза.
#
# Что мерится. Спека §18.3 требует soak на 30 минут, а прибор, который бы его исполнял, до этого
# цикла отсутствовал: `crates/…/tests/fuzz_*.rs` умеют wall-clock бюджет (`VEC_DHT_FUZZ_SECS`), но
# ни CI, ни lab-контур его никогда не выставлял, и обычная сборка гоняет только бюджеты по числу
# итераций. Здесь soak исполняется локально (8 фаззер-тестов по 240 с в один поток, агрегат ≥ 1800 с)
# и ставится ночным джобом в CI.
#
# Дыра обязана называться до починки: `--tag PRE_FIX_ --skip-soak` исполняет этот же прибор на дереве
# base-коммита (во временном клоне, куда копируются финальные приборы) и печатает CI_SECS_ENV_SET=0 —
# то есть «ночного носителя нет», а не «носитель зелёный».
#
# Тайминги (суммарное wall-clock время, числа итераций, принято/отклонено) в замороженную таблицу НЕ
# входят: они не инвариантны к расписанию хоста (правило 7 пункт (е)), поэтому печатаются фактами и
# кладутся в носитель, но порог над ними не ставится. Порог стоит над агрегатным булем
# `SOAK_GE_1800` и над нулём паник.
set -uo pipefail
TAG=""
SKIP_SOAK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="${2:-}"; shift 2 ;;
    --skip-soak) SKIP_SOAK=1; shift ;;
    *) shift ;;
  esac
done
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/
PER_TEST_SECS="${VEC_E0135_PER_TEST_SECS:-260}"

buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }

# (0) Гейт карточки и диск.
python lab/cycle-gate.py gate H-0135 >>"$buf" 2>&1 && emit GATE_H0134_OK 1 || emit GATE_H0134_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"
[ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# (1) Предпосылки прибора: сколько тестов, сколько из них #[ignore], выставлен ли бюджет в CI.
FUZZ_FILES="crates/vecdht-artifact/tests/fuzz_decode.rs crates/vecdht-crypto/tests/fuzz_verify.rs"
emit FUZZ_TESTS_TOTAL "$(grep -h -o '#\[test\]' $FUZZ_FILES | wc -l)"
emit FUZZ_IGNORED "$(grep -h -o '#\[ignore' $FUZZ_FILES | wc -l)"
emit PER_TEST_SECS "$PER_TEST_SECS"
emit CI_SECS_ENV_SET "$(grep -c 'VEC_DHT_FUZZ_SECS' .github/workflows/verify.yml || true)"
emit CI_NIGHTLY_SOAK_JOB "$(grep -c 'fuzz-soak' .github/workflows/verify.yml || true)"
emit CI_SOAK_EXPORT_SECS "$(grep -o 'VEC_DHT_FUZZ_SECS=[0-9]*' .github/workflows/verify.yml | tail -1 | cut -d= -f2 || echo none)"

# (2) Экстрактор паник обязан уметь краснеть: посадка строк panic в синтетический лог.
cat >${SCR}plant.log <<'PL'
test json_fuzz ... ok
thread 'main' panicked at crates/vecdht-artifact/tests/fuzz_decode.rs:999: вход не воспроизведён
test manifest_fuzz ... ok
PL
PP=$(grep -c 'panicked at' ${SCR}plant.log || true)
[ "${PP:-0}" = 1 ] && emit PLANT_PANIC_CAUGHT 1 || emit PLANT_PANIC_CAUGHT 0
grep -c 'panicked at' /dev/null >/dev/null 2>&1
emit PANIC_EXTRACTOR_EMPTY_OK "$( [ "$(grep -c 'panicked at' /dev/null || true)" = 0 ] && echo 1 || echo 0 )"

# (3) Сам soak. Один поток обязателен: бюджет wall-clock считается на тест, и в параллели восемь
# тестов съели бы 240 с суммарно, а не по очереди — агрегат гейта §18.3 был бы фиктивным.
TOTAL=0
if [ "$SKIP_SOAK" = 0 ]; then
  export VEC_DHT_FUZZ_SECS="$PER_TEST_SECS"
  cargo test --release -p vecdht-artifact --test fuzz_decode -- --test-threads=1 --nocapture \
    >${SCR}art.log 2>&1
  emit ART_SOAK_EXIT $?
  cargo test --release -p vecdht-crypto --test fuzz_verify -- --test-threads=1 --nocapture \
    >${SCR}cry.log 2>&1
  emit CRY_SOAK_EXIT $?
  emit ART_PASSED "$(grep -o 'test result: ok\. [0-9]*' ${SCR}art.log | tail -1 | grep -o '[0-9]*' || echo none)"
  emit CRY_PASSED "$(grep -o 'test result: ok\. [0-9]*' ${SCR}cry.log | tail -1 | grep -o '[0-9]*' || echo none)"
  emit PANICS_TOTAL "$(cat ${SCR}art.log ${SCR}cry.log | grep -c 'panicked at' || true)"
  emit FUZZ_BUDGETED_TESTS "$(cat ${SCR}art.log ${SCR}cry.log | grep -c 'за [0-9.]* с' || true)"
  TOTAL=$(cat ${SCR}art.log ${SCR}cry.log |
          grep -o 'за [0-9.]* с' | awk '{ s += $2 } END { printf "%.0f", s+0 }')
  emit SOAK_WALL_SECS "${TOTAL:-0}"
  [ "${TOTAL:-0}" -ge 1800 ] && emit SOAK_GE_1800 1 || emit SOAK_GE_1800 0
  cp ${SCR}art.log ${SCR}cry.log "${TMPDIR:-/tmp}"/ 2>/dev/null || true
else
  emit SOAK_SKIPPED 1
  emit SOAK_WALL_SECS 0
  emit SOAK_GE_1800 0
  emit PANICS_TOTAL 0
fi

# (4) Неизменность свидетельств и остальной контур.
emit RUST_TOUCHED "$(git diff --name-only a675bf4 -- crates/ | wc -l)"
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
bash lab/check-text-clean.sh >${SCR}text.txt 2>&1; emit TEXTGUARD_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?

# STABLE — сравнение с предыдущим снимком фактов того же дерева (тайминги исключены: они не годятся
# в порог и не должны делать второй прогон «несходным» по причине скорости хоста).
SNAP=${TMPDIR:-/tmp}/e0135-post1.facts
if [ -z "$TAG" ] && [ -f "$SNAP" ]; then
  Filt() { grep -v -E '^(DISK_FREE_MB|SOAK_WALL_SECS|TEXTGUARD_FILES)=' "$1"; }
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then
    emit STABLE 1
  else
    emit STABLE 0
  fi
fi
if [ -z "$TAG" ]; then
  Filt2() { grep -v -E '^(DISK_FREE_MB|SOAK_WALL_SECS|TEXTGUARD_FILES)=' "$1"; }
  Filt2 "$buf" > "$SNAP"
fi
if [ -n "$TAG" ]; then sed "s/^/${TAG}/" "$buf"; else cat "$buf"; fi
rm -f "$buf"
