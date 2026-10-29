#!/usr/bin/env bash
# Guard AGENTS.md №5: зеркало спеки обязано быть побайтово равным оригиналом.
#
#     docs/VecDHT-SPEC-v8.md                    — оригинал (в git)
#     ~/OneDrive/Desktop/VecDHT-SPEC-v8.md      — зеркало (вне git, читается владельцем)
#     docs/VecDHT-SPEC-v9.md                    — то же для платных заказов v9
#     ~/OneDrive/Desktop/VecDHT-SPEC-v9.md
#
# Запускать перед каждым коммитом, трогающим спеку: зеркало не коммитится, поэтому его
# расхождение не видно ни в git status, ни в CI — только здесь. Выход 0 — все зеркала совпали,
# выход 1 — хотя бы одно разошлось (печатается diffstat по каждому). Правку зеркал делает `--fix`.
#
# Список документов живёт в одном массиве: цикл сверки обязан покрыть v9 тем же прибором, что и v8,
# а не отдельной копией скрипта (иначе v9 расходится молча).
#
# `--selftest` (карточка `H-0151`) сажает дефект в temp-каталог: оригиналы и зеркала строятся
# здесь же, поэтому посадка не зависит от OneDrive хоста. Корень и каталог зеркал
# переопределяются `VEC_DHT_ROOT` / `SPEC_MIRROR_DIR`; без переменных поведение прежнее.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${VEC_DHT_ROOT:-$(cd "$SELF_DIR/.." && pwd)}"
MIRROR_DIR="${SPEC_MIRROR_DIR:-${HOME}/OneDrive/Desktop}"
DOCS=(VecDHT-SPEC-v8.md VecDHT-SPEC-v9.md)

if [[ "${1:-}" == "--selftest" ]]; then
  SELF="$SELF_DIR/$(basename "$0")"
  T="$(mktemp -d)" || { echo "ПРИБОР: mktemp не исполнен" >&2; exit 2; }
  trap 'rm -rf "$T"' EXIT
  mkdir -p "$T/orig/docs" "$T/mirror"
  printf 'спека v8\n' > "$T/orig/docs/VecDHT-SPEC-v8.md"
  printf 'спека v9\n' > "$T/orig/docs/VecDHT-SPEC-v9.md"
  cp "$T/orig/docs/"*.md "$T/mirror/"
  cases=0; passed=0
  run_case() { # $1 имя, $2 ожидаемый rc, $3 подстрока вывода
    cases=$((cases + 1))
    rc=0
    out=$(VEC_DHT_ROOT="$T/orig" SPEC_MIRROR_DIR="$T/mirror" bash "$SELF" 2>&1) || rc=$?
    if [ "$rc" = "$2" ] && printf '%s\n' "$out" | grep -qF "$3"; then
      passed=$((passed + 1)); echo "ПОСАДКА $1: OK (rc=$rc)"
    else
      echo "ПОСАДКА $1: FAIL — rc=$rc, ожидались rc=$2 и строка «$3»" >&2
    fi
  }
  run_case match 0 'OK: VecDHT-SPEC-v8.md'
  printf 'лишняя строка\n' >> "$T/mirror/VecDHT-SPEC-v9.md"
  run_case divergent 1 'зеркало разошлось с оригиналом'
  cp "$T/orig/docs/VecDHT-SPEC-v9.md" "$T/mirror/VecDHT-SPEC-v9.md"
  rm -f "$T/mirror/VecDHT-SPEC-v8.md"
  run_case no_mirror 1 'зеркала VecDHT-SPEC-v8.md нет на месте'
  rm -f "$T/orig/docs/VecDHT-SPEC-v9.md"
  run_case no_origin 2 'нет оригинала docs/VecDHT-SPEC-v9.md'
  echo "SMK_SELFTEST_CASES=$cases"
  echo "SMK_SELFTEST_PASSED=$passed"
  echo "SMK_SELFTEST_FAILED=$((cases - passed))"
  [ "$cases" = "$passed" ] && exit 0
  exit 1
fi

cd "$ROOT"

if [[ "${1:-}" == "--fix" ]]; then
  mkdir -p "$MIRROR_DIR"
fi

failed=0
missing=0
# нет оригинала = скрипт запущен не там, где надо (выход 2, как в версии до v9);
# разошлось или нет зеркала = настоящий провал guarded-файла (выход 1)
for name in "${DOCS[@]}"; do
  ORIG="docs/$name"
  MIRROR="${MIRROR_DIR}/$name"

  if [[ ! -f "$ORIG" ]]; then
    echo "FAIL: нет оригинала $ORIG (запускать из корня репозитория)" >&2
    missing=$((missing + 1))
    continue
  fi

  if [[ "${1:-}" != "--fix" && ! -f "$MIRROR" ]]; then
    echo "FAIL: зеркала $name нет на месте ($MIRROR); создать: ./lab/check-spec-mirror.sh --fix" >&2
    failed=$((failed + 1))
    continue
  fi

  if [[ "${1:-}" == "--fix" ]]; then
    cp "$ORIG" "$MIRROR"
    echo "зеркало обновлено из $ORIG"
  fi

  if diff -q "$ORIG" "$MIRROR" >/dev/null 2>&1; then
    echo "OK: $name — зеркало совпадает с оригиналом ($(wc -l < "$ORIG") строк, $(sha256sum "$ORIG" | cut -c1-12))"
    continue
  fi

  echo "FAIL: зеркало разошлось с оригиналом."
  echo "  оригинал: $ORIG"
  echo "  зеркало:  $MIRROR"
  # Guard в конце трубы обязателен: скрипт стоит под `set -euo pipefail`, `diff` на расхождении
  # возвращает 1, и без guard'а errexit обрывал скрипт здесь — раньше его же строки «починить:»
  # и до `failed=…` (класс измерен в `E-0128`; вердикт скрипта при этом не менялся, менялся
  # отчёт). Форма `diff … || true | head` не годится: она разбирается как `diff … || (true |
  # head)` и печатает пустоту — guard обязан стоять после всей трубы.
  diff "$ORIG" "$MIRROR" | head -40 || true
  failed=$((failed + 1))
done

if [ "$missing" -gt 0 ]; then exit 2; fi
if [ "$failed" -eq 0 ]; then exit 0; fi

echo "починить: ./lab/check-spec-mirror.sh --fix"
exit 1
