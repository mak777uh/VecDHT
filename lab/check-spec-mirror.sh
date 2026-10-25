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
set -euo pipefail

cd "$(dirname "$0")/.."
MIRROR_DIR="${HOME}/OneDrive/Desktop"
DOCS=(VecDHT-SPEC-v8.md VecDHT-SPEC-v9.md)

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
  diff "$ORIG" "$MIRROR" | head -40
  failed=$((failed + 1))
done

if [ "$missing" -gt 0 ]; then exit 2; fi
if [ "$failed" -eq 0 ]; then exit 0; fi

echo "починить: ./lab/check-spec-mirror.sh --fix"
exit 1
