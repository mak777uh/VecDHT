#!/usr/bin/env bash
# Guard AGENTS.md №5: зеркало спеки обязано быть побайтово равным оригиналу.
#
#     docs/VecDHT-SPEC-v8.md                    — оригинал (в git)
#     ~/OneDrive/Desktop/VecDHT-SPEC-v8.md      — зеркало (вне git, читается владельцем)
#
# Запускать перед каждым коммитом, трогающим спеку: зеркало не коммитится, поэтому его
# расхождение не видно ни в git status, ни в CI — только здесь. Выход 0 — зеркало совпал,
# выход 1 — разошлось (печатается diffstat). Правку зеркала делает `--fix`.
set -euo pipefail

cd "$(dirname "$0")/.."
ORIG="docs/VecDHT-SPEC-v8.md"
MIRROR="${HOME}/OneDrive/Desktop/VecDHT-SPEC-v8.md"

if [[ ! -f "$ORIG" ]]; then
  echo "FAIL: нет оригинала $ORIG (запускать из корня репозитория)" >&2
  exit 2
fi

if [[ "${1:-}" == "--fix" ]]; then
  mkdir -p "$(dirname "$MIRROR")"
  cp "$ORIG" "$MIRROR"
  echo "зеркало обновлено из $ORIG"
fi

if diff -q "$ORIG" "$MIRROR" >/dev/null 2>&1; then
  echo "OK: зеркало спеки совпадает с оригиналом ($(wc -l < "$ORIG") строк, $(sha256sum "$ORIG" | cut -c1-12))"
  exit 0
fi

echo "FAIL: зеркало разошлось с оригиналом."
echo "  оригинал: $ORIG"
echo "  зеркало:  $MIRROR"
diff "$ORIG" "$MIRROR" | head -40
echo "починить: ./lab/check-spec-mirror.sh --fix"
exit 1
