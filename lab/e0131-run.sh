#!/usr/bin/env bash
# H-0131 / E-0131 (ADR-0072): переносимое из flowguard-spec — пара стражей, каждый с посадкой.
#
# Что мерится. Три свойства двух приборов, а не их наличие:
# (1) краснота на живом дереве до починки (`--tag PRE_FIX_`): восемь абсолютных путей домашнего
#     каталога в tracked и восемнадцать висячих backtick-цитат;
# (2) самотесты с посадками: синтетический токен, вымышленный путь и УСТАРЕВШЕЕ разрешение —
#     все три обязаны быть названы, иначе страж, который что-то разрешает, не страж;
# (3) зелень после починки при неизменных свидетельствах: шесть Lean-моделей в дереве остались
#     шестью, `crates/` не тронут, зеркало спеки не тронуто.
#
# Independent-счётчик `LOCALPATH_TRACKED_OUTSIDE_LOGS` печатается в обход стража (свой `git grep`):
# число, которое вычисляет сам прибор, не должно быть единственным свидетелем его же вердикта.
#
# PRE_FIX-исполнение — тот же прибор на том же дереве ДО починки; после починки helper
# зовётся дважды без аргумента, и два набора фактов сравниваются (`STABLE`).
set -uo pipefail
TAG=""
if [ "${1:-}" = "--tag" ]; then TAG="${2:-}"; fi
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PYTHONIOENCODING=utf-8

buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }

# (0) Гейт карточки и диск.
python lab/cycle-gate.py gate H-0131 >>"$buf" 2>&1 && emit GATE_H0131_OK 1 || emit GATE_H0131_OK 0
bash lab/disk-report.sh >lab/.e0131-disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' lab/.e0131-disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"
[ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# (1) Страж секретов: самотест, затем дерево; история отдельным фактом.
bash lab/check-secrets.sh --selftest >lab/.e0131-sec-st.txt 2>&1
emit SECRETS_SELFTEST_EXIT $?
ST_SEC=$(grep -c 'НАХОДКА\[секрет\]' lab/.e0131-sec-st.txt || true)
[ "${ST_SEC:-0}" -ge 1 ] && emit PLANT_SECRET_CAUGHT 1 || emit PLANT_SECRET_CAUGHT 0
bash lab/check-secrets.sh >lab/.e0131-sec.txt 2>&1
emit SECRETS_EXIT $?
emit SECRETS_FINDINGS "$(grep -c '^НАХОДКА' lab/.e0131-sec.txt || true)"
grep -E '^(GITCONFIG_REMOTE|ИСТОРИЯ_СОВПАДЕНИЙ)=' lab/.e0131-sec.txt |
  while IFS== read -r k v; do
    [ "$k" = "ИСТОРИЯ_СОВПАДЕНИЙ" ] && k=SECRETS_HISTORY
    printf '%s=%s\n' "$k" "$v" >>"$buf"
  done
LOC=$(git grep -I -l -E 'C:\\Users\\[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+' -- . ':(exclude)lab/logs' 2>/dev/null | wc -l)
emit LOCALPATH_TRACKED_OUTSIDE_LOGS "$LOC"

# (2) Страж цитат: самотест с тремя проверками, затем дерево.
python lab/check-artifact-refs.py --selftest >lab/.e0131-refs-st.txt 2>&1
emit REFS_SELFTEST_EXIT $?
grep -q 'PLANT_REF=caught' lab/.e0131-refs-st.txt && emit PLANT_REF_CAUGHT 1 || emit PLANT_REF_CAUGHT 0
grep -q 'STALE_ALLOWLIST=caught' lab/.e0131-refs-st.txt && emit STALE_ALLOWLIST_CAUGHT 1 || emit STALE_ALLOWLIST_CAUGHT 0
python lab/check-artifact-refs.py >lab/.e0131-refs.txt 2>&1
emit REFS_EXIT $?
grep -E '^REFS_(CITED|MISSING|ALLOWED|ALLOWLIST_EMPTY)=' lab/.e0131-refs.txt |
  while IFS== read -r k v; do
    [ "$k" = "REFS_ALLOWLIST_EMPTY" ] && k=ALLOWLIST_EMPTY_REASON
    printf '%s=%s\n' "$k" "$v" >>"$buf"
  done

# (3) Неизменность свидетельств и остальной контур.
emit LEAN_MODELS_TRACKED "$(git ls-files '*.lean' | wc -l)"
emit RUST_TOUCHED "$(git diff --name-only HEAD -- crates/ | wc -l)"
bash lab/check-text-clean.sh >lab/.e0131-text.txt 2>&1
emit TEXTGUARD_EXIT $?
bash lab/check-spec-mirror.sh >lab/.e0131-mirror.txt 2>&1
emit MIRROR_EXIT $?
python lab/cycle-gate.py audit >lab/.e0131-audit.txt 2>&1
emit GATE_AUDIT_EXIT $?
emit CI_GUARD_STEPS "$(grep -c -E 'check-secrets\.sh|check-artifact-refs\.py' .github/workflows/verify.yml || true)"

# STABLE — сравнение с предыдущим снимком фактов того же дерева, если он есть: второй прогон
# обязан совпасть, иначе факты не годятся в порог (правило 7 пункта (е)).
if [ -z "$TAG" ] && [ -f lab/.e0131-post1.facts ]; then
  if diff -q <(grep -v DISK_FREE_MB "$buf") <(grep -v DISK_FREE_MB lab/.e0131-post1.facts) >/dev/null; then
    emit STABLE 1
  else
    emit STABLE 0
  fi
fi
if [ -n "$TAG" ]; then sed "s/^/${TAG}/" "$buf"; else cat "$buf"; fi
rm -f "$buf"
