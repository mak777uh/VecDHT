#!/usr/bin/env bash
# E-0126 (A7): релизный комплект v1 обязан быть исполняемым фактом, а не списком в плане
# (H-0126). Порог заморожен коммитом пре-регистрации до правки; прибор — `lab/check-release-kit.sh`,
# таблица — `lab/expectations/e0126.tsv`.
#
# Шаги:
#   (0) гейт карточки и носитель до прогона;
#   (1) PRE_FIX: дерево пина `d18ad2b` из `git archive` + нынешний прибор копией внутрь (прибора на
#       пине нет), прогон `--dir` обязан быть красным, а счётчик ADR — всё ещё 23;
#   (2) живой прогон на рабочем дереве: вывод прибора переносится в файл фактов дословно;
#   (3) шесть посадок дефекта на копиях дерева (живое дерево не трогается), каждая обязана изменить
#       байт и покраснеть, а соседний флаг — остаться единицей (иначе ноль не отличим от слепоты);
#   (4) независимый пересчёт диапазона ADR другим кодом (`ls` + `sed` + `awk`);
#   (5) всё выше исполняется дважды на неизменном дереве -> `STABLE` по `diff -q`;
#   (6) границы правки (`CODE_CHANGED_RS`), синхронность `Cargo.lock` (`cargo metadata --locked`);
#   (7) полный контур стражей (текст, threshold-lint, claim-map, repo-review, зеркало спеки);
#   (8) посадка неверного ожидания: `lab/expect.py` обязан покраснеть;
#   (9) сверка `lab/expectations/e0126.tsv` с двумя файлами фактов;
#   (10) носитель после прогона.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0126-all.log"
PIN=d18ad2b
EXPECT="lab/expectations/e0126.tsv"
KIT="lab/check-release-kit.sh"
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0126.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
G="$OUT/facts_global.txt"
F1="$OUT/facts1.txt"
F2="$OUT/facts2.txt"
: > "$G"; : > "$F1"; : > "$F2"
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Общий факт пишется литералом в двойных кавычках: `lab/threshold-lint.py` считает ключ напечатанным,
# только если слева стоит начало строки, кавычка или пробел.
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
femit() { printf '%s\n' "$2" >> "$1"; }
# Флаг из вывода прибора: строка `KEY=значение` с якорем по началу строки. Пустое значение печатается
# как MISSING и красит сверку: молчание прогона не считается успехом.
flag() { # flag <файл-вывода> <ключ>
  local v
  v=$(sed -n "s|^${2}=||p" "$1" 2>/dev/null | head -1)
  [ -n "$v" ] || v=MISSING
  printf '%s' "$v"
}

say "########## E-0126 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py H-0126 2>&1 | tail -n 12 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0126_OK=${gok}"
[ "$gok" = 1 ] || note 1
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf '%s' "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
emit0 "DISK_GE_15000=${dok}"
[ "$dok" = 1 ] || note 1

# --- одно измерение: PRE_FIX + живой прогон + посадки + пересчёт ----------------
measure() { # measure <файл-фактов> <метка исполнения>
  local F="$1" tag="$2" r root p v rc
  root="$OUT/root-$tag"; pfx="$OUT/prefix-$tag"; base="$OUT/base-$tag"
  mkdir -p "$root" "$pfx" "$base/.github/workflows" "$base/sdk/vecdht-py" "$base/lab/decisions"

  say "### ШАГ 1.${tag} PRE_FIX: пин ${PIN} + нынешний прибор ### $(date +%FT%T%:z)"
  git archive --format=tar "$PIN" | tar -x -C "$pfx"
  cp "$KIT" "$pfx/lab/check-release-kit.sh"
  bash "$pfx/lab/check-release-kit.sh" --dir "$pfx" > "$OUT/prefix-$tag.txt" 2>&1
  rc=$?
  cat "$OUT/prefix-$tag.txt" | tee -a "$LOG"
  # Имена фактов печатаются литералом, а не шаблоном `PRE_FIX_${k}=`: `lab/threshold-lint.py` не
  # считает такую строку напечатанным фактом, и ключ остался бы сиротой (прецедент `E-0095`).
  femit "$F" "PRE_FIX_CK_CHANGELOG_EXISTS=$(flag "$OUT/prefix-$tag.txt" "CK_CHANGELOG_EXISTS")"
  femit "$F" "PRE_FIX_CK_WORKFLOW_EXISTS=$(flag "$OUT/prefix-$tag.txt" "CK_WORKFLOW_EXISTS")"
  femit "$F" "PRE_FIX_CK_ADR_LISTED=$(flag "$OUT/prefix-$tag.txt" "CK_ADR_LISTED")"
  femit "$F" "PRE_FIX_CK_ADR_RANGE_TOTAL=$(flag "$OUT/prefix-$tag.txt" "CK_ADR_RANGE_TOTAL")"
  femit "$F" "PRE_FIX_KIT_FAIL=$(flag "$OUT/prefix-$tag.txt" "KIT_FAIL")"
  femit "$F" "PRE_FIX_EXIT=${rc}"
  if [ "$(flag "$OUT/prefix-$tag.txt" "CK_CHANGELOG_EXISTS")" = 0 ] \
     && [ "$(flag "$OUT/prefix-$tag.txt" "CK_ADR_RANGE_TOTAL")" = 23 ] && [ "$rc" -ne 0 ]; then
    say "PRE_FIX ok: комплект красен, счётчик ADR жив"
  else
    say "PRE_FIX ПРОВАЛ: пин не красный или прибор ослеп — порог (2) не выполнен"; note 1
  fi

  say "### ШАГ 2.${tag} живой прогон на рабочем дереве ### $(date +%FT%T%:z)"
  bash "$KIT" > "$OUT/live-$tag.txt" 2>&1
  rc=$?
  cat "$OUT/live-$tag.txt" | tee -a "$LOG"
  cat "$OUT/live-$tag.txt" >> "$F"
  femit "$F" "KIT_EXIT=${rc}"
  [ "$rc" -eq 0 ] || note 1

  say "### ШАГ 3.${tag} независимый пересчёт диапазона ADR ### $(date +%FT%T%:z)"
  r=$(ls "$VEC_DHT_ROOT"/lab/decisions 2>/dev/null | sed -nE 's/^ADR-([0-9]{4})-.*\.md$/\1/p' \
      | awk '{n=$1+0; if (n>=44 && n<=66) c++} END{print c+0}')
  femit "$F" "ADR_INDEP_COUNT=${r}"
  if [ "$r" = "$(flag "$OUT/live-$tag.txt" "CK_ADR_RANGE_TOTAL")" ]; then eq=1; else eq=0; fi
  femit "$F" "ADR_COUNT_EQ=${eq}"
  [ "$eq" = 1 ] || note 1

  say "### ШАГ 4.${tag} шесть посадок на копиях дерева ### $(date +%FT%T%:z)"
  for f in CHANGELOG.md README.md README.ru.md Cargo.toml; do
    [ -f "$VEC_DHT_ROOT/$f" ] && cp "$VEC_DHT_ROOT/$f" "$base/"
  done
  [ -f "$VEC_DHT_ROOT/.github/workflows/release.yml" ] &&
    cp "$VEC_DHT_ROOT/.github/workflows/release.yml" "$base/.github/workflows/"
  [ -f "$VEC_DHT_ROOT/sdk/vecdht-py/Cargo.toml" ] &&
    cp "$VEC_DHT_ROOT/sdk/vecdht-py/Cargo.toml" "$base/sdk/vecdht-py/"
  cp "$VEC_DHT_ROOT"/lab/decisions/ADR-*.md "$base/lab/decisions/"

  landed=0; red=0
  # (а) CHANGELOG удалён целиком.
  p="$root/a"; rm -rf "$p"; cp -r "$base" "$p"; rm -f "$p/CHANGELOG.md"
  [ ! -e "$p/CHANGELOG.md" ] && landed=$((landed + 1))
  bash "$KIT" --dir "$p" > "$OUT/plant-a-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_A_CHANGELOG=$(flag "$OUT/plant-a-$tag.txt" "CK_CHANGELOG_EXISTS")"
  femit "$F" "PLANT_A_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # (б) из CHANGELOG вычеркнута одна строка ADR -> listing меньше total на 1.
  p="$root/b"; rm -rf "$p"; cp -r "$base" "$p"
  sed -i '/ADR-0050-revocation-durable-after-restart/d' "$p/CHANGELOG.md" 2>/dev/null
  diff -q "$base/CHANGELOG.md" "$p/CHANGELOG.md" >/dev/null 2>&1 || landed=$((landed + 1))
  bash "$KIT" --dir "$p" > "$OUT/plant-b-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_B_ADR_ALL=$(flag "$OUT/plant-b-$tag.txt" "CK_ADR_ALL")"
  femit "$F" "PLANT_B_LISTED=$(flag "$OUT/plant-b-$tag.txt" "CK_ADR_LISTED")"
  femit "$F" "PLANT_B_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # (в) `push:` заменён на `pull_request:`: YAML остаётся валидным, тега больше нет.
  p="$root/c"; rm -rf "$p"; cp -r "$base" "$p"
  sed -i 's|^  push:|  pull_request:|' "$p/.github/workflows/release.yml" 2>/dev/null
  diff -q "$base/.github/workflows/release.yml" "$p/.github/workflows/release.yml" >/dev/null 2>&1 ||
    landed=$((landed + 1))
  bash "$KIT" --dir "$p" > "$OUT/plant-c-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_C_ON_TAG=$(flag "$OUT/plant-c-$tag.txt" "CK_WORKFLOW_ON_TAG")"
  femit "$F" "PLANT_C_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # (г) `$GITHUB_REF_NAME` -> литеральный id: вызов верификации остаётся, имя блока теряется.
  p="$root/d"; rm -rf "$p"; cp -r "$base" "$p"
  sed -i 's|\$GITHUB_REF_NAME|ci-static-id|' "$p/.github/workflows/release.yml" 2>/dev/null
  diff -q "$base/.github/workflows/release.yml" "$p/.github/workflows/release.yml" >/dev/null 2>&1 ||
    landed=$((landed + 1))
  bash "$KIT" --dir "$p" > "$OUT/plant-d-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_D_RUNID=$(flag "$OUT/plant-d-$tag.txt" "CK_WORKFLOW_RUNID")"
  femit "$F" "PLANT_D_RUNS_VERIFY=$(flag "$OUT/plant-d-$tag.txt" "CK_WORKFLOW_RUNS_VERIFY")"
  femit "$F" "PLANT_D_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # (д) SDK вернулся к `0.1.0`: Cargo/CHANGELOG согласованы, третий носитель нет.
  p="$root/e"; rm -rf "$p"; cp -r "$base" "$p"
  sed -i 's|^version = "1\.0\.0"|version = "0.1.0"|' "$p/sdk/vecdht-py/Cargo.toml" 2>/dev/null
  diff -q "$base/sdk/vecdht-py/Cargo.toml" "$p/sdk/vecdht-py/Cargo.toml" >/dev/null 2>&1 ||
    landed=$((landed + 1))
  bash "$KIT" --dir "$p" > "$OUT/plant-e-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_E_VERSION_ALL=$(flag "$OUT/plant-e-$tag.txt" "CK_VERSION_ALL")"
  femit "$F" "PLANT_E_VERSION_EQ=$(flag "$OUT/plant-e-$tag.txt" "CK_VERSION_EQ")"
  femit "$F" "PLANT_E_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # (ё) неразбираемый YAML: артефакт назван, parse краснеет один.
  p="$root/f"; rm -rf "$p"; cp -r "$base" "$p"
  printf '\tzzz: сломано\n' >> "$p/.github/workflows/release.yml" 2>/dev/null
  diff -q "$base/.github/workflows/release.yml" "$p/.github/workflows/release.yml" >/dev/null 2>&1 ||
    landed=$((landed + 1))
  bash "$KIT" --dir "$p" > "$OUT/plant-f-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_F_YAML=$(flag "$OUT/plant-f-$tag.txt" "CK_YAML_PARSE")"
  femit "$F" "PLANT_F_ARTIFACT=$(flag "$OUT/plant-f-$tag.txt" "CK_WORKFLOW_ARTIFACT")"
  femit "$F" "PLANT_F_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))

  femit "$F" "PLANT_LANDED=${landed}"
  if [ "$landed" = 6 ] && [ "$red" = 6 ]; then ar=1; else ar=0; fi
  femit "$F" "PLANT_ALL_RED=${ar}"
  say "посадки: байт изменён ${landed}/6, красных ${red}/6"
  [ "$ar" = 1 ] || note 1
}

say "########## ИЗМЕРЕНИЕ 1 ##########"
measure "$F1" 1
say "########## ИЗМЕРЕНИЕ 2 ##########"
measure "$F2" 2

if diff -q "$F1" "$F2" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
[ "$st" = 1 ] || note 1
say "два исполнения сравнены построчно (diff -q): STABLE=${st}"

say "### ШАГ 6 границы правки и синхронность Cargo.lock ### $(date +%FT%T%:z)"
rs=$(git diff --name-only "$PIN" -- '*.rs' 2>/dev/null | grep -cve '^lab/' || true)
emit0 "CODE_CHANGED_RS=${rs:-0}"
[ "${rs:-0}" = 0 ] || note 1
# ДИАГНОЗ-4 (после пре-регистрации, до замера): без `--filter-platform` этот вызов красен на хосте
# by construction. `cargo metadata` скачивает манифесты ВСЕХ таргетов, а Unix--only `async-io
# v2.6.0` в локальном кэше отсутствует (под Windows он не собирается), и его нельзя дотянуть:
# `cargo metadata --locked` без `--offline` даёт «transfer too slow: failed to transfer more than
# 10 bytes in 30s», а `curl https://static.crates.io/...` — «schannel: failed to receive handshake».
# Фильтр по таргету хоста меняет только множество скачиваемых манифестов: `--locked` по-прежнему
# краснит выход, если `Cargo.lock` отстал от новой версии (измерено на копии дерева: версия
# `[workspace.package]` 9.9.9 при прежнем `Cargo.lock` даёт 101).
cargo metadata --locked --offline --filter-platform x86_64-pc-windows-gnu --format-version 1 \
  > "$OUT/meta.txt" 2>&1
rc=$?
emit0 "CARGO_METADATA_LOCKED_EXIT=${rc}"
note "$rc"
printf 'cargo metadata (--locked --offline, таргет хоста): байт вывода=%s\n' \
  "$(wc -c < "$OUT/meta.txt")" | tee -a "$LOG"
[ "$rc" = 0 ] || tail -n 4 "$OUT/meta.txt" | tee -a "$LOG"

say "### ШАГ 7 полный контур стражей ### $(date +%FT%T%:z)"
CYCLE_FILES="$KIT $EXPECT lab/e0126-run.sh CHANGELOG.md .github/workflows/release.yml \
lab/hypotheses/H-0126-release-kit-ready-for-tag.md \
lab/experiments/E-0126-release-kit-ready-for-tag.md \
lab/decisions/ADR-0067-release-kit-is-checked-not-promised.md"
# shellcheck disable=SC2086
bash lab/check-text-clean.sh $CYCLE_FILES 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "TEXTGUARD_EXIT=${rc}"; note "$rc"
python lab/threshold-lint.py "$EXPECT" --helper lab/e0126-run.sh \
  --sources "$KIT" lab/e0126-run.sh 2>&1 | tail -4 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "LINT_EXIT=${rc}"; note "$rc"
python lab/check-claim-map.py 2>&1 | tail -2 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "CLAIMMAP_EXIT=${rc}"; note "$rc"
python lab/repo-review.py 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "REPO_REVIEW_EXIT=${rc}"; note "$rc"
bash lab/check-spec-mirror.sh 2>&1 | tail -2 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "MIRROR_EXIT=${rc}"; note "$rc"

say "### ШАГ 8 посадка неверного ожидания ### $(date +%FT%T%:z)"
awk -F'\t' 'BEGIN{OFS="\t"} $1=="CK_ADR_ALL"{$2="0"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^CK_ADR_ALL\t0\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка CK_ADR_ALL в таблице не найдена"
  plant=0
else
  cat "$G" >> "$F1"
  python lab/expect.py "$OUT/plant.tsv" "$F1" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
[ "$plant" = 1 ] || note 1

say "### ШАГ 9 сверка ожиданий ### $(date +%FT%T%:z)"
cat "$G" >> "$F2"
python lab/expect.py "$EXPECT" "$F1" "$F2" 2>&1 | tail -n 20 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "EXPECT_EXIT=%s\n" "$rc" | tee -a "$LOG"
note "$rc"

say "### ШАГ 10 носитель после ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
