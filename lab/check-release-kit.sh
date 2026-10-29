#!/usr/bin/env bash
set -uo pipefail
# lab/check-release-kit.sh — релизный комплект v1 как исполняемый прибор (карточка H-0126/E-0126).
#
# Что проверяется и почему именно так (строка H1 в `ROADMAP.md` требует «a release tag exists with a
# build recipe and a changelog from v7.5»): до этого цикла в репозитории не было ни CHANGELOG.md, ни
# `.github/workflows/release.yml`, и версия в `Cargo.toml` оставалась `0.1.0`. Тег ставит владелец,
# поэтому прибор проверяет готовность к тегу, а не сам тег, и печатает `CK_TAG_EXISTS` как замер,
# а не как цель.
#
# Деградация: при отсутствующем файле прибор печатает ноль и продолжает считать остальные ключи, а
# не падает (правило контура: «прибор деградирует в нули, а не паникует»). Выход 1 — только если
# хоть один обязательный флаг равен нулю.
#
# Аргументы: [--dir ROOT] — корень дерева для проверки (по умолчанию корень репозитория). Посадка
# дефектов исполняется именно так: helper копирует нужные поддерева в temp-корень и запускает
# прибор с --dir, не трогая рабочее дерево во время прогона.
#
# `--selftest` (карточка `H-0151`) строит комплекты сам: пустой корень, здоровый комплект и
# комплект с одним снятым флагом. Без третьего случая «краснеет» означало бы только «пусто»,
# а не «видит конкретный нуль».

# --- самопроверка посадки ------------------------------------------------------
if [ "${1:-}" = "--selftest" ]; then
  SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  T="$(mktemp -d)" || { echo "ПРИБОР: mktemp не исполнен" >&2; exit 2; }
  trap 'rm -rf "$T"' EXIT
  cases=0; passed=0
  ok() { cases=$((cases + 1)); passed=$((passed + 1)); echo "ПОСАДКА $1: OK"; }
  no() { cases=$((cases + 1)); echo "ПОСАДКА $1: FAIL — $2" >&2; }

  mk_kit() { # $1 — корень здорового комплекта
    d="$1"
    mkdir -p "$d/.github/workflows" "$d/lab/decisions" "$d/sdk/vecdht-py"
    {
      echo '# Changelog'
      echo '## [0.2.0]'
      echo 'Релизный комплект, совместим с v7.5.'
      echo '- ADR-0044-queue'
    } > "$d/CHANGELOG.md"
    {
      echo 'on:'
      echo '  push:'
      echo '    tags:'
      echo "      - 'v*'"
      echo 'jobs:'
      echo '  release:'
      echo '    runs-on: ubuntu-latest'
      echo '    steps:'
      echo '      - run: cargo build --release -p vecdht-cli'
      echo '      - run: lab/workspace-verify.sh "$GITHUB_REF_NAME"'
      echo '      - uses: actions/upload-artifact@v4'
      echo '        with:'
      echo '          name: vecdht-cli'
    } > "$d/.github/workflows/release.yml"
    echo '[workspace.package]' > "$d/Cargo.toml"
    echo 'version = "0.2.0"' >> "$d/Cargo.toml"
    echo '[package]' > "$d/sdk/vecdht-py/Cargo.toml"
    echo 'version = "0.2.0"' >> "$d/sdk/vecdht-py/Cargo.toml"
    echo '# проект' > "$d/README.md"
    echo 'cargo build --release -p vecdht-cli' >> "$d/README.md"
    echo '# проект' > "$d/README.ru.md"
    echo 'cargo build --release -p vecdht-cli' >> "$d/README.ru.md"
    echo '# очередь' > "$d/lab/decisions/ADR-0044-queue.md"
  }

  # (а) пустой корень: обязательный флаг — ноль, выход 1
  mkdir -p "$T/empty"
  out=$(bash "$SELF" --dir "$T/empty" 2>&1); rc=$?
  if [ "$rc" = 1 ] && printf '%s\n' "$out" | grep -qx 'CK_CHANGELOG_EXISTS=0' \
     && printf '%s\n' "$out" | grep -qx 'KIT_FAIL=1'; then
    ok empty
  else
    no empty "rc=$rc, ожидались rc=1 и CK_CHANGELOG_EXISTS=0 плюс KIT_FAIL=1"
  fi

  # (б) здоровый комплект: выход 0
  mk_kit "$T/good"
  out=$(bash "$SELF" --dir "$T/good" 2>&1); rc=$?
  if [ "$rc" = 0 ] && printf '%s\n' "$out" | grep -qx 'KIT_FAIL=0'; then
    ok good
  else
    no good "rc=$rc, ожидался 0; нули: $(printf '%s\n' "$out" | grep -E '=0$' | tr '\n' ' ')"
  fi

  # (в) один снятый флаг в здоровом комплекте: rc 1, ноль ровно у него, соседний флаг цел
  cp -r "$T/good" "$T/defect"
  grep -v 'actions/upload-artifact' "$T/good/.github/workflows/release.yml" \
    > "$T/defect/.github/workflows/release.yml"
  out=$(bash "$SELF" --dir "$T/defect" 2>&1); rc=$?
  if [ "$rc" = 1 ] && printf '%s\n' "$out" | grep -qx 'CK_WORKFLOW_ARTIFACT=0' \
     && printf '%s\n' "$out" | grep -qx 'CK_CHANGELOG_EXISTS=1'; then
    ok defect
  else
    no defect "rc=$rc, ожидались rc=1, CK_WORKFLOW_ARTIFACT=0 и CK_CHANGELOG_EXISTS=1"
  fi

  echo "RKS_SELFTEST_CASES=$cases"
  echo "RKS_SELFTEST_PASSED=$passed"
  echo "RKS_SELFTEST_FAILED=$((cases - passed))"
  [ "$cases" = "$passed" ] && exit 0
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ "${1:-}" = "--dir" ] && ROOT="$2"

CHANGELOG="$ROOT/CHANGELOG.md"
WORKFLOW="$ROOT/.github/workflows/release.yml"
CARGO="$ROOT/Cargo.toml"
SDK_CARGO="$ROOT/sdk/vecdht-py/Cargo.toml"
recipe='cargo build --release -p vecdht-cli'

fail=0
emit() { printf '%s\n' "$1"; }
req() { # req КЛЮЧ=значение — обязательный флаг: ноль красит выход.
  # Форма аргумента выбрана не ради красоты: `lab/threshold-lint.py` признаёт факт напечатанным,
  # только если в источнике имя стоит рядом с `=`. Вариант `req КЛЮЧ "$значение"` оставлял 13 ключей
  # сиротами, и линт краснел вместо того, чтобы краснеть прогону (ДИАГНОЗ-3 карточки E-0126).
  emit "$1"
  case "$1" in *=0) fail=1 ;; esac
}

# --- CHANGELOG ---------------------------------------------------------------
if [ -f "$CHANGELOG" ]; then cex=1; else cex=0; fi
req CK_CHANGELOG_EXISTS="$cex"

if [ "$cex" = 1 ] && grep -q 'v7\.5' "$CHANGELOG"; then f75=1; else f75=0; fi
req CK_CHANGELOG_FROM_V75="$f75"

# Диапазон ADR релизной очереди: 0044 (очередь и шесть решений владельца) … 0066 (бюджет промахов).
# Число НЕ пишется литералом: оно выводится из дерева, иначе правка множества ADR молча обнулила бы
# ожидание; дыра в диапазоне даёт 22 вместо 23 и ловится ожиданием. Перебираются файлы каталога, а не
# маска: первая версия писала `ls "$ROOT"/lab/decisions/ADR-0"$n"-*.md` и получала `ADR-044` при файле
# `ADR-0044` (ДИАГНОЗ-1 карточки E-0126), вторая — `"$pat"` в кавычках, где `*` не раскрывается вовсе
# (ДИАГНОЗ-2); оба брака дают ровно тот же нуль, что и отсутствующий CHANGELOG, то есть невыявляемы.
ADR_FIRST=44
ADR_LAST=66
total=0; listed=0
for f in "$ROOT"/lab/decisions/ADR-*.md; do
  [ -e "$f" ] || continue
  num=$(basename "$f" | sed -E 's/^ADR-([0-9]{4})-.*/\1/; s/^0+//')
  case "$num" in ''|*[!0-9]*) continue ;; esac
  [ "$num" -ge "$ADR_FIRST" ] || continue
  [ "$num" -le "$ADR_LAST" ] || continue
  total=$((total + 1))
  name=$(basename "$f" | sed 's/\.md$//')
  if [ "$cex" = 1 ] && grep -qF "$name" "$CHANGELOG"; then listed=$((listed + 1)); fi
done
emit "CK_ADR_RANGE_TOTAL=$total"
emit "CK_ADR_LISTED=$listed"
if [ "$total" -gt 0 ] && [ "$listed" = "$total" ]; then aall=1; else aall=0; fi
req CK_ADR_ALL="$aall"

# --- workflow релиза ---------------------------------------------------------
if [ -f "$WORKFLOW" ]; then wex=1; else wex=0; fi
req CK_WORKFLOW_EXISTS="$wex"

if [ "$wex" = 1 ] && awk '/^on:/{o=1} o && /^  push:/{p=1} p && /tags:/{print "yes"; exit}' "$WORKFLOW" | grep -q yes; then
  wtag=1
else
  wtag=0
fi
req CK_WORKFLOW_ON_TAG="$wtag"

if [ "$wex" = 1 ] && grep -q 'lab/workspace-verify.sh' "$WORKFLOW"; then wv=1; else wv=0; fi
req CK_WORKFLOW_RUNS_VERIFY="$wv"

# H1 требует не «CI что-то прогоняет», а «тег называет блок лога, который он produced»: значит
# аргументом script'у передаётся имя тега, а не литеральный run-id, придуманный человеком.
if [ "$wex" = 1 ] && grep -qE 'lab/workspace-verify\.sh.*GITHUB_REF_NAME' "$WORKFLOW"; then wr=1; else wr=0; fi
req CK_WORKFLOW_RUNID="$wr"

# Рецепт сборки из README обязан быть тем же, что исполняет CI, иначе «build recipe» и «built
# artifact» — две разные сборки (проверяется одна и та же литерная строка команды).
if [ "$wex" = 1 ] && grep -qF "$recipe" "$WORKFLOW"; then wb=1; else wb=0; fi
req CK_WORKFLOW_BUILDS_RECIPE="$wb"

if [ "$wex" = 1 ] && grep -q 'actions/upload-artifact' "$WORKFLOW" && grep -q 'vecdht-cli' "$WORKFLOW"; then wa=1; else wa=0; fi
req CK_WORKFLOW_ARTIFACT="$wa"

if [ "$wex" = 1 ] && python -c "import sys,yaml; yaml.safe_load(open(sys.argv[1],encoding='utf-8'))" "$WORKFLOW" 2>/dev/null; then
  y=1
else
  y=0
fi
req CK_YAML_PARSE="$y"

# --- версия и рецепт сборки --------------------------------------------------
# Версия объявлена дважды: `version` в `[workspace.package]` и своя строка в `sdk/vecdht-py` (он вне
# `members`). Расходятся — и SDK уезжает с чужим номером, поэтому `CK_VERSION_ALL` требует равенства
# трёх носителей, а не двух.
vc=$(grep -m1 '^version' "$CARGO" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$vc" ] || vc=none
emit "CK_VERSION_CARGO=$vc"
vs=$(grep -m1 '^version' "$SDK_CARGO" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$vs" ] || vs=none
emit "CK_VERSION_SDK=$vs"
vch=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$CHANGELOG" 2>/dev/null | sed -E 's/^## \[([^]]+)\]/\1/')
[ -n "$vch" ] || vch=none
emit "CK_VERSION_CHANGELOG=$vch"
if [ "$vc" != none ] && [ "$vc" = "$vch" ]; then veq=1; else veq=0; fi
req CK_VERSION_EQ="$veq"
if [ "$veq" = 1 ] && [ "$vs" != none ] && [ "$vs" = "$vc" ]; then vall=1; else vall=0; fi
req CK_VERSION_ALL="$vall"

# Рецепт сборки назван в обоих README одинаковой командой — критерий H1 говорит «build recipe»,
# а не «ссылка на сборку»: проверяется строка команды, а не наличие заголовка.
if grep -qF "$recipe" "$ROOT/README.md" 2>/dev/null && grep -qF "$recipe" "$ROOT/README.ru.md" 2>/dev/null; then
  rr=1
else
  rr=0
fi
req CK_README_RECIPE="$rr"

# --- тег ---------------------------------------------------------------
# Замер, а не цель: исполнитель обязан НЕ ставить тег (красная зона владельца).
if [ -n "$(git -C "$ROOT" tag 2>/dev/null)" ]; then tg=1; else tg=0; fi
emit "CK_TAG_EXISTS=$tg"

emit "KIT_FAIL=$fail"
[ "$fail" = 0 ] || exit 1
exit 0
