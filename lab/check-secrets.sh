#!/usr/bin/env bash
# H-0131 / E-0131 (ADR-0072): страж секретов и локальных путей.
#
# Перенесено из flowguard-spec (`lab/check-secrets.sh`), но без их предупреждающего режима: у нас
# молчание = провал, поэтому любая находка — выход 1. Их страж предупреждал; наш краснеет.
#
# Три проверки, каждая с названным вредителем:
# (1) токены и приватные ключи в tracked-файлах — утечка, которую нельзя отозвать пушем;
# (2) токены в истории (`git log -p --all`) — история не переписывается, значит найденное там
#     живёт вечно и должно быть названо вслух; исключение `lab/logs` не делается: носитель лога
#     обязан цитировать счёт, а не чужой токен;
# (3) абсолютный локальный путь пользователя в tracked-файлах вне `lab/logs/` — не секрет, но
#     непереносимо: сторонний реализатор не может ни прочитать упомянутый файл, ни повторить
#     команду. `lab/logs/` исключён осознанно: носитель обязан цитировать реальные пути прогона,
#     и вырезать их означало бы уничтожить свидетельство.
# (4) `.git/config`: удалённый URL не обязан содержать вложенных учётных данных; если содержит —
#     это тот же токен, что и (1), только в конфиге, который `git ls-files` не видит.
#
# `--selftest` сажает три дефекта в временный каталог (синтетические формы, настоящих секретов в
# репозитории нет и не будет) и требует, чтобы страж назвал каждый; без этого теста страж,
# который что-то разрешает, не имеет права считаться стражем (ДИАГНОЗ-2 цикла E-0130).
#
# Выход: 0 — чисто; 1 — находки напечатаны; 2 — сломан сам прибор (нет git, нет репозитория).
set -uo pipefail

SELFTEST=0
NO_HISTORY=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --selftest) SELFTEST=1 ;;
    --no-history) NO_HISTORY=1 ;;
    *) ARGS+=("$a") ;;
  esac
done

# Паттерны утечки. Все формы синтетические: настоящий GitHub-токен — `ghp_` + 36 base62,
# пат `github_pat_` + 57, AWS Access Key ID — `AKIA` + 16.
SECRET_RE='ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|gh[osu]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
# Пути, выдающие одного конкретного пользователя на одной конкретной машине.
LOCALPATH_RE='C:\\Users\\[^\\ ]+|[Pp]roject[Ee]xport|[A-Za-z]:\\Users\\|[[:space:]]/home/[a-z][a-z0-9_.-]{2,}|/Users/[a-z][a-z0-9_.-]{2,}'

findings=0
report() {
  # $1 = проверка, $2 = «файл:строка», $3 = сокровённая находка
  printf 'НАХОДКА[%s] %s :: %s\n' "$1" "$2" "$3"
  findings=$((findings + 1))
}

check_blob() {
  # Один файл, произвольный путь: секрет + (если разрешено) локальный путь.
  local f="$1" skip_localpaths="${2:-0}"
  [ -f "$f" ] || return 0
  while IFS=: read -r ln text; do
    [ -n "${ln:-}" ] || continue
    report "секрет" "$f:$ln" "$(printf '%s' "$text" | cut -c1-72)"
  done < <(grep -nIE "$SECRET_RE" "$f" 2>/dev/null || true)
  if [ "$skip_localpaths" != 1 ]; then
    while IFS=: read -r ln text; do
      [ -n "${ln:-}" ] || continue
      report "локальный_путь" "$f:$ln" "$(printf '%s' "$text" | cut -c1-72)"
    done < <(grep -nIE "$LOCALPATH_RE" "$f" 2>/dev/null || true)
  fi
}

scan_tree() {
  # Режим репозитория: только tracked-файлы, бинарники пропускаем (-I).
  local files
  files=$(git ls-files) || { echo "ПРИБОР: git ls-files не исполнен" >&2; exit 2; }
  for f in $files; do
    case "$f" in
      lab/logs/*) check_blob "$f" 1 ;;
      *) check_blob "$f" 0 ;;
    esac
  done
}

scan_history() {
  local n=0
  n=$(git log -p --all 2>/dev/null | grep -cIE "$SECRET_RE" || true)
  if [ "${n:-0}" != 0 ]; then
    report "секрет_в_истории" "git log -p --all" "совпадений=$n"
  fi
  echo "ИСТОРИЯ_СОВПАДЕНИЙ=$n"
}

scan_gitconfig() {
  local url=""
  url=$(git config --get remote.origin.url 2>/dev/null || true)
  [ -n "$url" ] || { echo "GITCONFIG_REMOTE=none"; return 0; }
  if printf '%s' "$url" | grep -qE '://[^/@:]+(:[^/@]+)?@'; then
    report "секрет_в_git_config" "remote.origin.url" "вложенные учётные данные"
  fi
  echo "GITCONFIG_REMOTE=clean"
}

run_selftest() {
  local tmp rc
  tmp=$(mktemp -d) || { echo "ПРИБОР: mktemp не исполнен" >&2; exit 2; }
  mkdir -p "$tmp/sub"
  printf 'token = ghp_%s\n' "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" > "$tmp/a.txt"
  printf 'key = AKIA%s\n' "ABCDEFGHIJKLMNOP" >> "$tmp/a.txt"
  printf 'p = C:\\Users\\someone\\work\\x.rs\n' > "$tmp/sub/b.md"
  printf 'чисто: lab/disk-report.sh и E-0131\n' > "$tmp/clean.md"
  rc=0
  check_blob "$tmp/a.txt" 0
  check_blob "$tmp/sub/b.md" 0
  check_blob "$tmp/clean.md" 0
  [ "$findings" = 3 ] || { echo "САМОТЕСТ: посадок 3, названо $findings" >&2; rc=1; }
  # Отрицательная ветка: чистый файл не обязан дать ни одной находки.
  findings=0
  check_blob "$tmp/clean.md" 0
  [ "$findings" = 0 ] || { echo "САМОТЕСТ: чистый файл дал находки" >&2; rc=1; }
  # Локальный путь в носителе лога — не находка (иначе страж жёг бы свидетельства).
  findings=0
  printf 'cd /c/Users/Admin/vecdht-work/vecdht\n' > "$tmp/d.log"
  check_blob "$tmp/d.log" 1
  [ "$findings" = 0 ] || { echo "САМОТЕСТ: исключение лога не работает" >&2; rc=1; }
  rm -rf "$tmp"
  if [ "$rc" = 0 ]; then echo "SECRETS_SELFTEST=ok"
  else echo "SECRETS_SELFTEST=fail"; fi
  exit "$rc"
}

if [ "$SELFTEST" = 1 ]; then run_selftest; fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$ROOT" ]; then echo "ПРИБОР: вне git-репозитория" >&2; exit 2; fi
cd "$ROOT"

scan_tree
scan_gitconfig
if [ "$NO_HISTORY" = 0 ]; then scan_history; fi

echo "SECRETS_FINDINGS=$findings"
if [ "$findings" = 0 ]; then echo "SECRETS_EXIT=0"; exit 0; else echo "SECRETS_EXIT=1"; exit 1; fi
