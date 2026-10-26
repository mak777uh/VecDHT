#!/usr/bin/env bash
# Две машины, три узла: пользовательский сценарий условия 3 `ADR-0044`.
#
#   машина 1: церемония (артефакт, три кредашиала, genesis шарда 0), узел 0 и узел 1;
#   машина 2: копия каталога церемонии, узел 2, затем `agent publish` и `agent find`.
#
# Каталог церемонии переносим целиком: артефакт, genesis, кредашиалы и seed-ы узлов. Ключи здесь
# dev-овские (выведены из фиксированного seed), поэтому переносить их между машинами безопасно
# только для демонстрации: боевой узел обязан получить свой ключ и свой кредашиал отдельно.
#
# Скрипт намеренно не собирает бинарь: сборка — отдельное действие с видимой ценой, а сценарий
# не должен менять дерево, пока владелец его прогоняет. Путь к бинарю: `VECDHT_CLI` или
# `target/release/vecdht-cli(.exe)`, затем `target/debug/vecdht-cli(.exe)`.
#
# Употребление:
#   bash lab/two-hosts.sh ceremony DIR
#   bash lab/two-hosts.sh serve DIR INDEX LISTEN [BOOTSTRAP ...]
#   bash lab/two-hosts.sh publish DIR BOOTSTRAP TEXT
#   bash lab/two-hosts.sh find DIR BOOTSTRAP TEXT
#   bash lab/two-hosts.sh selfcheck [DIR]
#
# `selfcheck` поднимает все три узла на 127.0.0.1 и прогоняет сценарий целиком: публикация через
# узел 0, поиск через узел 1, сверка owner/slot. Это проверка скрипта, а не замена сценария двух
# машин: `selfcheck` не доказывает, что разные машины видят друг друга.
#
# Метки `HOSTS_*` — ASCII и в одну строку: их читает владелец и сверяет с логом, а не парсер
# с богатой грамматикой. `HOSTS_OK=1` печатается последней строкой успеха.
set -uo pipefail
cd "$(dirname "$0")/.."

# Git Bash подменяет аргументы, похожие на POSIX-пути, в Windows-пути: значение
# `--listen /ip4/127.0.0.1/udp/0/quic-v1` доезжало до узла как `C:/Program Files/Git/ip4/...`.
# Исключение по префиксу адреса чинит только адреса; пути к артефакту и каталогу узла обязаны
# остаться конвертируемыми, иначе Rust-бинарь не поймёт `/tmp/...`.
export MSYS2_ARG_CONV_EXCL="/ip4;/ip6"

SHARD=0
# Текст демонстрации выбран не по смыслу, а по адресу: сеть держит один шард 0, а центроид
# dev-артефакта — 1024 кластера по 16 на шард. При фиксированном seed и суррогатном векторе
# этот текст попадает в кластер 9 (`encode` подтверждает это при церемонии), то есть в шард 0.
DEFAULT_TEXT="vec dht two host check 52"
# dev-ключи: авторитет артефакта, три узла и два оператора. Значения — повтор одного байта,
# как в тесте `node_run.rs`; genesis из этих seed-ов называет primary узел 0.
DEV_BYTE=07
MEMBER_BYTES=(1f 20 21)

die() { printf 'two-hosts: %s\n' "$*" >&2; exit 2; }

rep32() {
  local s=""
  local i
  for i in $(seq 1 32); do s="$s$1"; done
  printf '%s' "$s"
}

cli() {
  if [ -n "${VECDHT_CLI:-}" ]; then
    [ -x "$VECDHT_CLI" ] || die "VECDHT_CLI=$VECDHT_CLI не исполняется"
    printf '%s' "$VECDHT_CLI"
    return 0
  fi
  local c
  for c in target/release/vecdht-cli.exe target/release/vecdht-cli \
           target/debug/vecdht-cli.exe target/debug/vecdht-cli; do
    if [ -x "$c" ]; then printf '%s' "$c"; return 0; fi
  done
  die "нет бинаря vecdht-cli; соберите: cargo build --release -p vecdht-cli"
}

seed_of() {
  local file=$1 name=$2
  local value
  value=$(sed -n "s/^$name //p" "$file" | head -1)
  [ -n "$value" ] || die "в $file нет строки $name"
  printf '%s' "$value"
}

# --- церемония ---------------------------------------------------------------

ceremony() {
  local dir=${1:-}
  [ -n "$dir" ] || die "ceremony: нужен каталог"
  local cli
  cli=$(cli)
  local dev
  dev=$(rep32 "$DEV_BYTE")
  mkdir -p "$dir" || die "не создать $dir"
  local keys="$dir/keys.txt"
  : > "$keys"
  printf 'dev %s\n' "$dev" >> "$keys"

  "$cli" artifact init --out "$dir/artifact" --seed "$dev" --dev-keys 1 \
    > "$dir/artifact-init.txt" 2>&1 \
    || die "artifact init отказал: см. $dir/artifact-init.txt"

  : > "$dir/members.txt"
  local i
  for i in 0 1 2; do
    local seed
    seed=$(rep32 "${MEMBER_BYTES[$i]}")
    printf 'member%d %s\n' "$i" "$seed" >> "$keys"
    local names owner peer nonce
    names=$("$cli" key show --seed "$seed") || die "key show отказал для узла $i"
    owner=$(printf '%s\n' "$names" | sed -n 's/^owner //p')
    peer=$(printf '%s\n' "$names" | sed -n 's/^peer_id //p')
    [ ${#owner} -eq 64 ] || die "owner узла $i не 64 символа hex"
    [ -n "$peer" ] || die "peer_id узла $i пуст"
    nonce=$(printf '%032x' $((i + 1)))
    "$cli" cert issue --artifact "$dir/artifact" --out "$dir/cert-$i.bin" \
      --owner "$owner" --peer-id "$peer" --shard "$SHARD" --capacity 100000 \
      --valid-from 0 --valid-until 4102444800 --nonce "$nonce" \
      --dev-keys 1 --seed "$dev" > "$dir/cert-$i.txt" 2>&1 \
      || die "cert issue отказал для узла $i: см. $dir/cert-$i.txt"
    printf '%s %s 100000\n' "$owner" "$peer" >> "$dir/members.txt"
  done
  printf 'publisher %s\n' "$(rep32 29)" >> "$keys"
  printf 'seeker %s\n' "$(rep32 2a)" >> "$keys"

  # Адрес текста проверяется здесь, а не при публикации: отказ «нет держателя шарда 30» через
  # минуту после старта читается как поломка сети, хотя это неверно выбранный текст.
  local text_cluster text_shard enc
  enc=$("$cli" encode --artifact "$dir/artifact" --text "$DEFAULT_TEXT" --allow-surrogate 2>&1)
  text_cluster=$(printf '%s\n' "$enc" | awk '$1=="cluster_id" {print $2; exit}')
  [ -n "$text_cluster" ] || die "encode не назвал кластер текста демонстрации"
  text_shard=$(printf '%s\n' "$enc" | awk '$1=="cluster_id" {gsub(/\)/, "", $4); print $4; exit}')
  [ "$text_shard" = "$SHARD" ] \
    || die "текст демонстрации попадает в шард $text_shard, а сеть держит шард $SHARD"
  printf '%s\n' "$DEFAULT_TEXT" > "$dir/text.txt"

  "$cli" genesis build --artifact "$dir/artifact" --out "$dir/genesis.bin" \
    --members "$dir/members.txt" --shard "$SHARD" --generated-at 0 \
    --dev-keys 1 --seed "$dev" > "$dir/genesis.txt" 2>&1 \
    || die "genesis build отказал: см. $dir/genesis.txt"

  local primary owner_i
  primary=$(sed -n 's/^  primary  *//p' "$dir/genesis.txt" | head -1)
  [ -n "$primary" ] || die "genesis не напечатал primary"
  owner_i=0
  for i in 0 1 2; do
    if grep -q "^$primary " "$dir/members.txt"; then
      # Номер строки владельца в members.txt — и есть индекс узла: файл писался по порядку.
      owner_i=$(( $(grep -n "^$primary " "$dir/members.txt" | head -1 | cut -d: -f1) - 1 ))
    fi
  done

  printf 'HOSTS_CEREMONY=1 DIR=%s SHARD=%s MEMBERS=3 PRIMARY_INDEX=%s PRIMARY_OWNER=%s\n' \
    "$dir" "$SHARD" "$owner_i" "$primary"
  printf 'HOSTS_TEXT_CLUSTER=%s HOSTS_TEXT_SHARD=%s HOSTS_TEXT=%s\n' \
    "$text_cluster" "$text_shard" "$DEFAULT_TEXT"
  printf 'HOSTS_HINT=перенесите каталог целиком: scp -r %s <машина2>:/tmp/\n' "$dir"
}

# --- узел --------------------------------------------------------------------

serve() {
  local dir=$1 index=$2 listen=$3
  shift 3
  local cli seed
  cli=$(cli)
  seed=$(seed_of "$dir/keys.txt" "member$index")
  local args=(
    node run
    --artifact "$dir/artifact"
    --dir "$dir/node$index"
    --shard "$SHARD"
    --seed "$seed"
    --cert "$dir/cert-$index.bin"
    --genesis "$dir/genesis.bin"
    --listen "$listen"
    --status-sec "${STATUS_SEC:-10}"
    --run-seconds "${RUN_SECONDS:-0}"
  )
  local b
  for b in "$@"; do args+=(--bootstrap "$b"); done
  exec "$cli" "${args[@]}"
}

# --- агент -------------------------------------------------------------------

publish() {
  local dir=$1 boot=$2 text=$3
  local cli
  cli=$(cli)
  mkdir -p "$dir/logs"
  local log="$dir/logs/publish.log"
  "$cli" agent publish --artifact "$dir/artifact" --text "$text" \
    --seed "$(seed_of "$dir/keys.txt" publisher)" --bootstrap "$boot" \
    --allow-surrogate --timeout "${TIMEOUT:-30}" > "$log" 2>&1
  local code=$?
  cat "$log"
  [ $code -eq 0 ] || { printf 'HOSTS_PUBLISH_OK=0 CODE=%s LOG=%s\n' "$code" "$log"; return $code; }
  local owner slot
  owner=$(awk '$1=="owner" && length($2)==64 {print $2; exit}' "$log")
  slot=$(awk '$1=="epoch" && $5=="slot" {print $6; exit}' "$log")
  [ -n "$owner" ] || { printf 'HOSTS_PUBLISH_OK=0 WHY=no-owner LOG=%s\n' "$log"; return 2; }
  [ -n "$slot" ] || { printf 'HOSTS_PUBLISH_OK=0 WHY=no-slot LOG=%s\n' "$log"; return 2; }
  printf 'HOSTS_PUBLISH_OK=1 OWNER=%s SLOT=%s LOG=%s\n' "$owner" "$slot" "$log"
}

find() {
  local dir=$1 boot=$2 text=$3
  local cli
  cli=$(cli)
  mkdir -p "$dir/logs"
  local log="$dir/logs/find.log"
  "$cli" agent find --artifact "$dir/artifact" --text "$text" \
    --seed "$(seed_of "$dir/keys.txt" seeker)" --bootstrap "$boot" \
    --allow-surrogate --timeout "${TIMEOUT:-30}" > "$log" 2>&1
  local code=$?
  cat "$log"
  [ $code -eq 0 ] || { printf 'HOSTS_FIND_OK=0 CODE=%s LOG=%s\n' "$code" "$log"; return $code; }
  # Строка совпадения: `N. owner HEX шард S кластер C слот K d2 D similarity X`.
  # Номера полей не зависят от кириллицы в подписях, поэтому разбор идёт по позициям и словам.
  local owner slot d2 matches
  matches=$(awk '$2=="owner" {n++} END {print n+0}' "$log")
  [ "$matches" -gt 0 ] || { printf 'HOSTS_FIND_OK=0 WHY=no-match LOG=%s\n' "$log"; return 2; }
  owner=$(awk '$2=="owner" {print $3; exit}' "$log")
  slot=$(awk '$2=="owner" {for (i=1;i<=NF;i++) if ($i=="d2") {print $(i-1); exit}}' "$log")
  d2=$(awk '$2=="owner" {for (i=1;i<=NF;i++) if ($i=="d2") {print $(i+1); exit}}' "$log")
  [ -n "$owner" ] || { printf 'HOSTS_FIND_OK=0 WHY=no-owner LOG=%s\n' "$log"; return 2; }
  [ -n "$slot" ] || { printf 'HOSTS_FIND_OK=0 WHY=no-slot LOG=%s\n' "$log"; return 2; }
  printf 'HOSTS_FIND_OK=1 OWNER=%s SLOT=%s D2=%s MATCHES=%s LOG=%s\n' \
    "$owner" "$slot" "$d2" "$matches" "$log"
}

# --- ожидание узла и самопроверка -------------------------------------------

# Ждём `NODE_READY` в логе и печатаем первый адрес: до этой строки узел не объявил себя живым.
# Если процесс уже умер, ждать 90 секунд незачем: отказ узла — это причина, а не задержка.
wait_ready() {
  local log=$1 pid=${2:-} i dead=0
  for i in $(seq 1 90); do
    local addr
    addr=$(sed -n 's/.*NODE_READY .*listen=\([^ ]*\).*/\1/p' "$log" 2>/dev/null | head -1)
    if [ -n "$addr" ]; then printf '%s' "${addr%%,*}"; return 0; fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      dead=$((dead + 1))
      [ "$dead" -ge 2 ] && return 1
    fi
    sleep 1
  done
  return 1
}

selfcheck() {
  local dir=${1:-}
  if [ -z "$dir" ]; then
    dir=$(mktemp -d "${TMPDIR:-/tmp}/vecdht-two-hosts.XXXXXX") || die "mktemp отказал"
  fi
  local started
  started=$(date +%s)
  ceremony "$dir" || { printf 'HOSTS_OK=0\n'; return 2; }
  mkdir -p "$dir/logs"

  local pids=()
  cleanup() { local p; for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
  trap cleanup EXIT

  local listen=/ip4/127.0.0.1/udp/0/quic-v1
  STATUS_SEC=5 RUN_SECONDS=180 serve "$dir" 0 "$listen" > "$dir/logs/node0.log" 2>&1 &
  pids+=($!)
  local a0
  a0=$(wait_ready "$dir/logs/node0.log" "${pids[0]}") \
    || { tail -20 "$dir/logs/node0.log" >&2; printf 'HOSTS_OK=0 WHY=node0-not-ready\n'; return 2; }
  printf 'HOSTS_NODE0=%s\n' "$a0"

  STATUS_SEC=5 RUN_SECONDS=180 serve "$dir" 1 "$listen" "$a0" > "$dir/logs/node1.log" 2>&1 &
  pids+=($!)
  STATUS_SEC=5 RUN_SECONDS=180 serve "$dir" 2 "$listen" "$a0" > "$dir/logs/node2.log" 2>&1 &
  pids+=($!)
  local a1 a2
  a1=$(wait_ready "$dir/logs/node1.log" "${pids[1]}") \
    || { tail -20 "$dir/logs/node1.log" >&2; printf 'HOSTS_OK=0 WHY=node1-not-ready\n'; return 2; }
  a2=$(wait_ready "$dir/logs/node2.log" "${pids[2]}") \
    || { tail -20 "$dir/logs/node2.log" >&2; printf 'HOSTS_OK=0 WHY=node2-not-ready\n'; return 2; }
  printf 'HOSTS_NODE1=%s HOSTS_NODE2=%s\n' "$a1" "$a2"

  # Эпоха и lease должны сойтись до публикации: агент идёт к primary через DHT, и проба
  # раньше, чем узлы обменялись состоянием, краснела бы на исправном дереве.
  sleep "${SETTLE_SEC:-3}"

  local text=${TEXT:-$DEFAULT_TEXT}
  local pub find_out
  pub=$(publish "$dir" "$a0" "$text") || { printf '%s\nHOSTS_OK=0 WHY=publish\n' "$pub"; return 2; }
  printf '%s\n' "$pub"
  find_out=$(find "$dir" "$a1" "$text") || { printf '%s\nHOSTS_OK=0 WHY=find\n' "$find_out"; return 2; }
  printf '%s\n' "$find_out"

  local p_owner p_slot f_owner f_slot f_d2
  p_owner=$(printf '%s\n' "$pub" | sed -n 's/.*HOSTS_PUBLISH_OK=1 OWNER=\([0-9a-f]*\) .*/\1/p')
  p_slot=$(printf '%s\n' "$pub" | sed -n 's/.*HOSTS_PUBLISH_OK=1 OWNER=[0-9a-f]* SLOT=\([0-9]*\) .*/\1/p')
  f_owner=$(printf '%s\n' "$find_out" | sed -n 's/.*HOSTS_FIND_OK=1 OWNER=\([0-9a-f]*\) .*/\1/p')
  f_slot=$(printf '%s\n' "$find_out" | sed -n 's/.*HOSTS_FIND_OK=1 OWNER=[0-9a-f]* SLOT=\([0-9]*\) .*/\1/p')
  f_d2=$(printf '%s\n' "$find_out" | sed -n 's/.*HOSTS_FIND_OK=1 OWNER=[0-9a-f]* SLOT=[0-9]* D2=\([0-9]*\) .*/\1/p')

  local match=0
  if [ "$p_owner" = "$f_owner" ] && [ "$p_slot" = "$f_slot" ] && [ "$f_d2" = "0" ]; then
    match=1
  fi
  local secs=$(( $(date +%s) - started ))
  printf 'HOSTS_MATCH=%s HOSTS_DIR=%s HOSTS_SECONDS=%s\n' "$match" "$dir" "$secs"
  [ "$match" -eq 1 ] || { printf 'HOSTS_OK=0 WHY=mismatch\n'; return 2; }
  printf 'HOSTS_OK=1\n'
}

# --- диспетчер ---------------------------------------------------------------

case "${1:-}" in
  ceremony) shift; ceremony "$@" ;;
  serve)    shift; [ $# -ge 3 ] || die "serve: DIR INDEX LISTEN [BOOTSTRAP ...]"; serve "$@" ;;
  publish)  shift; [ $# -eq 3 ] || die "publish: DIR BOOTSTRAP TEXT"; publish "$@" ;;
  find)     shift; [ $# -eq 3 ] || die "find: DIR BOOTSTRAP TEXT"; find "$@" ;;
  selfcheck) shift; selfcheck "${1:-}" ;;
  *)
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
