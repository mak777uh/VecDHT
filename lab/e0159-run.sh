#!/usr/bin/env bash
# Носитель круга H-0159: клиент стороннего реализатора v9 обязан зеркалить §V9.3 так же, как
# `normalize_statement` в Rust: пустой после нормализации результат — отказ, а хвостовым пробелом
# считается только ASCII ` ` и `\t`. Порядок:
#  (0) PRE_FIX — клиент с пина пре-регистрации, взятый `git show` в $TMP: на пустом входе и на
#      NBSP-только он отдаёт пустые байты (два расхождения названы числом);
#  (1) POST_FIX — рабочее дерево: те же пробы дают `reject` и `bytes:c2a00a`, как Rust;
#  (2) приёмосдаточное исполнение клиента на документах v9 (V913_ALL_OK, три примера);
#  (3) соседние стражи, py_compile, границы продукта, диск, повторяемость.
#
# Употребление: bash lab/e0159-run.sh [каталог-вывода]
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

SCR=$(mktemp -d)/
OUT=${1:-$SCR}
mkdir -p "$OUT"
OUT="${OUT%/}/"
FACTS="${OUT}facts.txt"
: > "$FACTS"

emit() { printf '%s=%s\n' "$1" "$2" | tee -a "$FACTS"; }
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%;_+-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }
win() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
cleanup() { rm -rf "$SCR"; }
trap cleanup EXIT
CLIENT="lab/v9-independent-client.py"

PIN=$(git log --format=%H --grep="H-0159: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)

# --- проба нормализатора: импорт клиента, четыре входа, сверка с Rust ---------------------------------
cat > "${SCR}probe.py" <<'PY'
import importlib.util
import sys

path, prefix = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("v9client_probe", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def value(x):
    if x is None:
        return "reject"
    return "bytes:" + x.hex()

cases = {
    "EMPTY": b"",
    "SPACES": b" \r\n\t\n",
    "NBSP": "\u00a0".encode("utf-8"),
    "PLAIN": b"a \r\n",
}
out = {name: module.normalize(raw) for name, raw in cases.items()}
print(prefix + "_IMPORT=1")
for name, got in out.items():
    print(prefix + "_" + name + "=" + value(got))
print(prefix + "_EMPTY_EQ_RUST=" + str(int(out["EMPTY"] is None)))
print(prefix + "_NBSP_EQ_RUST=" + str(int(out["NBSP"] == "\u00a0\n".encode("utf-8"))))
n = module.normalize(b"x\n\n")
print(prefix + "_IDEMPOTENT=" + str(int(n is not None and module.normalize(n) == n)))
PY

probe() {
  path=$1; prefix=$2; log=$3
  python "${SCR}probe.py" "$(win "$path")" "$prefix" > "$log" 2>&1 || true
  for k in IMPORT EMPTY SPACES NBSP PLAIN EMPTY_EQ_RUST NBSP_EQ_RUST IDEMPOTENT; do
    emit "${prefix}_${k}" "$(grab "$log" "${prefix}_${k}")"
  done
}

# --- ШАГ 0: PRE_FIX — клиент пина --------------------------------------------------------------
git show "$PIN:$CLIENT" > "${SCR}old-client.py" 2>"${SCR}show.log"
probe "${SCR}old-client.py" PRE_FIX "${SCR}pre.log"

# --- ШАГ 1: POST_FIX — клиент рабочего дерева ---------------------------------------------------
probe "$CLIENT" POST_FIX "${SCR}post.log"

# --- ШАГ 2: приёмосдаточное исполнение клиента --------------------------------------------------
r=0
python "$CLIENT" docs/PAID_ORDER-VECTORS.md docs/VecDHT-SPEC-v9.md > "${SCR}client.log" 2>&1 || r=$?
emit CLIENT_RC "$r"
emit CLIENT_ALL_OK "$(grab "${SCR}client.log" V913_ALL_OK)"
emit CLIENT_EXAMPLES "$(grab "${SCR}client.log" V913_EXAMPLES)"
for w in W1 W2 W3; do
  emit "CLIENT_${w}_NORM_EQ" "$(grab "${SCR}client.log" "V913_${w}_NORM_EQ")"
  emit "CLIENT_${w}_HASH_EQ" "$(grab "${SCR}client.log" "V913_${w}_HASH_EQ")"
done

r=0
python -m py_compile "$CLIENT" > "${SCR}pyc.log" 2>&1 || r=$?
emit PY_COMPILE "$r"

# --- ШАГ 3: соседние стражи --------------------------------------------------------------------
r=0; python lab/check-guard-selftests.py > "${SCR}gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
r=0; python lab/check-contour-parity.py > "${SCR}parity.log" 2>&1 || r=$?
emit PARITY_EXIT "$r"
r=0; python lab/check-contours.py > "${SCR}contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; python lab/check-expect-freeze.py > "${SCR}expect.log" 2>&1 || r=$?
emit EXPECT_FREEZE_EXIT "$r"
r=0; bash lab/check-text-clean.sh --all > "${SCR}text.log" 2>&1 || r=$?
emit TEXT_EXIT "$r"
r=0; python lab/check-ci-numbers.py > "${SCR}cin.log" 2>&1 || r=$?
emit CI_NUMBERS_EXIT "$r"

# --- ШАГ 4: границы продукта и диск ------------------------------------------------------------
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_READABLE "$([ "$D" != none ] && echo 1 || echo 0)"

# --- ШАГ 5: вердикт по замороженной таблице -----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2-; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0159.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0159-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
