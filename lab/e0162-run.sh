#!/usr/bin/env bash
# e0162-run.sh — носитель H-0162: зелёная часть 4-го круга (m1/m2/m3/m5, T2, R3/m8).
# PIN — коммит, внёсший карточку H-0162 (пре-регистрация): по нему берётся старый `frame.rs`.
# PRE_FIX — `git checkout <пин> -- frame.rs` с trap-возвратом на HEAD; новый тест лежит в рабочем
# дереве, поэтому старый декодер компилируется и обязан краснеть. POST — живое дерево.
set -u
cd "$(dirname "$0")/.."
PIN=$(git log --format=%H --reverse -- lab/hypotheses/H-0162-external-audit-round4-green.md | head -1)
FRAME=crates/vecdht-wire/src/frame.rs
CODEC=crates/vecdht-wire/src/codec.rs
MSGS=crates/vecdht-wire/src/messages.rs
NEW=crates/vecdht-wire/tests/decode_strictness.rs
SPEC=docs/VecDHT-SPEC-v8.md
TMP=$(mktemp -d)
trap 'git checkout -q HEAD -- "$FRAME"; rm -rf "$TMP"' EXIT
: > "$TMP/facts"
emit() { printf '%s\t%s\n' "$1" "$2" | tee -a "$TMP/facts"; }
bool_rc() { if [ "$1" -eq 0 ]; then echo 0; else echo 1; fi; }
ok_bool() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }
spec_section() { awk -v h="$1" 'index($0,h)==1{f=1;next} f&&/^### /{exit} f' "$SPEC"; }

emit PIN_FOUND "$(git cat-file -e "$PIN^{commit}" 2>/dev/null && echo 1 || echo 0)"

# PRE_FIX: старый декодер обязан принять хвост, то есть новый тест обязан быть красным.
git checkout -q "$PIN" -- "$FRAME"
cargo test -q -p vecdht-wire --test decode_strictness > "$TMP/pre.log" 2>&1; r=$?
emit PRE_FIX_TEST_RC "$(bool_rc $r)"
git checkout -q HEAD -- "$FRAME"

# POST_FIX: живое дерево.
cargo test -q -p vecdht-wire --test decode_strictness > "$TMP/post.log" 2>&1; r=$?
emit POST_FIX_TEST_RC "$(bool_rc $r)"
emit TEST_CASES "$(grep -c '#\[test\]' "$NEW")"
emit TEST_PASS "$(grep -oE 'test result: ok\. [0-9]+ passed' "$TMP/post.log" | grep -oE '[0-9]+' | head -1)"
cargo test -q -p vecdht-node --test frame_byte_mutation > "$TMP/mut.log" 2>&1; r=$?
emit BYTE_MUTATION_RC "$(bool_rc $r)"
cargo test -q -p vecdht-wire > "$TMP/wire.log" 2>&1; r=$?
emit WIRE_TEST_RC "$(bool_rc $r)"
cargo test -q -p vecdht-wire --test golden_vectors > "$TMP/golden.log" 2>&1; r=$?
emit GOLDEN_RC "$(bool_rc $r)"

emit TAIL_IMPL "$(grep -c 'TrailingBytes' "$FRAME")"
emit SIGLEN_MSG "$(grep -c 'must be 64' "$CODEC")"
emit SIGLEN32 "$(grep -c '32, 64' "$CODEC")"
emit DOMAIN_LITERALS "$(grep -c 'DOMAIN: &.*= b"' "$MSGS")"
emit DOMAIN_NAMED "$(grep -c 'DOMAIN: &.*= domain::' "$MSGS")"

emit README_PROVIDER "$(grep -c 'asks one provider per shard' README.md)"
emit README_NODE_DECISION "$(grep -c 'what that node decided' README.md)"
emit RU_PROVIDER "$(grep -c 'одного провайдера на шард' README.ru.md)"
emit RU_NODE_DECISION "$(grep -c 'решение этого узла' README.ru.md)"
emit README_CA "$(grep -c 'Records are content-addressed' README.md)"
emit RU_CA "$(grep -c 'Записи адресованы по содержимому' README.ru.md)"

emit SPEC_RECOMP "$(grep -c 'verifiable re-computation:' "$SPEC")"
emit SPEC_SIGFIELD "$(grep -c 'IntentTextResponse\.sig' "$SPEC")"
emit SPEC_PENALTY "$(grep -c 'штрафуется' "$SPEC")"
emit SPEC_NOT_V1 "$(spec_section '### 14.2' | grep -c 'не реализовано в v1')"
emit SPEC_PROVIDER "$(grep -c 'candidates.first()' "$SPEC")"
emit SPEC_TIMEOUT "$(grep -c 'полного таймаута `find`' "$SPEC")"
emit SPEC_ARTIFACT "$(grep -c '`ArtifactAnnounce` в v1 не обрабатывается' "$SPEC")"

emit WIRE_SRC_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-wire/src/')"
emit TESTS_TOUCHED "$(git diff --name-only "$PIN" | grep -c '/tests/')"
emit README_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^README')"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^docs/VecDHT-SPEC-v8.md$')"
emit CI_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^\.github/workflows/verify.yml$')"
emit GOLDEN_CHANGED "$(git diff --name-only "$PIN" | grep -cE 'golden|VECTORS')"

python lab/check-ci-numbers.py > "$TMP/cin.log" 2>&1; r=$?
emit CIN_EXIT "$(bool_rc $r)"
emit CIN_TOTAL_ALL "$(awk -F= '$1=="CIN_TOTAL_ALL"{print $2}' "$TMP/cin.log")"
emit CIN_CRATE_WIRE "$(awk -F= '$1=="CIN_CRATE_WIRE"{print $2}' "$TMP/cin.log")"
emit CIN_FINDINGS "$(awk -F= '$1=="CIN_FINDINGS"{print $2}' "$TMP/cin.log")"

python lab/check-spec-cites.py > /dev/null 2>&1; emit CITES_EXIT "$(bool_rc $?)"
python lab/check-claim-map.py > /dev/null 2>&1; emit CLAIMMAP_EXIT "$(bool_rc $?)"
bash lab/check-spec-mirror.sh > /dev/null 2>&1; emit MIRROR_EXIT "$(bool_rc $?)"
python lab/check-guard-selftests.py > /dev/null 2>&1; emit GSE_EXIT "$(bool_rc $?)"
python lab/check-contour-parity.py > /dev/null 2>&1; emit PARITY_EXIT "$(bool_rc $?)"
python lab/check-contours.py > /dev/null 2>&1; emit CONTOURS_EXIT "$(bool_rc $?)"
python lab/check-expect-freeze.py > /dev/null 2>&1; emit EXPECT_FREEZE_EXIT "$(bool_rc $?)"
bash lab/check-text-clean.sh --all > /dev/null 2>&1; emit TEXT_EXIT "$(bool_rc $?)"
python lab/check-claims.py > /dev/null 2>&1; emit CLAIMS_EXIT "$(bool_rc $?)"
disk=$(bash lab/disk-report.sh 2>/dev/null | head -1)
case "$disk" in DISK_FREE_MB=*) emit DISK_READABLE 1;; *) emit DISK_READABLE 0;; esac

WORST=0
while IFS=$'\t' read -r k v; do
  [ -z "$k" ] && continue
  got=$(awk -F'\t' -v k="$k" '$1==k{print $2}' "$TMP/facts")
  if [ "$got" = "$v" ]; then
    echo "СВЕРКА $k=$got"
  else
    echo "РАСХОЖДЕНИЕ $k: ждали $v, получили ${got:-нет}"
    WORST=1
  fi
done < lab/expectations/e0162.tsv
echo "WORST_RC=$WORST"

SNAP="$(git rev-parse HEAD)|$(git status --porcelain | sha256sum | cut -c1-16)"
STABLE_FILE=/tmp/e0162-stable.txt
if [ -f "$STABLE_FILE" ] && [ "$(cat "$STABLE_FILE")" = "$SNAP" ]; then
  echo "STABLE=1"
else
  printf '%s' "$SNAP" > "$STABLE_FILE"
  echo "STABLE=0"
fi
