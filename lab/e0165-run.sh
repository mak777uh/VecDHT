#!/usr/bin/env bash
# e0165-run.sh — носитель D3/H-0165: кусок снапшота принимается только по полномочию принятой эпохи.
# PIN — коммит, внёсший карточку H-0165 (пре-регистрация): по нему берётся старый node.rs.
# PRE_FIX — `git checkout <пин> -- node.rs` с trap-возвратом на HEAD. Как и в E-0163/E-0164:
# правка обязана быть закоммичена ДО прогона, иначе trap вернёт дерево на HEAD и сотрёт её.
set -u
cd "$(dirname "$0")/.."
PIN=$(git log --format=%H --reverse -- lab/hypotheses/H-0165-snapshot-offer-authority.md | head -1)
NODE=crates/vecdht-node/src/node.rs
TEST=crates/vecdht-node/tests/d3_snapshot_authority.rs
TMP=$(mktemp -d)
trap 'git checkout -q HEAD -- "$NODE"; rm -rf "$TMP"' EXIT
: > "$TMP/facts"
emit() { printf '%s\t%s\n' "$1" "$2" | tee -a "$TMP/facts"; }
bool_rc() { if [ "$1" -eq 0 ]; then echo 0; else echo 1; fi; }
ok_bool() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }
# Значения golden-векторов не должны меняться; комментарий — не значение, поэтому считаются
# только изменённые не-комментарные строки файла векторов.
golden_code_diff() {
  git diff -U0 "$PIN" -- crates/vecdht-wire/tests/golden_vectors.rs \
    | grep -E '^[+-]' | grep -vE '^\+\+\+|^---' | grep -vE '^[+-][[:space:]]*//' | wc -l
}

emit PIN_FOUND "$(git cat-file -e "$PIN^{commit}" 2>/dev/null && echo 1 || echo 0)"
emit PRE_FIX_AUTHORITY_CHECK "$(git show "$PIN:$NODE" | grep -c 'snapshot_authority_ok')"
emit PRE_FIX_EPOCH_CHECK "$(git show "$PIN:$NODE" | grep -c 'offer.epoch == epoch')"
git checkout -q "$PIN" -- "$NODE"
cargo test -q -p vecdht-node --test d3_snapshot_authority > "$TMP/pre_auth.log" 2>&1; r=$?
emit PRE_FIX_AUTH_TEST_RC "$(bool_rc $r)"
git checkout -q HEAD -- "$NODE"
emit POST_FIX_AUTHORITY_CHECK "$(grep -c 'snapshot_authority_ok' "$NODE")"
emit POST_FIX_EPOCH_CHECK "$(grep -c 'offer.epoch == epoch' "$NODE")"
cargo test -q -p vecdht-node --test d3_snapshot_authority > "$TMP/post_auth.log" 2>&1; r=$?
emit POST_FIX_AUTH_TEST_RC "$(bool_rc $r)"
emit AUTH_CASES "$(grep -c '#\[test\]' "$TEST")"
emit AUTH_PASS "$(grep -oE 'test result: ok\. [0-9]+ passed' "$TMP/post_auth.log" | grep -oE '[0-9]+' | head -1)"
cargo test -q -p vecdht-node --test s94_tail > "$TMP/s94.log" 2>&1; r=$?
emit S94_TAIL_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test gates_p4 > "$TMP/p4.log" 2>&1; r=$?
emit GATES_P4_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test w2r3_stale_read > "$TMP/w2r3.log" 2>&1; r=$?
emit W2R3_RC "$(bool_rc $r)"
cargo test -q -p vecdht-wire --test golden_vectors > "$TMP/golden.log" 2>&1; r=$?
emit GOLDEN_VECTORS_RC "$(bool_rc $r)"
emit GOLDEN_CODE_DIFF "$(golden_code_diff)"
emit WAL_FORMAT_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-index/src/wal.rs')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" | grep -q '^crates/vecdht-wire/' && echo 1 || echo 0)"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^docs/VecDHT-SPEC-v8.md')"
emit PRODUCT_TOUCHED "$(git diff --name-only "$PIN" | grep -q '^crates/vecdht-node/src/' && echo 1 || echo 0)"
# Таблица и карточка обязаны войти одним коммитом: иначе порог цикла поднят после пре-регистрации.
# `TEST_TOUCHED` здесь не у дел — тест добавлен тем же пин-коммитом и правки от него не требует.
emit PIN_HASEXPECT "$([ "$(git log --format=%H --reverse -- lab/expectations/e0165.tsv | head -1)" = "$PIN" ] && echo 1 || echo 0)"
emit SPEC_RULE "$(grep -cF 'принимается только от члена принятой эпохи и только с её эпохой' docs/VecDHT-SPEC-v8.md)"
python lab/check-guard-selftests.py > /dev/null 2>&1; emit GSE_EXIT "$(bool_rc $?)"
python lab/check-contour-parity.py > /dev/null 2>&1; emit PARITY_EXIT "$(bool_rc $?)"
python lab/check-contours.py > /dev/null 2>&1; emit CONTOURS_EXIT "$(bool_rc $?)"
python lab/check-expect-freeze.py > /dev/null 2>&1; emit EXPECT_FREEZE_EXIT "$(bool_rc $?)"
bash lab/check-text-clean.sh --all > /dev/null 2>&1; emit TEXT_EXIT "$(bool_rc $?)"
python lab/check-claims.py > /dev/null 2>&1; emit CLAIMS_EXIT "$(bool_rc $?)"
bash lab/check-spec-mirror.sh > /dev/null 2>&1; emit SPEC_MIRROR_EXIT "$(bool_rc $?)"
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
done < lab/expectations/e0165.tsv
echo "WORST_RC=$WORST"

SNAP="$(git rev-parse HEAD)|$(git status --porcelain | sha256sum | cut -c1-16)"
STABLE_FILE=/tmp/e0165-stable.txt
if [ -f "$STABLE_FILE" ] && [ "$(cat "$STABLE_FILE")" = "$SNAP" ]; then
  echo "STABLE=1"
else
  printf '%s' "$SNAP" > "$STABLE_FILE"
  echo "STABLE=0"
fi
