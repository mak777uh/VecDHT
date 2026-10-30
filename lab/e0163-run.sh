#!/usr/bin/env bash
# e0163-run.sh — носитель D1+D2: хвост WAL принимается только от подписанного primary эпохи.
# PIN — коммит, внёсший карточку H-0163 (пре-регистрация): по нему берутся старые node.rs и frame.rs.
# PRE_FIX — `git checkout <пин> -- node.rs frame.rs` с trap-возвратом на HEAD; новые тесты лежат в
# рабочем дереве, поэтому старый код компилируется и обязан краснеть. POST — живое дерево.
set -u
cd "$(dirname "$0")/.."
PIN=$(git log --format=%H --reverse -- lab/hypotheses/H-0163-wal-pull-authority.md | head -1)
TEST=crates/vecdht-node/tests/s94_tail.rs
NODE=crates/vecdht-node/src/node.rs
FRAME=crates/vecdht-wire/src/frame.rs
TMP=$(mktemp -d)
trap 'git checkout -q HEAD -- "$NODE" "$FRAME"; rm -rf "$TMP"' EXIT
: > "$TMP/facts"
emit() { printf '%s\t%s\n' "$1" "$2" | tee -a "$TMP/facts"; }
bool_rc() { if [ "$1" -eq 0 ]; then echo 0; else echo 1; fi; }
ok_bool() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }
sig_block() { awk '/pub fn signature_required/{f=1} f{print} f&&/^    }$/{exit}'; }
has() { grep -qF "$2" "$1" && echo 1 || echo 0; }

emit PIN_FOUND "$(git cat-file -e "$PIN^{commit}" 2>/dev/null && echo 1 || echo 0)"
emit PRE_FIX_SIG_REQUIRED "$(git show "$PIN:$FRAME" | sig_block | grep -c 'WalPullResponse')"
git checkout -q "$PIN" -- "$NODE" "$FRAME"
cargo test -q -p vecdht-node --test s94_tail > "$TMP/pre.log" 2>&1; r=$?
emit PRE_FIX_TEST_RC "$(bool_rc $r)"
git checkout -q HEAD -- "$NODE" "$FRAME"
emit POST_FIX_SIG_REQUIRED "$(sig_block < "$FRAME" | grep -c 'WalPullResponse')"
cargo test -q -p vecdht-node --test s94_tail > "$TMP/post.log" 2>&1; r=$?
emit POST_FIX_TEST_RC "$(bool_rc $r)"
emit TEST_CASES "$(grep -c '#\[test\]' "$TEST")"
emit TEST_PASS "$(grep -oE 'test result: ok\. [0-9]+ passed' "$TMP/post.log" | grep -oE '^test result: ok\. [0-9]+' | grep -oE '[0-9]+' | head -1)"
cargo test -q -p vecdht-node --test s94_tail wal_pull_only_primary_is_accepted -- --exact > "$TMP/primary.log" 2>&1; r=$?
emit ONLY_PRIMARY_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test s94_tail cold_node_without_membership_trusts_only_roster -- --exact > "$TMP/cold.log" 2>&1; r=$?
emit COLD_ROSTER_RC "$(bool_rc $r)"
emit SPEC_STALE "$(has docs/VecDHT-SPEC-v8.md 'Каждый WAL-фрейм несёт `epoch` и подпись primary')"
emit SPEC_RULE "$(has docs/VecDHT-SPEC-v8.md 'только от primary принятой эпохи')"
emit GOLDEN_DIFF "$(git diff --name-only "$PIN" | grep -c 'golden')"
emit WAL_FORMAT_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-index/src/wal.rs')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-wire/')"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^docs/VecDHT-SPEC-v8.md')"
emit PRODUCT_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-node/src/node.rs')"
emit TEST_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-node/tests/s94_tail.rs')"
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
done < lab/expectations/e0163.tsv
echo "WORST_RC=$WORST"

SNAP="$(git rev-parse HEAD)|$(git status --porcelain | sha256sum | cut -c1-16)"
STABLE_FILE=/tmp/e0163-stable.txt
if [ -f "$STABLE_FILE" ] && [ "$(cat "$STABLE_FILE")" = "$SNAP" ]; then
  echo "STABLE=1"
else
  printf '%s' "$SNAP" > "$STABLE_FILE"
  echo "STABLE=0"
fi
