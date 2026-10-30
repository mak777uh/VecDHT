#!/usr/bin/env bash
# e0161-run.sh — носитель D4: `WalPullRequest` тратит узловой admission §11.3.4.
# PIN — коммит, внёсший карточку H-0161 (пре-регистрация): по нему берётся старый `node.rs`.
# PRE_FIX — `git checkout <пин> -- node.rs` с trap-возвратом на HEAD; тест лежит в рабочем дереве,
# поэтому старый код компилируется и обязан краснеть. POST — живое дерево.
set -u
cd "$(dirname "$0")/.."
PIN=$(git log --format=%H --reverse -- lab/hypotheses/H-0161-pull-admission.md | head -1)
TEST=crates/vecdht-node/tests/s11_pull_admission.rs
NODE=crates/vecdht-node/src/node.rs
TMP=$(mktemp -d)
trap 'git checkout -q HEAD -- "$NODE"; rm -rf "$TMP"' EXIT
: > "$TMP/facts"
emit() { printf '%s\t%s\n' "$1" "$2" | tee -a "$TMP/facts"; }
bool_rc() { if [ "$1" -eq 0 ]; then echo 0; else echo 1; fi; }
ok_bool() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }
in_pull() { awk '/fn handle_pull_request/{f=1} f{print} f&&/^    }$/{exit}'; }

emit PIN_FOUND "$(git cat-file -e "$PIN^{commit}" 2>/dev/null && echo 1 || echo 0)"
emit PRE_FIX_ADMIT_IN_PULL "$(git show "$PIN:$NODE" | in_pull | grep -c 'reserve_admit')"
git checkout -q "$PIN" -- "$NODE"
cargo test -q -p vecdht-node --test s11_pull_admission > "$TMP/pre.log" 2>&1; r=$?
emit PRE_FIX_TEST_RC "$(bool_rc $r)"
git checkout -q HEAD -- "$NODE"
emit POST_FIX_ADMIT_IN_PULL "$(in_pull < "$NODE" | grep -c 'reserve_admit')"
cargo test -q -p vecdht-node --test s11_pull_admission > "$TMP/post.log" 2>&1; r=$?
emit POST_FIX_TEST_RC "$(bool_rc $r)"
emit TEST_CASES "$(grep -c '#\[test\]' "$TEST")"
emit TEST_PASS "$(grep -oE 'test result: ok\. [0-9]+ passed' "$TMP/post.log" | grep -oE '^test result: ok\. [0-9]+' | grep -oE '[0-9]+' | head -1)"
emit BUSY_CODE "$(grep -c 'err_code::BUSY' "$TEST")"
cargo test -q -p vecdht-node --test s11_pull_admission foreign_shard_pull_is_free -- --exact > "$TMP/foreign.log" 2>&1; r=$?
emit FOREIGN_FREE "$(ok_bool $r)"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-wire/')"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^docs/VecDHT-SPEC')"
emit PRODUCT_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-node/src/node.rs')"
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
done < lab/expectations/e0161.tsv
echo "WORST_RC=$WORST"

SNAP="$(git rev-parse HEAD)|$(git status --porcelain | sha256sum | cut -c1-16)"
STABLE_FILE=/tmp/e0161-stable.txt
if [ -f "$STABLE_FILE" ] && [ "$(cat "$STABLE_FILE")" = "$SNAP" ]; then
  echo "STABLE=1"
else
  printf '%s' "$SNAP" > "$STABLE_FILE"
  echo "STABLE=0"
fi
