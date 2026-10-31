#!/usr/bin/env bash
# e0164-run.sh — носитель T1/H-0164: подпись `Publish` обязательна, дверь не пропускает кадр без неё.
# PIN — коммит, внёсший карточку H-0164 (пре-регистрация): по нему берётся старый frame.rs.
# PRE_FIX — `git checkout <пин> -- frame.rs` с trap-возвратом на HEAD. Как и в E-0163: правка
# обязана быть закоммичена ДО прогона, иначе trap вернёт дерево на HEAD и сотрёт её.
set -u
cd "$(dirname "$0")/.."
PIN=$(git log --format=%H --reverse -- lab/hypotheses/H-0164-publish-signature.md | head -1)
FRAME=crates/vecdht-wire/src/frame.rs
TEST=crates/vecdht-node/tests/t1_publish_signature.rs
TMP=$(mktemp -d)
trap 'git checkout -q HEAD -- "$FRAME"; rm -rf "$TMP"' EXIT
: > "$TMP/facts"
emit() { printf '%s\t%s\n' "$1" "$2" | tee -a "$TMP/facts"; }
bool_rc() { if [ "$1" -eq 0 ]; then echo 0; else echo 1; fi; }
ok_bool() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }
sig_block() { awk '/pub fn signature_required/{f=1} f{print} f&&/^    }$/{exit}'; }
has() { grep -qF "$2" "$1" && echo 1 || echo 0; }
# Значения golden-векторов не должны меняться; комментарий — не значение, поэтому считаются
# только изменённые не-комментарные строки файла векторов.
golden_code_diff() {
  git diff -U0 "$PIN" -- crates/vecdht-wire/tests/golden_vectors.rs \
    | grep -E '^[+-]' | grep -vE '^\+\+\+|^---' | grep -vE '^[+-][[:space:]]*//' | wc -l
}

emit PIN_FOUND "$(git cat-file -e "$PIN^{commit}" 2>/dev/null && echo 1 || echo 0)"
emit PRE_FIX_SIG_REQUIRED "$(git show "$PIN:$FRAME" | sig_block | grep -c '| Kind::Publish')"
git checkout -q "$PIN" -- "$FRAME"
cargo test -q -p vecdht-wire --lib signature_required_matrix_matches_spec -- --exact > "$TMP/pre_matrix.log" 2>&1; r=$?
emit PRE_FIX_MATRIX_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test t1_publish_signature > "$TMP/pre_t1.log" 2>&1; r=$?
emit PRE_FIX_T1_RC "$(bool_rc $r)"
git checkout -q HEAD -- "$FRAME"
emit POST_FIX_SIG_REQUIRED "$(sig_block < "$FRAME" | grep -c '| Kind::Publish')"
cargo test -q -p vecdht-wire --lib signature_required_matrix_matches_spec -- --exact > "$TMP/post_matrix.log" 2>&1; r=$?
emit POST_FIX_MATRIX_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test t1_publish_signature > "$TMP/post_t1.log" 2>&1; r=$?
emit POST_FIX_T1_RC "$(bool_rc $r)"
emit T1_CASES "$(grep -c '#\[test\]' "$TEST")"
emit T1_PASS "$(grep -oE 'test result: ok\. [0-9]+ passed' "$TMP/post_t1.log" | grep -oE '[0-9]+' | head -1)"
cargo test -q -p vecdht-node --test s14_cluster_bloat_price > "$TMP/bloat.log" 2>&1; r=$?
emit BLOAT_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test s14_cell_cap_enforced --test s77_cell_cap_scan --test s77b_cell_cap_scan_observe --test c103_cluster_reassign > "$TMP/caps.log" 2>&1; r=$?
emit CAPS_RC "$(bool_rc $r)"
cargo test -q -p vecdht-cli --test s13_disk_privacy > "$TMP/privacy.log" 2>&1; r=$?
emit PRIVACY_RC "$(bool_rc $r)"
cargo test -q -p vecdht-net --test s19_find_e2e_price > "$TMP/e2e.log" 2>&1; r=$?
emit E2E_RC "$(bool_rc $r)"
cargo test -q -p vecdht-net --test gossip_door_parity > "$TMP/gossip.log" 2>&1; r=$?
emit GOSSIP_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test adversarial > "$TMP/adversarial.log" 2>&1; r=$?
emit ADVERSARIAL_RC "$(bool_rc $r)"
cargo test -q -p vecdht-node --test intent_class_filter > "$TMP/intent.log" 2>&1; r=$?
emit INTENT_RC "$(bool_rc $r)"
cargo test -q -p vecdht-wire --test golden_vectors > "$TMP/golden.log" 2>&1; r=$?
emit GOLDEN_VECTORS_RC "$(bool_rc $r)"
emit GOLDEN_CODE_DIFF "$(golden_code_diff)"
emit WAL_FORMAT_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^crates/vecdht-index/src/wal.rs')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" | grep -q '^crates/vecdht-wire/' && echo 1 || echo 0)"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" | grep -c '^docs/VecDHT-SPEC-v8.md')"
emit PRODUCT_TOUCHED "$(git diff --name-only "$PIN" | grep -qE '^crates/vecdht-(node|wire)/src/' && echo 1 || echo 0)"
emit TEST_TOUCHED "$(git diff --name-only "$PIN" | grep -q '^crates/vecdht-node/tests/t1_publish_signature.rs' && echo 1 || echo 0)"
emit SPEC_OPTIONAL "$(grep -cE '^0x10.*опционально' docs/VecDHT-SPEC-v8.md)"
emit SPEC_REQUIRED "$(grep -cF 'обязательна (ключом заявленного owner)' docs/VecDHT-SPEC-v8.md)"
emit SPEC_BUCKET "$(grep -cF 'токен списывается у обоих, потому что пересылка' docs/VecDHT-SPEC-v8.md)"
emit LEAN_NOTE "$(has lab/lean/VecDHT/Admission.lean 'дверь отбрасывает неподписанный кадр до admission')"
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
done < lab/expectations/e0164.tsv
echo "WORST_RC=$WORST"

SNAP="$(git rev-parse HEAD)|$(git status --porcelain | sha256sum | cut -c1-16)"
STABLE_FILE=/tmp/e0164-stable.txt
if [ -f "$STABLE_FILE" ] && [ "$(cat "$STABLE_FILE")" = "$SNAP" ]; then
  echo "STABLE=1"
else
  printf '%s' "$SNAP" > "$STABLE_FILE"
  echo "STABLE=0"
fi
