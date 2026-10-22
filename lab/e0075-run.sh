#!/usr/bin/env bash
# E-0075: §15/§9.2 — genesis и пороговая подпись: индекс, двери и две руки порога.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0075-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0075 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test s15_authority_seam --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test s15_authority_seam -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- genesis: индекс подписи не используется, только диапазон/уникальность + count_valid:"
  sed -n '/fn check_authorities/,/^    }/p' crates/vecdht-node/src/membership.rs
  echo "-- переход: ключ берётся ровно по заявленному индексу:"
  sed -n '/fn check_members/,/^    }/p' crates/vecdht-node/src/membership.rs
  echo "-- check_indices: диапазон и уникальность, без привязки к ключу:"
  sed -n '/fn check_indices/,/^    }/p' crates/vecdht-node/src/membership.rs
  echo "-- count_valid: подпись против любого ключа, дедуп по ключу:"
  sed -n '/pub fn count_valid/,/^    }/p' crates/vecdht-crypto/src/cert.rs
  echo "-- порог genesis из Params, порог NodeCert из AuthoritySet:"
  grep -n "authority_threshold" crates/vecdht-node/src/config.rs crates/vecdht-node/src/membership.rs
  grep -n "authorities.check\|self.threshold" crates/vecdht-crypto/src/cert.rs | head -6
  echo "-- open принимает обе структуры и не сверяет их:"
  grep -n "pub fn open(\|authorities: AuthoritySet\|let chain = Chain" crates/vecdht-node/src/node.rs | head -8
  echo "-- from_manifest копирует порог из манифеста:"
  grep -n "authority_threshold: m.authority.threshold" crates/vecdht-node/src/config.rs
  echo "-- манифест: порог 1..=16 при threshold <= keys.len(), константы 3 нет:"
  grep -n "threshold: i64_of(obj, \"threshold\"" crates/vecdht-artifact/src/manifest.rs
  grep -n "authority.threshold > self.authority.keys.len" -A 4 crates/vecdht-artifact/src/manifest.rs
  echo "-- §15.1/§15.2 обещают 3-of-5:"
  grep -n "authority_keys: 3-of-5\|3-of-5 pubkeys\|(3-of-5, §15.2)" docs/VecDHT-SPEC-v8.md
  echo "-- §9.2: смысл индекса в sigs:"
  grep -n "позиция подписанта" docs/VecDHT-SPEC-v8.md
  echo "-- единственные подписи с индексами на wire:"
  grep -n "pub sigs" crates/vecdht-wire/src/messages.rs
  echo "-- домены дверей:"
  grep -n "pub const MEMBER\|pub const ARTIFACT" crates/vecdht-wire/src/messages.rs
  grep -n "pub const DOMAIN_NODE_CERT" crates/vecdht-crypto/src/cert.rs
  grep -n "pub const DOMAIN_ARTIFACT" crates/vecdht-artifact/src/manifest.rs
  echo "-- юнит-тесты дверей уже есть (не переписывались):"
  grep -rn "fn genesis_needs_the_authority_threshold_and_nothing_else\|fn threshold_signature_round_trip\|fn foreign_authority_key_does_not_count\|fn duplicate_signature_from_same_key_does_not_reach_threshold" crates
  echo "-- wire и спека не тронуты этим циклом:"
  git diff HEAD --stat -- crates/vecdht-wire docs/VecDHT-SPEC-v8.md
  echo "-- оракул E-0075:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/s15_authority_seam.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
