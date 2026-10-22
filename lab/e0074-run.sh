#!/usr/bin/env bash
# E-0074: хвост §9.4/§9.7 — дыра WAL, аутентичность pull, снапшот-путь, уход primary.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0074-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0074 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test s94_tail --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test s94_tail -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- матрица подписей: pull вне signature_required, ReplicateOp/SnapshotOffer внутри:"
  sed -n '/pub fn signature_required/,/^    }/p' crates/vecdht-wire/src/frame.rs
  echo "-- WalPullResponse: encode_unsigned и отсутствие epoch/подписи у фреймов:"
  grep -n "fn handle_pull_request" -A 55 crates/vecdht-node/src/node.rs | tail -18
  echo "-- handle_pull_response: какие проверки есть до применения:"
  grep -n "fn handle_pull_response" -A 12 crates/vecdht-node/src/node.rs
  echo "-- приём снапшота: отказ тёплому до любой записи:"
  grep -n "fn install_snapshot" -A 10 crates/vecdht-node/src/node.rs
  echo "-- продолжение pull только по дыре, не по усечённому лимиту:"
  grep -n "applied_seq < resp.to_seq" -B 3 -A 3 crates/vecdht-node/src/node.rs
  grep -n "MAX_PULL_ATTEMPTS" crates/vecdht-node/src/node.rs
  echo "-- serve_snapshot: живые поля manifest() против файла last_snapshot_seq:"
  grep -n "let mf = self.store.manifest\|snapshot_seq: seq\|applied_seq: mf.applied_seq\|next_slot: mf.next_slot" crates/vecdht-node/src/node.rs
  echo "-- flush_snapshot пишет applied_seq/next_slot на момент барьера:"
  grep -n "let mf = StoreManifest" -A 9 crates/vecdht-index/src/store.rs
  echo "-- drain_deadline_bucket: запись без чтения:"
  grep -rn "drain_deadline_bucket" crates
  echo "-- §9.7: обещание подписанных фреймов и догона после LeaveNotice:"
  grep -n "подписанные фреймы\|После .LeaveNotice\|после .LeaveNotice" docs/VecDHT-SPEC-v8.md
  echo "-- §9.5 п.2: seed отдаёт последний снапшот кусками:"
  grep -n "отдают последний опубликованный снапшот" docs/VecDHT-SPEC-v8.md
  echo "-- пустой состав/seed уже покрыт gates_p4 (не перемерялся):"
  grep -n "fn when_everyone_leaves_a_seed_serves_the_snapshot" crates/vecdht-node/tests/gates_p4.rs
  echo "-- геометрия снапшота:"
  grep -n "pub fn snapshot_size_for" -A 3 crates/vecdht-index/src/snapshot.rs
  grep -n "SNAPSHOT_CHUNK_MAX_LEN" crates/vecdht-wire/src/constants.rs
  echo "-- wire не тронут (нет диффа):"
  git diff HEAD --stat -- crates/vecdht-wire
  echo "-- оракул E-0074:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/s94_tail.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
