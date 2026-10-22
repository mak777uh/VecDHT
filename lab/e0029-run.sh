#!/usr/bin/env bash
# E-0029 (H-0028): читается ли вообще поле `shard` в MatchResult / RendezvousAccept.
# Только grep: сборки нет, тяжёлую цепочку e0027 не трогаем.
set -uo pipefail
cd "$(dirname "$0")/.."
LOG="lab/logs/e0029-all.log"
: > "$LOG"
SRC="crates/vecdht-net/src crates/vecdht-node/src crates/vecdht-index/src"
{
  echo "########## E-0029 · мёртвые поля shard · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## (1) чтения .shard вне тестов и комментариев ##########"
  grep -rn "\.shard" $SRC 2>/dev/null | grep -v "/tests/" | grep -v "//" \
    | grep -vE "shard_of|\.shards|self\.shard|entry\.shard|want:|found:|shard:|=> |spec\.shard"
  echo "########## (1а) отдельно: res\.shard / mr\.shard / answer\.shard / r#do\.shard ##########"
  grep -rnE "(res|mr|answer|rdo)\.shard" $SRC 2>/dev/null | grep -v "/tests/" | grep -v "//"
  echo "########## (1б) СЧЕТЧИК (1а): $(grep -rnE "(res|mr|answer|rdo)\.shard" $SRC 2>/dev/null | grep -v "/tests/" | grep -vc "//") ##########"
  echo "########## (2) приёмники Kind::RendezvousAccept в node (кроме производителя) ##########"
  grep -rn "RendezvousAccept" crates/vecdht-node/src crates/vecdht-net/src 2>/dev/null \
    | grep -v "/tests/" | grep -v "//"
  echo "########## (2а) СЧЕТЧИК (2): $(grep -rn "RendezvousAccept" crates/vecdht-node/src crates/vecdht-net/src 2>/dev/null | grep -v "/tests/" | grep -vc "//") ##########"
  echo "########## (3) откуда берётся аргумент shard в verify_match_result ##########"
  grep -rn "verify_match_result" crates/vecdht-net/src 2>/dev/null | grep -v "//"
  echo "########## (3а) подпись сверяется по байтам кадра или по пересборке? ##########"
  grep -n -A14 "fn verify_match_result" crates/vecdht-net/src/agent.rs | head -20
  echo "########## (4) норматив спеки: требование отвергать вне диапазона ##########"
  grep -n "SHARDS" docs/VecDHT-SPEC-v8.md
  grep -nc "обязан.*вне диапазона\|отвергнуть.*SHARDS" docs/VecDHT-SPEC-v8.md
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
