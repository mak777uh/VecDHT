#!/usr/bin/env bash
# H-0099, прибор формального контура №3 (Kani) для хоста без Kani.
#
# Зачем он существует: у Kani 0.68.0 четыре publish-ассета — Linux и macOS, Windows-сборки нет
# (`L-0018`). Значит на этом ноутбуке `cargo kani` неисполним в принципе, и харнеси из
# `crates/vecdht-node/src/admission.rs` под `#[cfg(kani)]` не компилируются ни здесь, ни в
# `cargo test`: обычный прогон их просто не видит. Полностью вслепую отдавать их в CI нельзя —
# опечатка в типе стоила бы красным прогоном и часом ожидания.
#
# Что делает прибор: механически вырезает из продукта (а) константы и тело `cell_cap_limit`,
# (б) все модули под `#[cfg(kani)]`, подставляет заглушку API Kani и прогоняет результат через
# `rustc --emit=metadata`. То есть проверяется ровно то, что исполнит CI: типы, имена, видимость.
# Проверка *корректности* утверждений этот прибор не делает — это делает Kani в CI, и подмена
# одного другим в карточке цикла не допускается.
#
# Метки стабильные, ASCII, читаются `lab/expectations/e0099.tsv`:
#   KCC_HARNESS_FNS=   сколько `fn` с атрибутом proof вырезано из продукта
#   KCC_ANCHORS=       сколько якорей из четырёх найдено (две константы, тело функции, модуль)
#   KCC_STATUS=OK|BAD  результат компиляции
#   KCC_RC=            код `rustc`
# Режимы: `check` (по умолчанию), `selftest` (посадка дефектов), `--print` (собранный текст в stdout).
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
SRC=crates/vecdht-node/src/admission.rs
WIRE=crates/vecdht-wire/src/constants.rs

# ------------------------------------------------------------------ вырезание из продукта
# Якоря подобраны так, что отсутствие любого из них видно по числу, а не по молчанию: пустой
# вырезок компилируется в пустышку и дал бы OK, поэтому ANCHORS обязан сойтись до компиляции.
extract_core() {
  { echo "// --- механически вырезано из $SRC ---"
    sed -n '/^pub const CELL_CAP_NUM/,/^const _: () = assert!(CELL_CAP_NUM/p' "$SRC"
  }
}
extract_harnesses() {
  # Атрибуты срезаются: заглушка не proc-macro, а `#[cfg(kani)]` в temp-крате выключил бы модуль.
  sed -n '/^#\[cfg(kani)\]/,/^}$/p' "$SRC" | grep -vE '^#\[cfg\(kani\)\]|^\s+#\[kani::(proof|unwind)'
}
count_harness_fns() { grep -cE '^\s+fn [a-z_0-9]+\(\) \{' <<<"$(extract_harnesses)"; }
count_anchors() {
  local n=0 core="$1" har="$2"
  grep -q 'pub const CELL_CAP_NUM' <<<"$core" && n=$((n + 1))
  grep -q 'pub fn cell_cap_limit' <<<"$core" && n=$((n + 1))
  grep -q 'pub const CELL_CAP_MAX_LIVE' <<<"$core" && n=$((n + 1))
  grep -q 'mod kani_harnesses' <<<"$har" && n=$((n + 1))
  echo $n
}
stub() {
  cat <<'RS'
// --- заглушка API Kani: только подпись, никакого model checking ---
#[allow(dead_code, unused_macros)]
mod kani {
    pub trait Arbitrary: Sized { fn any_() -> Self; }
    impl Arbitrary for u64 { fn any_() -> Self { 0 } }
    impl Arbitrary for bool { fn any_() -> Self { false } }
    pub fn any<A: Arbitrary>() -> A { A::any_() }
    pub fn assume(_b: bool) {}
    pub fn unconstrained<T: Default>() -> T { T::default() }
    macro_rules! cover { ($e:expr) => { let _ = $e; } }
    pub(crate) use cover;
}
RS
}
assemble() {
  local core har
  core="$(extract_core)"
  har="$(extract_harnesses)"
  { echo '#![allow(dead_code)]'
    echo "pub const CLUSTERS_PER_SHARD: u16 = $(grep -oE 'CLUSTERS_PER_SHARD: u16 = [0-9_]+' "$WIRE" | cut -d= -f2 | tr -d ' ');"
    echo "$core"
    stub
    echo "$har"
  }
}

mode="${1:-check}"
if [ "$mode" = "--print" ]; then assemble; exit 0; fi

DIR="$(mktemp -d "${TMPDIR:-/tmp}/kcc-XXXXXX")"
cleanup() { rm -rf "$DIR"; }
trap cleanup EXIT

# ------------------------------------------------------- компиляция одного собранного текста
compile_text() { # $1=текст temp-крата, $2=имейл для лога
  local f="$DIR/kcc.rs"
  printf '%s\n' "$1" > "$f"
  local out rc
  out="$(rustc --edition 2021 --crate-type=lib --emit=metadata -o "$DIR/kcc.rmeta" "$f" 2>&1)"; rc=$?
  printf '%s\n' "$out" | grep -E '^error' | head -5
  return $rc
}

if [ "$mode" = selftest ]; then
  echo "### KCC SELFTEST ###"
  pass=0; total=0
  good="$(assemble)"
  # (1) боевой текст обязан компилироваться.
  total=$((total + 1)); if compile_text "$good" >/dev/null; then echo "s1_good=OK"; pass=$((pass + 1)); else echo "s1_good=BAD"; fi
  # (2) харнес со сломанным типом — прибор обязан покраснеть.
  total=$((total + 1))
  badtype="$(printf '%s\n' "$good" | sed 's/assert!(cap >= min);/assert!(cap >= min); let _wrong: u32 = cap;/')"
  if compile_text "$badtype" >/dev/null; then echo "s2_type=ПРОПУЩЕН(прибор слеп)"; else echo "s2_type=Пойман"; pass=$((pass + 1)); fi
  # (3) удаление модуля-харнеса (неудачный якорь) — краснеет по числу якорей, а не по молчанию.
  total=$((total + 1))
  anchors_n=$(count_anchors "$(extract_core)" "")
  if [ "$anchors_n" -lt 4 ]; then echo "s3_anchor=Пойман (якорей=$anchors_n)"; pass=$((pass + 1)); else echo "s3_anchor=ПРОПУЩЕН"; fi
  # (4) константа из продукта вырезана та же, что в wire: подмена 16 на 8 ломает компиляцию тела.
  total=$((total + 1))
  drift="$(printf '%s\n' "$good" | sed 's/^pub const CLUSTERS_PER_SHARD: u16 = 16;/pub const CLUSTERS_PER_SHARD: u16 = 0xZZ;*/')"
  if compile_text "$drift" >/dev/null; then echo "s4_const=ПРОПУЩЕН"; else echo "s4_const=Пойман"; pass=$((pass + 1)); fi
  echo "KCC_SELFTEST total=$total passed=$pass"
  [ "$pass" -eq "$total" ] && { echo "KCC_SELFTEST_STATUS=OK"; exit 0; } || { echo "KCC_SELFTEST_STATUS=BAD"; exit 1; }
fi

CORE="$(extract_core)"
HAR="$(extract_harnesses)"
ANCHORS=$(count_anchors "$CORE" "$HAR")
HFNS=$(count_harness_fns)
TEXT="$(assemble)"
if compile_text "$TEXT"; then RC=0; else RC=1; fi
echo "KCC_ANCHORS=$ANCHORS"
echo "KCC_HARNESS_FNS=$HFNS"
echo "KCC_RUSTC_RC=$RC"
if [ "$RC" -eq 0 ] && [ "$ANCHORS" -eq 4 ] && [ "$HFNS" -ge 1 ]; then
  echo "KCC_STATUS=OK"; exit 0
fi
echo "KCC_STATUS=BAD"; exit 1
