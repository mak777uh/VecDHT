"""Проверка каркаса Python SDK (§17.1) без pytest и без собранного пакета.

Запуск из `sdk/vecdht-py` после `cargo build --release`:

    python test.py

Тест грузит расширение прямо по пути сборки, поэтому ему не нужен скопированный `.pyd` и не нужен
установленный пакет: каркас обязан быть проверяемым на той же машине, где его собрали.

Что здесь проверяется и почему именно это: границы между Rust и Python. Сам контракт (квантование,
assign, PoW) покрыт тестами в `crates/*`; здесь важно, что обёртка ничего не портит при передаче
через FFI — длину вектора, побайтовость hex, детерминизм повторного вызова и то, что незакрытые
методы громко падают, а не возвращают правдоподобную заглушку.
"""

import importlib.util
from importlib.machinery import ExtensionFileLoader
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
CANDIDATES = [
    HERE / "vecdht" / "vecdht_pyd.pyd",
    HERE / "vecdht" / "vecdht_pyd.dll",
    HERE / "target" / "release" / "vecdht_pyd.dll",
]


def load():
    for p in CANDIDATES:
        if p.exists():
            # ExtensionFileLoader, а не spec_from_file_location: у собранного на Windows cdylib
            # расширение `.dll`, и «обычный» поиск по суффиксам его не считает модулем.
            loader = ExtensionFileLoader("vecdht_pyd", str(p))
            spec = importlib.util.spec_from_loader("vecdht_pyd", loader)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod, p
    sys.exit(
        "расширение не найдено; собери его: cargo build --release в "
        f"{HERE} (искали: {', '.join(str(c) for c in CANDIDATES)})"
    )


def main():
    vd, path = load()
    print(f"загружено: {path}")
    checked = 0

    def ok(name, cond, detail=""):
        nonlocal checked
        if not cond:
            sys.exit(f"ПРОВАЛ: {name} {detail}")
        checked += 1
        print(f"  ok {name} {detail}")

    # 1. Константы приходят из Rust, а не переписаны в Python: сверка с тем, что читает узел.
    c = vd.constants()
    ok(
        "constants",
        c["dim"] == 384 and c["nlist"] == 1024 and c["shards"] == 64 and c["protocol_version"] == 8,
        f"{c['dim']}/{c['nlist']}/{c['shards']}/v{c['protocol_version']}",
    )
    ok(
        "pow-политика из артефакта",
        c["pow_bits_min"] <= c["pow_bits_default"] <= c["pow_bits_max"],
        f"{c['pow_bits_default']} в [{c['pow_bits_min']}; {c['pow_bits_max']}], фолбэк {c['blake3_mhz_core_fallback']} МХеш/с",
    )

    # 2. Артефакт: эталонный читается, хеш стабилен, манифест отдаётся JSON'ом.
    art = vd.Artifact.reference()
    h = art.artifact_hash()
    ok("artifact_hash", len(h) == 64 and h == vd.Artifact.reference().artifact_hash(), h[:16] + "…")
    man = json.loads(art.manifest_json())
    ok("manifest_json", man["routing"]["nlist"] == 1024 and man["power"]["pow_bits_default"] == c["pow_bits_default"])
    # Эталонный артефакт не подписан — и обязан об этом сказать. Если бы `verify()` вернул ноль
    # как успех, SDK молча принял бы артефакт, который узел отвергает (§15.1: pinned-хеш и
    # порог подписей авторитетов — то, чем сети отличают «наш артефакт» от «похожий»).
    try:
        art.verify()
        sys.exit("ПРОВАЛ: неподписанный эталонный артефакт прошёл проверку")
    except ValueError as exc:
        ok("verify отвергает неподписанный артефакт", "подписей" in str(exc), str(exc))

    # 3. Канонический текст (шаг 1): Python обязан получать то же, что подписывается (§6.6).
    canon = vd.normalize("  Привет   мир ")
    ok("normalize", canon == "Привет мир" and vd.is_canonical(canon) and not vd.is_canonical("  a  "), repr(canon))

    # 4. Шаги 6–8 через FFI: длина, границы и детерминизм после round-trip.
    pooled = [float(i % 11 - 5) / 3.0 for i in range(384)]
    e1 = art.finalize(pooled)
    e2 = art.finalize(pooled)
    ok(
        "finalize",
        len(e1["vec_q"]) == 384 and all(-127 <= v <= 127 for v in e1["vec_q"]) and e1 == e2,
        f"cluster {e1['cluster_id']} → shard {e1['shard']}",
    )
    ok("шард = кластер / 16 (§7.1)", e1["shard"] == e1["cluster_id"] // 16)
    try:
        art.finalize([0.0] * 383)
        sys.exit("ПРОВАЛ: finalize принял вектор неверной длины")
    except ValueError as exc:
        ok("длина входа проверяется", "384" in str(exc), str(exc))

    # 5. Query-путь: fan-out — это число `Find`, которое уйдёт по сети (§7.5).
    q = art.encode_query_surrogate("ищу партнёра по vector search", 16)
    ok("encode_query_surrogate", 1 <= q["fanout"] <= c["shards"], f"{q['fanout']} шардов, {len(q['clusters'])} кластеров")

    # 6. PoW: вход, перебор, проверка — через hex-границу побайтово.
    inp = vd.pow_input("a1" * 32, 7, 3, "b2" * 32, 1234)
    ok("pow_input", len(inp) == 2 * (13 + 32 + 2 + 8 + 32 + 4), f"{len(inp) // 2} байт домена+полей")
    nonce = vd.pow_mine(inp, c["pow_bits_min"], 0, 8_000_000)
    ok("pow_mine", nonce is not None and vd.pow_verify(inp, nonce, c["pow_bits_min"]), f"nonce {nonce}")
    try:
        vd.pow_mine(inp, 99, 0, 10)
        sys.exit("ПРОВАЛ: сложность вне артефакта принята")
    except ValueError as exc:
        ok("сложность вне диапазона отвергается", "outside" in str(exc), str(exc))

    # 7. Кодек: golden-фикстура wire-слоя декодируется через ту же функцию, что зовёт узел.
    vec = (REPO / "crates" / "vecdht-wire" / "tests" / "golden" / "vectors.txt").read_text(encoding="utf-8")
    fields = dict(
        line.split("=", 1) for line in vec.splitlines() if line.startswith(("frame.publish=", "body.publish="))
    )
    f = vd.decode_frame(fields["frame.publish"])
    ok(
        "decode_frame на golden-кадре",
        f["kind"] == "Publish" and f["version"] == 8 and f["body_hex"] == fields["body.publish"],
        f"{f['kind']} v{f['version']}, тело {len(f['body_hex']) // 2} байт",
    )

    # 8. Незакрытое должно падать, а не молча возвращать правдоподобные данные.
    agent = vd.Agent(".")
    for name, call in [
        ("publish", lambda: agent.publish("текст")),
        ("find", lambda: agent.find("текст")),
        ("session", lambda: agent.session("a1" * 32)),
    ]:
        try:
            call()
            sys.exit(f"ПРОВАЛ: Agent.{name} вернул результат, хотя транспорта нет")
        except NotImplementedError as exc:
            ok(f"Agent.{name} — NotImplemented", "P" in str(exc), str(exc).splitlines()[0][:60] + "…")

    print(f"\nпроверок: {checked} — все пройдены")


if __name__ == "__main__":
    main()
