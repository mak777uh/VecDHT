"""VecDHT v8 — Python SDK (§17.1).

Пакет-обёртка над Rust-расширением `vecdht_pyd`. Всё содержимое — реэкспорт: прав на
кодирование кадров, квантование, assign или PoW здесь нет и появиться они не могут, потому что
второй реализацией того же контракта Python стал бы вторым источником истины (спека §0, строка 10,
— ровно та причина, по которой v7.5 со своим «каноническим protobuf-энкодером» рассорился сам с
собой).

Чтобы пакет заработал, собранное расширение должно лежать рядом:

    cargo build --release            # в sdk/vecdht-py
    cp target/release/vecdht_pyd.dll vecdht/vecdht_pyd.pyd

Сборочный артефакт в git не хранится: он принадлежит конкретному Python, ABI и платформе, и
коммитить его — значит однажды получить «зелёный» импорт на чужой машине.
"""

from vecdht_pyd import (
    PROTOCOL_VERSION,
    Agent,
    Artifact,
    constants,
    decode_frame,
    is_canonical,
    normalize,
    pow_input,
    pow_mine,
    pow_verify,
    protocol_version,
)

__all__ = [
    "PROTOCOL_VERSION",
    "Agent",
    "Artifact",
    "constants",
    "decode_frame",
    "is_canonical",
    "normalize",
    "pow_input",
    "pow_mine",
    "pow_verify",
    "protocol_version",
]
