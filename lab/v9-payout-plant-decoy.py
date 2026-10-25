#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Посадка прежней (до правки) формулы `term_hash` в копию носителя слоя.

Зачем. Цикл `E-0114` закрыт зелёным прибором, и зелёный прибор сам по себе ничего не стоит:
нужен исполняемый след того, что он краснеет на том именно дефекте, который этот цикл чинил.
До правки §V9.7 носитель печатал формулу `term_hash` с разделителями `0x00` между всеми полями,
тогда как код (`crates/vecdht-orders/src/lib.rs`, `term_hash`) ставит терминатор только после
литерала домена — остальные поля фиксированной ширины, `asset_bytes` несёт свой терминатор
внутри, а `escrow_ref` предваряется длиной. Расход ловился ровно одним числом:
`V9C_TERM_EQ_GOT=0` из 31 вектора.

Что делает этот файл. Читает носитель, находит fence формулы в §1 и заменяет его дословно тем
блоком, который генератор печатал до правки (он же — в `docs/PAID_PAYOUT-VECTORS.md` дерева до
замера). Копия печатается в stdout; в stderr — сколько байт различают копию и оригинал.

Что есть провал прибора. Если маркер fence не найден, файл молча вернул бы неизменённый носитель,
и «красный контроль» стал бы зелёным: отсюда `sys.exit(3)` на отсутствии маркера и проверка, что
копия обязана отличаться от оригинала ненулевым числом байт.

Команда:
    python lab/v9-payout-plant-decoy.py docs/PAID_PAYOUT-VECTORS.md > /tmp/carrier_decoy.md
    python lab/v9-payout-bridge.py /tmp/carrier_decoy.md   # ожидание: V9C_TERM_EQ=0
"""

import sys

# Дословный блок §1 до правки: терминатор после каждого поля.
BEFORE = """term_hash = sha256( DOMAIN_TERM ‖ 0x00 ‖ order_ref(32) ‖ 0x00 ‖ chain_id:u64le ‖ 0x00 ‖
                         asset_bytes ‖ beneficiary_pubkey(32) ‖ 0x00 ‖
                         amount:u128le ‖ 0x00 ‖ u32le(len(escrow_ref)) ‖ escrow_ref
)"""

# Дословный блок §1 после правки: терминатор только после домена.
AFTER = """term_hash = sha256( DOMAIN_TERM ‖ 0x00 ‖ order_ref(32) ‖ chain_id:u64le ‖
                         asset_bytes ‖ beneficiary_pubkey(32) ‖ amount:u128le ‖
                         u32le(len(escrow_ref)) ‖ escrow_ref
)"""

MARKER = "term_hash = sha256("


def main(argv):
    path = argv[1] if len(argv) > 1 else "docs/PAID_PAYOUT-VECTORS.md"
    text = open(path, encoding="utf-8").read()
    if MARKER not in text:
        print("ПОСАДКА_НЕ_ИСПОЛНЕНА: в носителе нет формулы term_hash — контроль бесполезен",
              file=sys.stderr)
        return 3
    if AFTER not in text:
        print("ПОСАДКА_НЕ_ИСПОЛНЕНА: fence §1 не совпадает с ожидаемым (носитель переписан)",
              file=sys.stderr)
        return 3
    planted = text.replace(AFTER, BEFORE, 1)
    if planted == text:
        print("ПОСАДКА_НЕ_ИСПОЛНЕНА: замена не изменила байты", file=sys.stderr)
        return 3
    old = text.encode("utf-8")
    new = planted.encode("utf-8")
    first = next((i for i in range(min(len(old), len(new))) if old[i] != new[i]), min(len(old), len(new)))
    # Буфер, а не текст: на Windows текстовый stdout переводит "\n" в "\r\n", и копия перестала
    # бы быть побайтной — а именно побайтная копия и есть вход контроля.
    sys.stderr.write("ПОСАЖЕНО_РАСХОДЯЩИХСЯ_БАЙТ=%d\n" %
                     sum(1 for i in range(min(len(old), len(new))) if old[i] != new[i]))
    sys.stderr.write("ПОСАЖЕНО_ПЕРВОЕ_РАСХОЖДЕНИЕ=%d ПОСАЖЕНО_СДВИГ_ХВОСТА=%d\n" %
                     (first, len(new) - len(old)))
    sys.stderr.write("ДЛИНА_КОПИИ=%d ДЛИНА_НОСИТЕЛЯ=%d\n" % (len(new), len(old)))
    sys.stdout.buffer.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
