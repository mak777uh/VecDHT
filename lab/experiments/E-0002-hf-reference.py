#!/usr/bin/env python3
"""HF-референс для гейта (v) §18.1 — ровно те тексты, что перечислены в `gate_v_texts()`.

Пишет **сырые** pooled CLS-векторы, без L2-нормализации: normalize — это шаг 6 пайплайна
(§6.2), и `ModernBertEmbedder::embed_pooled` тоже возвращает вектор до него. Сравнение
нормализованных векторов скрыло бы ошибки масштаба.

Запуск (веса и tokenizer — вне git, §AGENTS.md 9):

    python lab/experiments/E-0002-hf-reference.py \
        --model-dir C:/Users/Admin/models/granite-embedding-97m-r2 \
        --out C:/Users/Admin/models/granite-embedding-97m-r2/hf_reference_multi.txt

Порядок строк — порядок `GATE_V_TEXTS`: кириллица, английский, короткий, мультиязычный,
обрезка по max_length=256. Формат — по одному float на строку, чтобы Rust-тест разбирал его
через `split_whitespace`, не таща JSON-парсер в гейт.
"""

import argparse

import torch
from transformers import AutoModel, AutoTokenizer

MAX_LENGTH = 256

TEXTS = [
    "Ищу контрагента для vector search",
    "Find a contractor for vector search",
    "короткий текст",
    "мультиязычный запрос: 東京でベクトル検索",
    ("Это длинный текст для проверки обрезки по max_length. " * 40).strip(),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True)
    model = AutoModel.from_pretrained(
        args.model_dir, local_files_only=True, dtype=torch.float32
    )
    model.eval()

    vectors = []
    with torch.no_grad():
        for i, text in enumerate(TEXTS):
            batch = tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=MAX_LENGTH,
            )
            inputs = dict(batch)
            # ModernBertModel.forward не принимает token_type_ids (см. E-0002).
            inputs.pop("token_type_ids", None)
            hidden = model(**inputs).last_hidden_state
            cls = hidden[:, 0, :].to(torch.float32)[0]
            vectors.append(cls)
            print(
                f"текст {i}: токенов {batch['input_ids'].shape[1]}, "
                f"norm {cls.norm().item():.9f}"
            )

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        for vector in vectors:
            for value in vector.tolist():
                f.write(f"{value:.9g}\n")
    print(f"записано {len(vectors)} векторов по {vectors[0].numel()} чисел в {args.out}")


if __name__ == "__main__":
    main()
