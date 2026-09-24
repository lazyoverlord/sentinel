"""Perturbation slice (SPEC §17): robustness to noise. Deterministic (seeded).

Text: typo noise (swap/drop/duplicate), character noise (random punctuation inside words), homoglyph noise
(Latin → Cyrillic/Greek look-alikes). Images: skew, blur, JPEG artefacts, perspective-like squeeze
("photographed screen" style).
"""
from __future__ import annotations

import io
import random

from PIL import Image, ImageFilter

HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "i": "і", "y": "у", "s": "ѕ"}


def typo(text: str, rate: float = 0.06, seed: int = 0) -> str:
    rng = random.Random(seed)
    out = list(text)
    i = 0
    while i < len(out) - 1:
        if out[i].isalpha() and rng.random() < rate:
            op = rng.choice(("swap", "drop", "dup"))
            if op == "swap":
                out[i], out[i + 1] = out[i + 1], out[i]
            elif op == "drop":
                del out[i]
                continue
            else:
                out.insert(i, out[i])
                i += 1
        i += 1
    return "".join(out)


def char_noise(text: str, rate: float = 0.05, seed: int = 0) -> str:
    rng = random.Random(seed)
    return "".join(c + (rng.choice(".-_*") if c.isalpha() and rng.random() < rate else "") for c in text)


def homoglyph(text: str, rate: float = 0.3, seed: int = 0) -> str:
    rng = random.Random(seed)
    return "".join(HOMOGLYPHS[c] if c in HOMOGLYPHS and rng.random() < rate else c for c in text)


TEXT_OPS = {"typo": typo, "char_noise": char_noise, "homoglyph": homoglyph}


def photo(png: bytes, seed: int = 0) -> bytes:
    """Skew + slight blur + squeeze + JPEG re-encode, like a phone photo of a screen."""
    rng = random.Random(seed)
    img = Image.open(io.BytesIO(png)).convert("RGB")
    img = img.rotate(rng.uniform(-4, 4), expand=True, fillcolor=(245, 245, 240))
    w, h = img.size
    img = img.resize((int(w * rng.uniform(0.85, 0.95)), h))
    img = img.filter(ImageFilter.GaussianBlur(rng.uniform(0.4, 1.0)))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=rng.randint(55, 75))
    return buf.getvalue()


def perturb_items(items: list[dict], ops=("typo", "char_noise", "homoglyph")) -> list[dict]:
    out = []
    for it in items:
        if "text" not in it:
            continue
        for k, op in enumerate(ops):
            out.append({**it, "id": f"{it['id']}~{op}", "text": TEXT_OPS[op](it["text"], seed=k),
                        "group": f"perturb:{op}"})
    return out
