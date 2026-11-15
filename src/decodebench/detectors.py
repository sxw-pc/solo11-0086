"""BOM、编码别名与严格解码统计（仅依赖标准库）。"""

from __future__ import annotations

import codecs
import unicodedata
from collections import Counter

from .models import DecodedSample

BOM_TABLE: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)

ALIASES = {
    "utf8": "utf-8",
    "utf_8": "utf-8",
    "utf-8-sig": "utf-8",
    "utf16": "utf-16",
    "utf_16": "utf-16",
    "utf16le": "utf-16-le",
    "utf-16le": "utf-16-le",
    "utf_16_le": "utf-16-le",
    "utf16be": "utf-16-be",
    "utf-16be": "utf-16-be",
    "utf_16_be": "utf-16-be",
    "gb2312": "gb18030",
    "gbk": "gb18030",
    "gb18030": "gb18030",
    "x-gbk": "gb18030",
    "cp936": "gb18030",
    "big5": "big5",
    "big-5": "big5",
    "big5-hkscs": "big5-hkscs",
    "cp950": "big5",
    "windows-1252": "windows-1252",
    "cp1252": "windows-1252",
    "win-1252": "windows-1252",
    "latin1": "latin-1",
    "latin-1": "latin-1",
    "iso-8859-1": "latin-1",
    "iso8859-1": "latin-1",
    "us-ascii": "ascii",
    "ascii": "ascii",
}

GB_FAMILY = {"gb18030"}
UTF16_FAMILY = {"utf-16", "utf-16-le", "utf-16-be"}


def detect_bom(raw: bytes) -> dict[str, str | int] | None:
    for marker, encoding in BOM_TABLE:
        if raw.startswith(marker):
            return {"encoding": encoding, "length": len(marker), "hex": marker.hex(" ")}
    return None


def canonical_encoding(name: str | None) -> str:
    if not name:
        return ""
    cleaned = name.strip().strip("\"'").lower().replace("_", "-")
    if cleaned in ALIASES:
        return ALIASES[cleaned]
    compact = cleaned.replace("-", "")
    if compact in ALIASES:
        return ALIASES[compact]
    try:
        return codecs.lookup(cleaned).name
    except LookupError:
        return cleaned


def compatible_encoding(declared: str | None, decision: str | None) -> bool:
    if not declared or not decision:
        return False
    left = canonical_encoding(declared)
    right = canonical_encoding(decision)
    if left == right:
        return True
    if left in GB_FAMILY and right in GB_FAMILY:
        return True
    if left in UTF16_FAMILY and right in UTF16_FAMILY:
        return True
    if left == "ascii" and right == "utf-8":
        return True
    return False


def looks_utf16(raw: bytes) -> bool:
    sample = raw[:2048]
    if len(sample) < 4:
        return False
    zeros = sample.count(0)
    if zeros / len(sample) < 0.20:
        return False
    even_zeros = sample[0::2].count(0) / max(1, len(sample[0::2]))
    odd_zeros = sample[1::2].count(0) / max(1, len(sample[1::2]))
    return max(even_zeros, odd_zeros) > 0.45


def _is_control(char: str) -> bool:
    category = unicodedata.category(char)
    if category in {"Cc", "Cs"} and char not in "\t\n\r\f":
        return True
    return False


def _is_cjk(char: str) -> bool:
    point = ord(char)
    return (
        0x3400 <= point <= 0x4DBF
        or 0x4E00 <= point <= 0x9FFF
        or 0xF900 <= point <= 0xFAFF
        or 0x20000 <= point <= 0x3134F
    )


def _is_latin(char: str) -> bool:
    point = ord(char)
    return 0x00C0 <= point <= 0x024F or 0x1E00 <= point <= 0x1EFF


def decode_sample(raw: bytes, encoding: str) -> DecodedSample:
    canonical = canonical_encoding(encoding)
    try:
        text = raw.decode(canonical, errors="strict")
    except (UnicodeError, LookupError, ValueError) as exc:
        return DecodedSample(
            encoding=canonical,
            success=False,
            text="",
            error=f"{type(exc).__name__}: {exc}"[:240],
            decoded_chars=0,
            replacement_count=0,
            control_ratio=0,
            printable_ratio=0,
            cjk_ratio=0,
            latin_ratio=0,
            unassigned_ratio=0,
            private_ratio=0,
            ascii_ratio=0,
            high_byte_ratio=0,
        )
    text = text.lstrip("﻿")
    total = len(text)
    denominator = max(1, total)
    controls = 0
    printable = 0
    cjk = 0
    latin = 0
    unassigned = 0
    private = 0
    ascii_count = 0
    categories: Counter[str] = Counter()
    for char in text:
        point = ord(char)
        if point < 128:
            ascii_count += 1
        categories[unicodedata.category(char)] += 1
        if _is_control(char):
            controls += 1
        if char.isprintable() or char in "\t\n\r\f":
            printable += 1
        if _is_cjk(char):
            cjk += 1
        if _is_latin(char):
            latin += 1
    unassigned = categories["Cn"]
    private = categories["Co"]
    high_bytes = sum(1 for byte in raw if byte >= 128)
    return DecodedSample(
        encoding=canonical,
        success=True,
        text=text,
        error=None,
        decoded_chars=total,
        replacement_count=text.count("�"),
        control_ratio=controls / denominator,
        printable_ratio=printable / denominator,
        cjk_ratio=cjk / denominator,
        latin_ratio=latin / denominator,
        unassigned_ratio=unassigned / denominator,
        private_ratio=private / denominator,
        ascii_ratio=ascii_count / denominator,
        high_byte_ratio=high_bytes / max(1, len(raw)),
    )
