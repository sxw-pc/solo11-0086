"""UTF-8 转码输出与编码声明重写。"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .config import Config
from .detectors import canonical_encoding, detect_bom
from .models import SourceFile, TranscodeResult

XML_DECLARATION = re.compile(
    r"\A\s*(<\?xml\b[^>]{0,400}?encoding\s*=\s*[\"']\s*)"
    r"([A-Za-z][A-Za-z0-9._-]*)"
    r"(\s*[\"'])",
    re.IGNORECASE,
)
META_TAG = re.compile(r"<meta\b[^>]{0,1024}>", re.IGNORECASE | re.DOTALL)
META_CHARSET = re.compile(
    r"(charset\s*=\s*[\"']?\s*)([A-Za-z][A-Za-z0-9._-]*)",
    re.IGNORECASE,
)
REWRITABLE_SUFFIXES = {".html", ".htm", ".xml"}


def _line_at(text: str, offset: int) -> int:
    return text[: max(0, offset)].count("\n") + 1


def _replacement(kind: str, original: str, start: int, end: int, text: str) -> dict[str, object]:
    return {
        "kind": kind,
        "original": original,
        "new": "utf-8",
        "line": _line_at(text, start),
        "offset": start,
        "position_basis": "decoded_source_characters",
        "end_offset": end,
    }


def rewrite_declarations(text: str, suffix: str) -> tuple[str, list[dict[str, object]]]:
    """把 HTML/XML 中声明的非 UTF-8 字符集改写为 utf-8。"""
    if suffix.lower() not in REWRITABLE_SUFFIXES:
        return text, []
    replacements: list[dict[str, object]] = []
    xml_match = XML_DECLARATION.match(text)
    if xml_match:
        original = xml_match.group(2)
        if canonical_encoding(original) != "utf-8":
            replacements.append(
                _replacement(
                    "xml_declaration",
                    original,
                    xml_match.start(2),
                    xml_match.end(2),
                    text,
                )
            )
    for tag in META_TAG.finditer(text):
        charset = META_CHARSET.search(tag.group(0))
        if not charset:
            continue
        original = charset.group(2)
        if canonical_encoding(original) == "utf-8":
            continue
        start = tag.start() + charset.start(2)
        end = tag.start() + charset.end(2)
        replacements.append(_replacement("html_meta_charset", original, start, end, text))
    if not replacements:
        return text, []
    rewritten = text
    for item in sorted(replacements, key=lambda row: int(row["offset"]), reverse=True):
        start = int(item["offset"])
        end = int(item["end_offset"])
        rewritten = rewritten[:start] + "utf-8" + rewritten[end:]
    return rewritten, replacements


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
    os.replace(temporary, path)


def transcode(source: SourceFile, raw: bytes, encoding: str, config: Config) -> TranscodeResult:
    """按裁决编码严格或替换解码，只写入独立转码目录。"""
    canonical = canonical_encoding(encoding)
    errors = config.transcode_errors
    try:
        text = raw.decode(canonical, errors=errors)
    except (UnicodeError, LookupError, ValueError) as exc:
        return TranscodeResult(
            success=False,
            encoding=canonical,
            errors=errors,
            output_rel_path=None,
            source_sha256=source.sha256,
            output_sha256=None,
            bytes_written=0,
            decoded_chars=0,
            replacement_count=0,
            replacement_used=False,
            bom_removed=False,
            rewrites=[],
            error=f"{type(exc).__name__}: {exc}"[:300],
        )

    bom_removed = False
    if detect_bom(raw) is not None and text.startswith("﻿"):
        text = text[1:]
        bom_removed = True

    rewrites: list[dict[str, object]] = []
    if config.rewrite_declarations:
        text, rewrites = rewrite_declarations(text, Path(source.rel_path).suffix)

    output = config.transcode_dir / source.rel_path
    try:
        output.resolve().relative_to(config.transcode_dir)
    except ValueError as exc:
        raise ValueError(f"转码输出路径越界: {source.rel_path}") from exc
    payload = text.encode("utf-8")
    _atomic_write(output, payload)
    output_sha = hashlib.sha256(payload).hexdigest()
    replacement_count = text.count(chr(0xFFFD))
    return TranscodeResult(
        success=True,
        encoding=canonical,
        errors=errors,
        output_rel_path=source.rel_path,
        source_sha256=source.sha256,
        output_sha256=output_sha,
        bytes_written=len(payload),
        decoded_chars=len(text),
        replacement_count=replacement_count,
        replacement_used=replacement_count > 0,
        bom_removed=bom_removed,
        rewrites=rewrites,
    )
