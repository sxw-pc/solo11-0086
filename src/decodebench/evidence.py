"""从字节、文档声明与 sidecar 中提取编码证据。"""

from __future__ import annotations

import re
from typing import Any

from .config import Config
from .detectors import compatible_encoding, detect_bom, looks_utf16
from .models import Evidence, SourceFile

XML_PATTERN_BYTES = re.compile(
    rb"<\?xml\b[^>]{0,400}?encoding\s*=\s*[\"']\s*([A-Za-z][A-Za-z0-9._-]*)\s*[\"']",
    re.IGNORECASE,
)
XML_PATTERN_TEXT = re.compile(
    r"<\?xml\b[^>]{0,400}?encoding\s*=\s*[\"']\s*([A-Za-z][A-Za-z0-9._-]*)\s*[\"']",
    re.IGNORECASE,
)
META_TAG = re.compile(rb"<meta\b[^>]{0,1024}>", re.IGNORECASE | re.DOTALL)
META_CHARSET = re.compile(
    rb"charset\s*=\s*[\"']?\s*([A-Za-z][A-Za-z0-9._-]*)", re.IGNORECASE
)
HEADER_CHARSET = re.compile(r"charset\s*=\s*[\"']?\s*([A-Za-z][A-Za-z0-9._-]*)", re.IGNORECASE)


def _line_for(raw: bytes, offset: int) -> int:
    return raw[: max(0, offset)].count(b"\n") + 1


def _xml_ascii(raw: bytes) -> list[Evidence]:
    start = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    while start < len(raw) and raw[start : start + 1] in b" \t\r\n":
        start += 1
    match = XML_PATTERN_BYTES.match(raw, start)
    if not match:
        return []
    value = match.group(1).decode("ascii", errors="replace")
    offset = match.start(1)
    return [
        Evidence(
            source="xml_declaration",
            declared=value,
            offset=offset,
            line=_line_for(raw, offset),
            note="XML declaration 中的 encoding 属性",
        )
    ]


def _utf16_order(raw: bytes) -> str | None:
    if raw.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if raw.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if not looks_utf16(raw):
        return None
    even_zeros = raw[0:2048:2].count(0)
    odd_zeros = raw[1:2048:2].count(0)
    return "utf-16-be" if even_zeros >= odd_zeros else "utf-16-le"


def _xml_utf16(raw: bytes) -> list[Evidence]:
    order = _utf16_order(raw)
    if order is None:
        return []
    try:
        prefix = raw[:4096].decode(order, errors="ignore")
    except (UnicodeError, LookupError):
        return []
    match = XML_PATTERN_TEXT.search(prefix)
    if not match or match.start() > 64:
        return []
    offset = match.start(1) * 2
    line = prefix[: match.start(1)].count("\n") + 1
    return [
        Evidence(
            source="xml_declaration",
            declared=match.group(1),
            offset=offset,
            line=line,
            note=f"UTF-16（{order}）XML declaration 中的 encoding 属性",
        )
    ]


def _meta_evidence(raw: bytes) -> list[Evidence]:
    found: list[Evidence] = []
    for tag in META_TAG.finditer(raw):
        match = META_CHARSET.search(tag.group(0))
        if not match:
            continue
        value = match.group(1).decode("ascii", errors="replace")
        offset = tag.start() + match.start(1)
        found.append(
            Evidence(
                source="meta_charset",
                declared=value,
                offset=offset,
                line=_line_for(raw, offset),
                note="HTML meta charset 声明",
            )
        )
    return found


def _header_evidence(sidecar: dict[str, Any]) -> list[Evidence]:
    headers = sidecar.get("headers", {})
    if not isinstance(headers, dict):
        return []
    content_types: list[tuple[str, str]] = []
    for name, value in headers.items():
        if str(name).lower() == "content-type" and isinstance(value, str):
            content_types.append((str(name), value))
    content_types.sort(key=lambda item: item[0].lower())
    found: list[Evidence] = []
    for name, value in content_types:
        match = HEADER_CHARSET.search(value)
        if not match:
            continue
        found.append(
            Evidence(
                source="http_header",
                declared=match.group(1),
                offset=None,
                line=None,
                note=f"sidecar 响应头 {name}: {value}",
            )
        )
    return found


def collect_evidence(source: SourceFile, raw: bytes, config: Config) -> list[Evidence]:
    """按 BOM、HTTP 头、XML、meta、fallback 的稳定顺序汇总证据。"""
    evidence: list[Evidence] = []
    bom = detect_bom(raw)
    if bom is not None:
        evidence.append(
            Evidence(
                source="bom",
                declared=str(bom["encoding"]),
                offset=0,
                line=1,
                note=f"文件头字节 {bom['hex']}，长度 {bom['length']}",
            )
        )
    if config.trusted_http_headers and source.sidecar:
        evidence.extend(_header_evidence(source.sidecar))
    evidence.extend(_xml_ascii(raw))
    if not any(item.source == "xml_declaration" for item in evidence):
        evidence.extend(_xml_utf16(raw))
    evidence.extend(_meta_evidence(raw))
    evidence.append(
        Evidence(
            source="fallback",
            declared=config.fallback_encoding,
            offset=None,
            line=None,
            note="配置文件 detection.fallback_encoding",
        )
    )
    return evidence


def collect_assembled_evidence(
    source: SourceFile,
    raw: bytes,
    config: Config,
    note: str,
) -> list[Evidence]:
    """只在已选定的完整组装字节上解释 BOM/头/文档声明。

    片段末尾被截断的多字节序列不参与解码，因此这里不会把片段边界误报为
    编码失败；额外的 `assembly` 证据只描述逻辑实体身份。
    """
    evidence = [
        Evidence(
            source="assembly",
            declared=None,
            offset=None,
            line=None,
            note=note,
        )
    ]
    evidence.extend(collect_evidence(source, raw, config))
    return evidence



def declaration_values(evidence: list[Evidence], source: str) -> list[Evidence]:
    return [item for item in evidence if item.source == source and item.declared]


def all_declared(evidence: list[Evidence]) -> list[Evidence]:
    return [
        item
        for item in evidence
        if item.source in {"bom", "http_header", "xml_declaration", "meta_charset"}
        and item.declared
    ]


def apply_decision_matches(evidence: list[Evidence], decision_encoding: str) -> None:
    for item in evidence:
        if item.source == "assembly":
            item.matches_decision = None
        elif item.source == "fallback":
            item.matches_decision = compatible_encoding(item.declared, decision_encoding)
        elif item.declared:
            item.matches_decision = compatible_encoding(item.declared, decision_encoding)
        else:
            item.matches_decision = None
