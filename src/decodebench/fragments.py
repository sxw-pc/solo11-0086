"""片段声明校验：字节长度、源摘要、响应身份与一致总长。"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .models import LoadedFragment, SourceFile
from .scanner import fragment_payload

VALID_STATUS = "ok"
_SHA256_VALIDATOR = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")


def validator_digest(validator: str) -> str | None:
    """若 validator 可解析为 SHA-256 十六进制，返回其小写值。"""
    match = _SHA256_VALIDATOR.match(validator.strip())
    return match.group(1).lower() if match else None


def _stable_read(path: Path) -> tuple[bytes | None, str | None]:
    """读取文件并确认读取期间未被改写。"""
    try:
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        return None, f"读取失败: {exc}"
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(raw) != after.st_size
    ):
        return None, "读取期间源文件发生变化"
    return raw, None


def load_fragment(source: SourceFile) -> LoadedFragment:
    """按固定顺序校验一个已声明片段，返回带稳定状态的对象。"""
    decl = source.fragment
    if decl is None:
        raise ValueError("load_fragment 需要已解析的片段声明")
    raw, read_error = _stable_read(source.path)
    if read_error is not None:
        return LoadedFragment(source, decl, None, None, "changed_during_read", [read_error])
    assert raw is not None
    sha = hashlib.sha256(raw).hexdigest()
    if sha != source.sha256:
        return LoadedFragment(
            source,
            decl,
            None,
            sha,
            "changed_during_read",
            ["扫描后源文件字节已被改写，拒绝使用"],
        )
    if (
        decl.entity_size <= 0
        or decl.byte_start < 0
        or decl.byte_end_inclusive < decl.byte_start
        or decl.byte_end_inclusive >= decl.entity_size
    ):
        return LoadedFragment(
            source,
            decl,
            raw,
            sha,
            "out_of_bounds",
            [
                f"片段区间 {decl.byte_start}..{decl.byte_end_inclusive} "
                f"不在 0..{decl.entity_size - 1} 内"
            ],
        )
    if len(raw) != decl.length:
        status = "prefix_only" if len(raw) < decl.length else "length_mismatch"
        return LoadedFragment(
            source,
            decl,
            raw,
            sha,
            status,
            [f"片段实际 {len(raw)} 字节，声明区间长度 {decl.length} 字节"],
        )
    payload = fragment_payload(source.sidecar)
    declared_source = payload.get("source_sha256")
    if isinstance(declared_source, str) and declared_source.lower() != sha:
        return LoadedFragment(
            source,
            decl,
            raw,
            sha,
            "source_sha_mismatch",
            ["sidecar.source_sha256 与实际源摘要不一致"],
        )
    declared_fragment = payload.get("fragment_sha256")
    if isinstance(declared_fragment, str) and declared_fragment.lower() != sha:
        return LoadedFragment(
            source,
            decl,
            raw,
            sha,
            "fragment_sha_mismatch",
            ["sidecar.fragment_sha256 与实际片段摘要不一致"],
        )
    return LoadedFragment(source, decl, raw, sha, VALID_STATUS, [])


def load_fragments(
    sources: list[SourceFile],
) -> tuple[list[LoadedFragment], list[dict[str, Any]]]:
    """读取所有片段；声明本身有误的源单独记录，不进入实体。"""
    loaded: list[LoadedFragment] = []
    issues: list[dict[str, Any]] = []
    for source in sources:
        if source.fragment is None:
            if source.fragment_error:
                issues.append(
                    {
                        "rel_path": source.rel_path,
                        "status": "declaration_error",
                        "reason": source.fragment_error,
                    }
                )
            continue
        loaded.append(load_fragment(source))
    return loaded, issues


def build_groups(fragments: list[LoadedFragment]) -> dict[str, list[LoadedFragment]]:
    groups: dict[str, list[LoadedFragment]] = {}
    for fragment in fragments:
        groups.setdefault(fragment.decl.capture_id, []).append(fragment)
    for capture_id in groups:
        groups[capture_id].sort(
            key=lambda item: (
                item.decl.byte_start,
                item.decl.byte_end_inclusive,
                item.rel_path,
            )
        )
    return groups


def shared_fragments(fragments: list[LoadedFragment]) -> list[dict[str, Any]]:
    """发现不同捕获组/路径下内容与区间都相同的片段，只记录不合并。"""
    buckets: dict[tuple[Any, ...], list[LoadedFragment]] = {}
    for fragment in fragments:
        if fragment.sha256 is None:
            continue
        key = (
            fragment.decl.entity_id,
            fragment.decl.byte_start,
            fragment.decl.byte_end_inclusive,
            fragment.sha256,
        )
        buckets.setdefault(key, []).append(fragment)
    shared: list[dict[str, Any]] = []
    for key in sorted(buckets, key=lambda item: (str(item[0]), item[1], item[2], item[3])):
        bucket = buckets[key]
        identities = {(item.decl.capture_id, item.rel_path) for item in bucket}
        if len(identities) < 2:
            continue
        shared.append(
            {
                "entity_id": key[0],
                "byte_start": key[1],
                "byte_end_inclusive": key[2],
                "sha256": key[3],
                "fragments": [
                    {"capture_id": item.decl.capture_id, "rel_path": item.rel_path}
                    for item in sorted(
                        bucket, key=lambda row: (row.decl.capture_id, row.rel_path)
                    )
                ],
            }
        )
    return shared


def union_gaps(
    ranges: list[tuple[int, int]], entity_size: int
) -> list[dict[str, int]]:
    """返回 0..entity_size-1 上未被任何闭区间覆盖的空洞。"""
    clipped = sorted(
        (max(0, start), min(entity_size - 1, end))
        for start, end in ranges
        if start <= entity_size - 1 and end >= 0
    )
    gaps: list[dict[str, int]] = []
    cursor = 0
    for start, end in clipped:
        if start > cursor:
            gaps.append({"start": cursor, "end": start - 1})
        cursor = max(cursor, end + 1)
        if cursor >= entity_size:
            break
    if cursor < entity_size:
        gaps.append({"start": cursor, "end": entity_size - 1})
    return gaps
