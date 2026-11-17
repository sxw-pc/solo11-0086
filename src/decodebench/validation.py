"""完全离线的 304 验证响应：本地状态解析、200 原件归属与头部合成。

304 没有正文，必须归属到唯一早先捕获、带完整实体字节的 200；无法唯一
归属时保留证据转人工复核，绝不用就近文件名、同目录现状或空 304 冒充正文。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detectors import canonical_encoding, compatible_encoding, detect_bom
from .models import SourceFile

VIEWS_SUBDIR = "_validation_views"

@dataclass(frozen=True)
class CaptureState:
    status: int
    resource_key: str
    captured_at: str
    captured_moment: datetime
    request_vary: dict[str, str]
    etag: str | None
    headers: dict[str, str]

@dataclass
class Attribution:
    attributed: bool
    error_codes: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    donor: SourceFile | None = None
    donor_raw: bytes = b""
    candidate_rel_paths: list[str] = field(default_factory=list)
    reason: str = ""

def _parse_timestamp(value: str) -> datetime | None:
    text = value[:-1] + "+00:00" if value.strip().endswith(("Z", "z")) else value.strip()
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)

def _normalize_vary(mapping: dict[Any, Any]) -> dict[str, str]:
    return {n.strip().lower(): v.strip() for n, v in mapping.items()
            if isinstance(n, str) and isinstance(v, str)}

def parse_capture_state(sidecar: dict[str, Any]) -> tuple[CaptureState | None, list[str]]:
    """解析合成 sidecar；结构不合同时返回 None 与稳定错误码，不做猜测。"""
    errors: list[str] = []
    if not isinstance(sidecar, dict) or not sidecar.get("local_capture"):
        return None, ["E_304_NOT_STATE_SIDECAR"]
    status = sidecar.get("status")
    if not isinstance(status, int):
        errors.append("E_304_MALFORMED_STATE")
    headers = sidecar.get("headers", {})
    if not isinstance(headers, dict):
        errors.append("E_304_MALFORMED_STATE")
        headers = {}
    resource_key = sidecar.get("resource_key")
    if not isinstance(resource_key, str) or not resource_key:
        errors.append("E_304_MALFORMED_STATE")
        resource_key = ""
    captured_at = sidecar.get("captured_at")
    moment = (_parse_timestamp(captured_at)
              if isinstance(captured_at, str) and captured_at else None)
    if moment is None:
        errors.append("E_304_MALFORMED_STATE")
    request_vary = sidecar.get("request_vary")
    if not isinstance(request_vary, dict):
        errors.append("E_304_VARY_INPUT_MISSING")
        request_vary = {}
    etag = sidecar.get("etag")
    if etag is not None and not isinstance(etag, str):
        errors.append("E_304_MALFORMED_STATE")
        etag = None
    if errors:
        return None, errors
    assert moment is not None
    return CaptureState(
        int(status), str(resource_key), str(captured_at), moment,
        _normalize_vary(request_vary),
        etag.strip() if isinstance(etag, str) else None,
        {str(n): str(v) for n, v in headers.items()}), []

def is_strong_etag(etag: str | None) -> bool:
    """强验证标记：非空、带引号且没有 W/ 弱前缀。"""
    if not etag:
        return False
    value = etag.strip()
    return (bool(value) and not value.startswith(("W/", "w/"))
            and value.startswith('"') and value.endswith('"') and len(value) >= 2)

def synthesize_headers(headers_200: dict[str, str],
                       headers_304: dict[str, str]) -> list[dict[str, str]]:
    """304 出现的同名字段覆盖 200（大小写不敏感），其余沿用旧值；标注来源。"""
    lowered_304 = {n.strip().lower(): n for n in headers_304}
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for name, value in headers_200.items():
        key = name.strip().lower()
        seen.add(key)
        if key in lowered_304:
            override = lowered_304[key]
            merged.append({"name": override, "value": headers_304[override],
                           "source": "status_304"})
        else:
            merged.append({"name": name, "value": value, "source": "status_200"})
    for name, value in headers_304.items():
        if name.strip().lower() not in seen:
            merged.append({"name": name, "value": value, "source": "status_304"})
    return merged

def merged_header_dict(synthesized: list[dict[str, str]]) -> dict[str, str]:
    return {i["name"]: i["value"] for i in synthesized}

def content_type_of(headers: dict[str, str]) -> str | None:
    return next((v for n, v in headers.items()
                 if n.strip().lower() == "content-type"), None)

def header_charset(content_type: str | None) -> str | None:
    if not content_type:
        return None
    match = re.search(r"charset\s*=\s*[\"']?\s*([A-Za-z][A-Za-z0-9._-]*)",
                      content_type, re.IGNORECASE)
    return match.group(1) if match else None

def validate_refreshed_decoding(raw: bytes, charset: str | None,
                                fallback_encoding: str) -> tuple[bool, str | None, str]:
    """严格校验 304 有效 charset；与 BOM 冲突或无法解码时拒绝，不做兜底掩盖。"""
    effective = canonical_encoding(charset or fallback_encoding)
    bom = detect_bom(raw)
    if bom is not None and not compatible_encoding(str(bom["encoding"]), effective):
        return False, "E_304_REFRESHED_UNDECODABLE", (
            f"复用实体的 BOM 声明 {bom['encoding']} 与 304 有效 charset {effective} 冲突")
    try:
        raw.decode(effective, errors="strict")
    except (UnicodeError, LookupError, ValueError) as exc:
        return False, "E_304_REFRESHED_UNDECODABLE", (
            f"复用字节无法按 304 有效 charset {effective} 严格解码：{exc}")
    return True, None, effective

def refreshed_output_rel_path(source_304_rel: str) -> str:
    """refreshed_view 的独立输出路径，绝不覆盖 200 旧视图。"""
    return (Path(VIEWS_SUBDIR) / Path(source_304_rel)).as_posix()

def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def _donor_state(source: SourceFile) -> CaptureState | None:
    state, errors = parse_capture_state(source.sidecar)
    return None if (state is None or errors) else state

def _read_donor_bytes(source: SourceFile) -> bytes | None:
    try:
        raw = source.path.read_bytes()
    except OSError:
        return None
    return raw or None  # 完整原始实体必须非空

def _no_match(state_304, same_resource, same_vary, weak_only, etag_mismatch):
    rel_vary = [i.rel_path for i in same_vary]
    if weak_only:
        return Attribution(False, ["E_304_WEAK_VALIDATOR"],
                           ["同资源同 Vary 的候选 200 只带弱验证标记 W/"],
                           candidate_rel_paths=rel_vary, reason="只存在弱验证标记")
    if etag_mismatch:
        return Attribution(False, ["E_304_ETAG_MISMATCH"],
                           [f"304 强 ETag {state_304.etag!r} 与候选 200 不一致"],
                           candidate_rel_paths=rel_vary, reason="强 ETag 不匹配")
    if same_vary and all(_read_donor_bytes(i) is None for i in same_vary):
        return Attribution(False, ["E_304_ORIGINAL_UNREADABLE"],
                           ["匹配的 200 原始实体字节不可读或为空"],
                           candidate_rel_paths=rel_vary, reason="旧正文不可读")
    return Attribution(
        False, ["E_304_NO_CANDIDATE_200"],
        ["找不到同资源键、相同 Vary、同一强 ETag 且捕获时间在前的 200 原件"],
        candidate_rel_paths=[i.rel_path for i in same_resource],
        reason="无满足全部匹配条件的 200")

def attribute_304(source_304: SourceFile, donors: list[SourceFile]) -> Attribution:
    """离线把 304 归属到唯一早先 200：资源键→Vary→强 ETag→时间→可读实体。"""
    state_304, errors = parse_capture_state(source_304.sidecar)
    if state_304 is None:
        return Attribution(False, errors or ["E_304_NOT_STATE_SIDECAR"],
                           ["304 sidecar 不满足离线验证状态合同，无法归属"],
                           reason="状态 sidecar 解析失败")
    if not is_strong_etag(state_304.etag):
        return Attribution(False, ["E_304_WEAK_VALIDATOR"],
                           [f"304 ETag {state_304.etag!r} 不是强验证标记，禁止复用正文"],
                           reason="只存在弱验证标记或缺少 ETag")

    same_resource: list[SourceFile] = []
    same_vary: list[SourceFile] = []
    etag_matched: list[SourceFile] = []
    weak_only = etag_mismatch = False
    for donor in sorted(donors, key=lambda i: i.rel_path):
        donor_state = _donor_state(donor)
        if donor_state is None or donor_state.status != 200:
            continue
        if donor_state.resource_key != state_304.resource_key:
            continue
        same_resource.append(donor)
        if donor_state.request_vary != state_304.request_vary:
            continue
        same_vary.append(donor)
        if not is_strong_etag(donor_state.etag):
            weak_only = True
        elif donor_state.etag != state_304.etag:
            etag_mismatch = True
        elif donor_state.captured_moment < state_304.captured_moment:
            etag_matched.append(donor)
    if not etag_matched:
        return _no_match(state_304, same_resource, same_vary, weak_only, etag_mismatch)

    readable: list[tuple[SourceFile, bytes]] = []
    unreadable: list[SourceFile] = []
    for donor in etag_matched:
        raw = _read_donor_bytes(donor)
        (unreadable if raw is None else readable).append(
            donor if raw is None else (donor, raw))
    if not readable:
        return Attribution(False, ["E_304_ORIGINAL_UNREADABLE"],
                           ["ETag 匹配的 200 原始实体字节不可读或为空"],
                           candidate_rel_paths=[i.rel_path for i in etag_matched],
                           reason="旧正文不可读")

    digests = {hashlib.sha256(raw).hexdigest() for _, raw in readable}
    candidate_paths = sorted(i.rel_path for i, _ in readable)
    if len(digests) > 1:
        detail = ", ".join(f"{i.rel_path}={hashlib.sha256(raw).hexdigest()[:12]}"
                           for i, raw in readable)
        return Attribution(False, ["E_304_ENTITY_CONFLICT"],
                           [f"同一强 ETag 下候选 200 的实体摘要互相矛盾：{detail}"],
                           candidate_rel_paths=candidate_paths,
                           reason="正文摘要/身份互相矛盾")

    # 同一实体的多个捕获：取捕获时间最晚者，平局按相对路径确定
    chosen_donor, chosen_raw = max(
        readable,
        key=lambda pair: (_donor_state(pair[0]).captured_moment, pair[0].rel_path))
    if unreadable:
        candidate_paths = sorted(set(candidate_paths)
                                 | {i.rel_path for i in unreadable})
    chosen_state = _donor_state(chosen_donor)
    assert chosen_state is not None
    return Attribution(
        True, donor=chosen_donor, donor_raw=chosen_raw,
        candidate_rel_paths=candidate_paths,
        reason=(f"归属到 {chosen_donor.rel_path}（资源键 {state_304.resource_key}，"
                f"强 ETag {state_304.etag}，200 捕获于 {chosen_state.captured_at}）"))
