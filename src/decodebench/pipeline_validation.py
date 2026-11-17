"""304 验证事件的双合同视图构建（流水线侧编排）。

归属/头部/解码规则在 validation；本模块把规则接到证据、裁决、转码与
manifest/台账事件结构上。
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import Config
from .evidence import collect_refreshed_evidence
from .models import SourceFile
from .resolver import resolve
from .scorer import analyze_candidates
from .transcoder import transcode_view
from .validation import (
    CaptureState, attribute_304, content_type_of, digest_bytes, header_charset,
    merged_header_dict, parse_capture_state, refreshed_output_rel_path,
    synthesize_headers, validate_refreshed_decoding,
)

def _virtual_donor_source(donor: SourceFile, view_rel_path: str) -> SourceFile:
    """构造 refreshed 视图的虚拟源（路径指向视图输出位）。"""
    return replace(donor, rel_path=view_rel_path, sidecar={}, sidecar_path=None,
                   sidecar_rel=None, sidecar_error=None, sidecar_sha256=None)

def base_event(source_304: SourceFile, state: CaptureState | None) -> dict[str, Any]:
    return {
        "rel_path_304": source_304.rel_path, "status": "unattributed",
        "resource_key": state.resource_key if state else None,
        "etag_304": state.etag if state else source_304.sidecar.get("etag"),
        "request_vary": dict(state.request_vary) if state else {},
        "captured_at_304": state.captured_at if state else None,
        "donor_rel_path": None, "donor_captured_at": None, "entity_sha256": None,
        "sidecar_200_sha256": None,
        "sidecar_304_sha256": source_304.sidecar_sha256,
        "header_edition": None, "synthesized_headers": [], "error_codes": [],
        "reason": "", "candidate_rel_paths": [], "views": []}

def _forensic_view(donor: SourceFile, donor_state: CaptureState,
                   donor_entry: dict[str, Any], entity_sha: str) -> dict[str, Any]:
    """forensic_original：304 只记为验证事件，展示 200 原始裁决与旧视图。"""
    transcode = donor_entry["transcode"]
    return {
        "contract": "forensic_original",
        "view_rel_path": transcode.get("output_rel_path"),
        "success": bool(transcode.get("success")),
        "published": bool(transcode.get("success")),
        "encoding": donor_entry["decision"]["encoding"],
        "method": donor_entry["decision"]["method"],
        "entity_sha256": entity_sha,
        "output_sha256": transcode.get("output_sha256"),
        "header_basis": "status_200_original",
        "evidence_source_rel_path": donor.rel_path,
        "note": f"304 仅记录为一次验证；沿用 200 原始头部与裁决，实体来自 {donor.rel_path}",
        "donor_captured_at": donor_state.captured_at}

def _refreshed_view(source_304: SourceFile, donor: SourceFile, donor_raw: bytes,
                    synthesized: list[dict[str, str]], config: Config,
                    entity_sha: str) -> dict[str, Any]:
    """refreshed_view：同一原始字节，按 304 合成后的有效头部重新裁决。"""
    view_rel_path = refreshed_output_rel_path(source_304.rel_path)
    headers = merged_header_dict(synthesized)
    content_type = content_type_of(headers)
    view: dict[str, Any] = {
        "contract": "refreshed_view", "view_rel_path": view_rel_path,
        "success": False, "published": False, "encoding": None, "method": None,
        "entity_sha256": entity_sha, "output_sha256": None,
        "header_basis": "synthesized_304",
        "declared_charset": header_charset(content_type),
        "rejection": None, "note": "",
    }
    # 合同硬门槛：有效 charset 必须严格解码复用字节且不与 BOM 冲突
    ok, reject_code, detail = validate_refreshed_decoding(
        donor_raw, view["declared_charset"], config.fallback_encoding)
    if not ok:
        view["rejection"] = {"code": reject_code, "message": detail,
                             "content_type": content_type}
        view["note"] = "头部与复用字节矛盾，保留两边证据并拒绝自动发布"
        return view
    evidence = collect_refreshed_evidence(donor_raw, headers, config.fallback_encoding)
    candidates = analyze_candidates(donor_raw, config.candidate_encodings)
    decision, evidence, _ = resolve(
        donor_raw, _virtual_donor_source(donor, view_rel_path),
        evidence, candidates, config)
    output = transcode_view(
        view_rel_path, donor_raw, entity_sha, decision.encoding, config,
        rewrite_suffix=Path(source_304.rel_path).suffix)
    view.update({
        "success": output.success, "published": output.success,
        "encoding": output.encoding, "method": decision.method,
        "output_sha256": output.output_sha256, "decision": decision.to_dict(),
        "evidence": [i.to_dict() for i in evidence], "transcode": output.to_dict()})
    if not output.success:
        view["rejection"] = {"code": "E_304_REFRESHED_UNDECODABLE",
                             "message": output.error or "刷新视图转码失败",
                             "content_type": content_type}
        view["note"] = "刷新视图转码失败，拒绝自动发布"
    else:
        view["note"] = "复用同一原始实体，按 304 有效头部重新裁决并生成独立视图"
    return view

def _mark_unattributed(event: dict[str, Any], attribution) -> dict[str, Any]:
    event["status"] = "unattributed"
    event["error_codes"] = list(attribution.error_codes)
    if all(code.startswith("E_304_") for code in event["error_codes"]):
        event["error_codes"].append("W_304_ATTRIBUTION_REVIEW")
    event["reason"] = attribution.reason
    event["messages"] = list(attribution.messages)
    return event

def process_validation_event(source_304: SourceFile, sources: list[SourceFile],
                             donor_entries: dict[str, dict[str, Any]],
                             config: Config) -> dict[str, Any]:
    """完全离线处理一个 304 验证响应；归属失败只保留证据、不产文本。"""
    state, state_errors = parse_capture_state(source_304.sidecar)
    event = base_event(source_304, state)
    if state is None:
        event["error_codes"] = state_errors or ["E_304_NOT_STATE_SIDECAR"]
        event["reason"] = "304 sidecar 不满足离线验证状态合同，待人工复核"
        return event
    attribution = attribute_304(
        source_304, [i for i in sources if i is not source_304])
    event["candidate_rel_paths"] = list(attribution.candidate_rel_paths)
    if not attribution.attributed or attribution.donor is None:
        return _mark_unattributed(event, attribution)
    donor, donor_raw = attribution.donor, attribution.donor_raw
    donor_state, donor_errors = parse_capture_state(donor.sidecar)
    if donor_state is None:
        event["error_codes"] = donor_errors or ["E_304_MALFORMED_STATE"]
        event["reason"] = "被归属 200 的状态 sidecar 无法解析"
        return event
    entity_sha = digest_bytes(donor_raw)
    event.update({
        "status": "attributed", "donor_rel_path": donor.rel_path,
        "donor_captured_at": donor_state.captured_at, "entity_sha256": entity_sha,
        "sidecar_200_sha256": donor.sidecar_sha256,
        "header_edition": "200-original+304-override",
        "synthesized_headers": synthesize_headers(donor_state.headers, state.headers),
        "reason": attribution.reason,
        "error_codes": ["W_304_FORENSIC_VALIDATION"]})
    donor_entry = donor_entries.get(donor.rel_path)
    if donor_entry is None:
        event["status"] = "unattributed"
        event["error_codes"] = ["E_304_ORIGINAL_UNREADABLE"]
        event["reason"] = "被归属 200 未产生可用的原始视图"
        return event
    refreshed = _refreshed_view(
        source_304, donor, donor_raw, event["synthesized_headers"], config, entity_sha)
    if refreshed["rejection"] is not None:
        event["error_codes"].append(str(refreshed["rejection"]["code"]))
    event["views"] = [_forensic_view(donor, donor_state, donor_entry, entity_sha),
                      refreshed]
    return event
