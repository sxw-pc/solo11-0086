"""构建字段顺序稳定的证据清单。"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .config import Config
from .detectors import detect_bom
from .models import (
    CandidateResult,
    Decision,
    DecompressResult,
    Evidence,
    MojibakeReport,
    SourceFile,
    TranscodeResult,
    WarningItem,
)
from .util import write_json

RISK_LEVELS = ("none", "low", "medium", "high")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _warning_rows(warnings: list[WarningItem]) -> list[dict[str, Any]]:
    rows = [item.to_dict() for item in warnings]
    rows.sort(
        key=lambda item: (
            str(item["code"]),
            item["line"] if item["line"] is not None else -1,
            item["offset"] if item["offset"] is not None else -1,
            str(item["message"]),
        )
    )
    return rows


def build_file_entry(
    source: SourceFile,
    raw: bytes,
    evidence: list[Evidence],
    candidates: list[CandidateResult],
    decision: Decision,
    transcode: TranscodeResult,
    mojibake: MojibakeReport | None,
    warnings: list[WarningItem],
    *,
    decompress: DecompressResult | None = None,
    body: bytes | None = None,
) -> dict[str, Any]:
    inspected = body if body is not None else raw
    reviewed = decompress is not None and decompress.status != "none"
    # 解封装失败且未发布正文时，gzip 实体本身不是可用于 BOM 的证据。
    bom = detect_bom(inspected) if (not reviewed or body is not None) else None
    warning_rows = _warning_rows(warnings)
    content = decompress.to_dict() if decompress is not None else None
    if decompress is None or decompress.status == "none":
        body_sha: str | None = source.sha256
    else:
        body_sha = decompress.decoded_sha256
    return {
        "rel_path": source.rel_path,
        "source_size": source.size,
        "source_sha256": source.sha256,
        "source_mtime": source.mtime,
        "sidecar": {
            "path": source.sidecar_rel,
            "present": source.sidecar_path is not None,
            "error": source.sidecar_error,
            "sha256": source.sidecar_sha256,
            "content_encoding": source.content_encoding_raw,
            "content_encoding_error": source.content_encoding_error,
        },
        "bom": bom,
        "content_encoding": content,
        "entity_sha256": source.sha256,
        "decoded_sha256": body_sha,
        "evidence": [item.to_dict() for item in evidence],
        "statistical_candidates": [item.to_dict() for item in candidates],
        "decision": decision.to_dict(),
        "transcode": transcode.to_dict(),
        "mojibake": (
            mojibake.to_dict()
            if mojibake is not None
            else {
                "level": "none",
                "findings": [],
                "recommendation": "未对正文做乱码诊断：解封装未通过验收，没有发布正文。",
            }
        ),
        "warnings": warning_rows,
        "warning_count": len(warning_rows),
    }


def summarize(files: list[dict[str, Any]]) -> dict[str, Any]:
    warning_counter: Counter[str] = Counter()
    warning_severity: dict[str, str] = {}
    methods: Counter[str] = Counter()
    risks: Counter[str] = Counter()
    content_states: Counter[str] = Counter()
    conflicts = 0
    transcoded = 0
    failed = 0
    partial = 0
    with_warnings = 0
    for item in files:
        decision = item["decision"]
        if decision["conflicts"]:
            conflicts += 1
        if item["transcode"]["success"]:
            transcoded += 1
        else:
            failed += 1
        if item["transcode"].get("partial"):
            partial += 1
        content = item.get("content_encoding") or {}
        content_states[str(content.get("status", "none"))] += 1
        methods[str(decision["method"])] += 1
        risks[str(item["mojibake"]["level"])] += 1
        if item["warnings"]:
            with_warnings += 1
        for warning in item["warnings"]:
            code = str(warning["code"])
            warning_counter[code] += 1
            old = warning_severity.get(code, "")
            if SEVERITY_RANK.get(str(warning["severity"]), 0) > SEVERITY_RANK.get(old, 0):
                warning_severity[code] = str(warning["severity"])
    distribution = [
        {"code": code, "count": warning_counter[code], "severity": warning_severity[code]}
        for code in sorted(warning_counter)
    ]
    return {
        "files_total": len(files),
        "conflict_files": conflicts,
        "transcode_success": transcoded,
        "transcode_failed": failed,
        "transcode_partial": partial,
        "content_encoding_states": [
            {"status": status, "count": content_states[status]}
            for status in sorted(content_states)
        ],
        "files_with_warnings": with_warnings,
        "warnings_total": sum(warning_counter.values()),
        "warning_distribution": distribution,
        "method_distribution": [
            {"method": method, "count": methods[method]} for method in sorted(methods)
        ],
        "risk_distribution": [
            {"level": level, "count": risks.get(level, 0)} for level in RISK_LEVELS
        ],
    }


def build_manifest(
    config: Config,
    now: str,
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(files, key=lambda item: str(item["rel_path"]))
    return {
        "schema_version": "1.0",
        "project": "decodebench",
        "rule_version": RULE_VERSION,
        "generated_at": now,
        "config_fingerprint": config.fingerprint,
        "scan_root": config.scan_root.as_posix(),
        "config_snapshot": config.raw,
        "summary": summarize(ordered),
        "files": ordered,
    }


def write_manifest(config: Config, manifest: dict[str, Any]) -> Path:
    write_json(config.manifest_path, manifest)
    return config.manifest_path
