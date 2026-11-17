"""构建字段顺序稳定的证据清单。"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .config import Config
from .detectors import detect_bom
from .models import (
    CandidateResult,
    Decision,
    Evidence,
    MojibakeReport,
    SourceFile,
    TranscodeResult,
    WarningItem,
)
from .util import write_json

RISK_LEVELS = ("none", "low", "medium", "high")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
AUDIT_FRAME_SCHEMA = "audit-frame/1.0"


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
    mojibake: MojibakeReport,
    warnings: list[WarningItem],
) -> dict[str, Any]:
    bom = detect_bom(raw)
    warning_rows = _warning_rows(warnings)
    return {
        "rel_path": source.rel_path,
        "source_size": source.size,
        "source_sha256": source.sha256,
        "source_mtime": source.mtime,
        "sidecar": {
            "path": source.sidecar_rel,
            "present": source.sidecar_path is not None,
            "error": source.sidecar_error,
        },
        "bom": bom,
        "evidence": [item.to_dict() for item in evidence],
        "statistical_candidates": [item.to_dict() for item in candidates],
        "decision": decision.to_dict(),
        "transcode": transcode.to_dict(),
        "mojibake": mojibake.to_dict(),
        "warnings": warning_rows,
        "warning_count": len(warning_rows),
    }


def summarize(files: list[dict[str, Any]]) -> dict[str, Any]:
    warning_counter: Counter[str] = Counter()
    warning_severity: dict[str, str] = {}
    methods: Counter[str] = Counter()
    risks: Counter[str] = Counter()
    conflicts = 0
    transcoded = 0
    failed = 0
    with_warnings = 0
    for item in files:
        decision = item["decision"]
        if decision["conflicts"]:
            conflicts += 1
        if item["transcode"]["success"]:
            transcoded += 1
        else:
            failed += 1
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


def _canonical_json(data: Any) -> str:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _frame_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def build_audit_frame(manifest: dict[str, Any]) -> dict[str, Any]:
    """冻结某批次的交付文件抽样框；调用方不得改写编码裁决或交付门槛。

    抽样单位是 ``rel_path`` 对应的交付文件。只有已成功写出 UTF-8 输出的文件
    才进入抽样框：转码失败的文件没有可复核的交付字节，不能冒充交付文件，
    也不能被静默当作 correct。未交付文件单独记录在 ``excluded`` 中，
    其输出字节数不进入字节暴露分母。
    """
    from .ledger import batch_identity_from_manifest

    batch_key, batch_id = batch_identity_from_manifest(manifest)
    included: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for item in manifest["files"]:
        transcode = item["transcode"]
        output_rel_path = transcode["output_rel_path"]
        if not transcode["success"] or not output_rel_path:
            excluded.append(
                {
                    "rel_path": item["rel_path"],
                    "reason": "no_delivered_output",
                    "error": transcode.get("error"),
                }
            )
            continue
        included.append(
            {
                "rel_path": item["rel_path"],
                "source_sha256": item["source_sha256"],
                "output_sha256": transcode["output_sha256"],
                "output_bytes": int(transcode["bytes_written"]),
                "output_rel_path": output_rel_path,
                "risk_level": item["mojibake"]["level"],
            }
        )
    included.sort(key=lambda row: str(row["rel_path"]))
    excluded.sort(key=lambda row: str(row["rel_path"]))
    risk_counts = Counter(str(row["risk_level"]) for row in included)
    strata = [
        {"risk_level": level, "population": int(risk_counts.get(level, 0))}
        for level in RISK_LEVELS
        if risk_counts.get(level, 0) > 0
    ]
    body: dict[str, Any] = {
        "schema_version": AUDIT_FRAME_SCHEMA,
        "project": "decodebench",
        "kind": "postdelivery_audit_frame",
        "batch_id": batch_id,
        "batch_key": batch_key,
        "rule_version": manifest["rule_version"],
        "config_fingerprint": manifest["config_fingerprint"],
        "scan_root": manifest["scan_root"],
        "manifest_generated_at": manifest["generated_at"],
        "unit": "delivered_file_per_rel_path",
        "strata_by": "risk_level",
        "ordered_risk_levels": list(RISK_LEVELS),
        "delivered_files": included,
        "excluded_files": excluded,
        "population": {
            "delivered_files": len(included),
            "delivered_output_bytes": sum(row["output_bytes"] for row in included),
            "excluded_files": len(excluded),
            "strata": strata,
        },
    }
    body["frame_digest"] = _frame_digest(body)
    return body
