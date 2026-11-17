"""构建字段顺序稳定的证据清单。"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .assembly import entity_record
from .config import Config
from .detectors import detect_bom
from .models import (
    Decision,
    EntityResult,
    Evidence,
    LoadedFragment,
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
    candidates: list[Any],
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


def build_assembly_entry(result: EntityResult) -> dict[str, Any]:
    record = entity_record(result)
    record["decision"] = None
    record["transcode"] = None
    record["mojibake"] = None
    record["warnings"] = []
    record["warning_count"] = 0
    return record


def build_entity_entry(
    result: EntityResult, file_entry: dict[str, Any]
) -> dict[str, Any]:
    record = entity_record(result)
    record["rel_path"] = file_entry["rel_path"]
    record["source_size"] = file_entry["source_size"]
    record["source_sha256"] = file_entry["source_sha256"]
    record["source_mtime"] = file_entry["source_mtime"]
    record["sidecar"] = file_entry["sidecar"]
    record["bom"] = file_entry["bom"]
    record["evidence"] = file_entry["evidence"]
    record["statistical_candidates"] = file_entry["statistical_candidates"]
    record["decision"] = file_entry["decision"]
    record["transcode"] = file_entry["transcode"]
    record["mojibake"] = file_entry["mojibake"]
    record["warnings"] = file_entry["warnings"]
    record["warning_count"] = file_entry["warning_count"]
    return record


def build_fragment_entry(
    result: EntityResult, fragment: LoadedFragment, consumed: bool
) -> dict[str, Any]:
    return {
        "entity_id": result.entity_id,
        "capture_id": fragment.decl.capture_id,
        "rel_path": fragment.rel_path,
        "sidecar_path": fragment.source.sidecar_rel,
        "source_size": fragment.source.size,
        "source_sha256": fragment.source.sha256,
        "source_mtime": fragment.source.mtime,
        "byte_start": fragment.decl.byte_start,
        "byte_end_inclusive": fragment.decl.byte_end_inclusive,
        "entity_size": fragment.decl.entity_size,
        "validator": fragment.decl.validator,
        "sha256": fragment.sha256,
        "status": fragment.status,
        "reasons": list(fragment.reasons),
        "consumed": consumed,
        "entity_status": result.status,
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


def _entity_summary(assembly: dict[str, Any]) -> dict[str, Any]:
    entities = assembly["entities"]
    complete = [item for item in entities if item["complete"]]
    transcoded = [
        item
        for item in complete
        if item.get("transcode") and item["transcode"]["success"]
    ]
    return {
        "contract": assembly["contract"],
        "entities_total": len(entities),
        "entities_complete": len(complete),
        "entities_ambiguous": sum(1 for item in entities if item["status"] == "ambiguous"),
        "entities_incomplete": sum(
            1
            for item in entities
            if item["status"] not in {"complete", "ambiguous"}
        ),
        "entities_transcoded": len(transcoded),
        "entities_assembled_size": {
            item["entity_id"]: item["entity_size"]
            for item in complete
            if item.get("selected")
        },
        "entities_utf8_output_sha256": {
            item["entity_id"]: item["transcode"]["output_sha256"] for item in transcoded
        },
        "fragments_declared": len(assembly["fragments"]),
        "fragments_consumed": sum(1 for item in assembly["fragments"] if item["consumed"]),
        "declaration_issues": len(assembly["declaration_issues"]),
    }


def build_manifest(
    config: Config,
    now: str,
    files: list[dict[str, Any]],
    assembly: dict[str, Any],
) -> dict[str, Any]:
    ordered = sorted(files, key=lambda item: str(item["rel_path"]))
    ordered_entities = sorted(assembly["entities"], key=lambda item: str(item["entity_id"]))
    ordered_fragments = sorted(
        assembly["fragments"],
        key=lambda item: (str(item["entity_id"]), str(item["capture_id"]), item["byte_start"], str(item["rel_path"])),
    )
    assembly_block = {
        "contract": assembly["contract"],
        "priority_capture_ids": list(assembly["priority_capture_ids"]),
        "max_combinations_per_entity": assembly["max_combinations_per_entity"],
        "summary": _entity_summary(
            {
                **assembly,
                "entities": ordered_entities,
                "fragments": ordered_fragments,
            }
        ),
        "declaration_issues": sorted(
            assembly["declaration_issues"], key=lambda item: str(item["rel_path"])
        ),
        "entities": ordered_entities,
        "fragments": ordered_fragments,
    }
    return {
        "schema_version": "1.1",
        "project": "decodebench",
        "rule_version": RULE_VERSION,
        "generated_at": now,
        "config_fingerprint": config.fingerprint,
        "scan_root": config.scan_root.as_posix(),
        "config_snapshot": config.raw,
        "summary": summarize(ordered),
        "assembly": assembly_block,
        "files": ordered,
    }


def write_manifest(config: Config, manifest: dict[str, Any]) -> Path:
    write_json(config.manifest_path, manifest)
    return config.manifest_path
