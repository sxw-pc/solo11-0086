"""人工标签的构造与严格校验。

标签必须绑定批次、抽样框摘要、抽样计划摘要、源 SHA 与输出 SHA。
重复、换版或未入样标签一律抛错，绝不静默改写本轮统计。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .audit_common import LABEL_SCHEMA, TAG_LABELS, AuditError, digest


def verify_plan(plan: dict[str, Any]) -> None:
    """拒绝被事后改动入样概率或样本的抽样计划。"""
    body = {key: value for key, value in plan.items() if key != "plan_digest"}
    if digest(body) != plan.get("plan_digest"):
        raise AuditError("抽样计划摘要与内容不一致，拒绝事后缩小入样概率")


def unit_index(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(unit["rel_path"]): unit for unit in plan["units"]}


def make_label(
    plan: dict[str, Any],
    rel_path: str,
    verdict: str,
    *,
    reviewer: str = "",
    note: str = "",
) -> dict[str, Any]:
    """为已入样文件生成绑定到批次/哈希/计划的人工标签。"""
    verify_plan(plan)
    if verdict not in TAG_LABELS:
        raise AuditError(f"未知标签: {verdict}")
    unit = unit_index(plan).get(rel_path)
    if unit is None:
        raise AuditError(f"文件不在抽样框内: {rel_path}")
    if not unit["sampled"] or float(unit["inclusion_probability"]) <= 0:
        raise AuditError(f"文件未入样，不能提交标签: {rel_path}")
    return {
        "schema_version": LABEL_SCHEMA,
        "batch_id": plan["batch_id"],
        "batch_key": plan["batch_key"],
        "frame_digest": plan["frame_digest"],
        "plan_digest": plan["plan_digest"],
        "rel_path": rel_path,
        "source_sha256": unit["source_sha256"],
        "output_sha256": unit["output_sha256"],
        "verdict": verdict,
        "reviewer": reviewer,
        "note": note,
    }


def validate_label(plan: dict[str, Any], label: dict[str, Any]) -> dict[str, Any]:
    verify_plan(plan)
    required = (
        "batch_id",
        "frame_digest",
        "plan_digest",
        "rel_path",
        "source_sha256",
        "output_sha256",
        "verdict",
    )
    missing = [key for key in required if key not in label]
    if missing:
        raise AuditError(f"标签缺少字段: {missing}")
    if str(label["verdict"]) not in TAG_LABELS:
        raise AuditError(f"未知标签: {label['verdict']}")
    if str(label["batch_id"]) != str(plan["batch_id"]):
        raise AuditError("标签批次与抽样计划不一致")
    if "batch_key" in label and str(label["batch_key"]) != str(plan["batch_key"]):
        raise AuditError("标签批次键与抽样计划不一致")
    if str(label["frame_digest"]) != str(plan["frame_digest"]):
        raise AuditError("标签抽样框摘要与抽样计划不一致")
    if str(label["plan_digest"]) != str(plan["plan_digest"]):
        raise AuditError("标签绑定的是另一版抽样计划")
    unit = unit_index(plan).get(str(label["rel_path"]))
    if unit is None:
        raise AuditError(f"标签文件不在抽样框内: {label['rel_path']}")
    if not unit["sampled"]:
        raise AuditError(f"标签文件未入样: {label['rel_path']}")
    if str(label["source_sha256"]) != str(unit["source_sha256"]):
        raise AuditError(f"标签源 SHA 与抽样计划不一致: {label['rel_path']}")
    if str(label["output_sha256"]) != str(unit["output_sha256"]):
        raise AuditError(f"标签输出 SHA 与抽样计划不一致: {label['rel_path']}")
    return dict(label)


def _output_hash(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apply_labels(
    plan: dict[str, Any],
    labels: list[dict[str, Any]],
    *,
    output_root: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """校验并归并标签；重复、换版、未入样标签直接拒绝，绝不静默改写。"""
    seen: dict[str, dict[str, Any]] = {}
    for label in labels:
        checked = validate_label(plan, label)
        rel_path = str(checked["rel_path"])
        if rel_path in seen:
            raise AuditError(f"同一文件重复提交标签: {rel_path}")
        seen[rel_path] = checked
    statuses: dict[str, dict[str, Any]] = {}
    for unit in plan["units"]:
        if not unit["sampled"]:
            continue
        rel_path = str(unit["rel_path"])
        label = seen.get(rel_path)
        status: dict[str, Any] = {
            "rel_path": rel_path,
            "risk_level": unit["risk_level"],
            "output_bytes": int(unit["output_bytes"]),
            "inclusion_probability": float(unit["inclusion_probability"]),
            "stratum_population": int(unit["stratum_population"]),
            "stratum_sample_size": int(unit["stratum_sample_size"]),
            "verdict": None if label is None else str(label["verdict"]),
            "status": "no_response" if label is None else str(label["verdict"]),
            "reason": "未收到人工标签" if label is None else "",
        }
        if output_root is not None:
            actual = _output_hash(Path(output_root) / str(unit["output_rel_path"]))
            if actual is None:
                status["status"] = "output_missing"
                status["reason"] = "交付输出文件缺失，无法复核该文件"
            elif actual != str(unit["output_sha256"]):
                raise AuditError(f"交付输出已换版: {rel_path}")
        statuses[rel_path] = status
    return statuses
