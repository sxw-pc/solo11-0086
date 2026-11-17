"""事后审计的双口径估计。

- 文件数口径：每个文件权重 ``1 / 入样概率``；
- 字节暴露口径：每个文件权重 ``output_bytes / 入样概率``，衡量错误文件中的
  UTF-8 输出字节暴露，而不是精确的错误字节数。

非有效回应（undecidable、未回应、输出缺失）不当作 correct，也不进入点估计，
而是作为可能错误的单位计入保守上界。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit_common import (
    AUDIT_FRAME_SCHEMA,
    DEFAULT_CONFIDENCE,
    DEFAULT_THRESHOLDS,
    ESTIMATE_SCHEMA,
    AuditError,
    stratum_bound,
    verify_frame,
)
from .audit_labels import apply_labels

COUNT_KEYS = ("wrong", "correct", "undecidable", "no_response", "output_missing")


def _ratio(numerator: float | None, denominator: float) -> float | None:
    if numerator is None or denominator <= 0:
        return None
    return numerator / denominator


def _threshold_verdict(
    lower: float | None, upper: float | None, threshold: float, estimable: bool
) -> str:
    if not estimable or lower is None or upper is None:
        return "insufficient"
    if lower > threshold:
        return "exceeds"
    if upper <= threshold:
        return "within"
    return "insufficient"


def _strata_rows(
    plan: dict[str, Any],
    delivered: list[dict[str, Any]],
    statuses: dict[str, dict[str, Any]],
    alpha: float,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    totals = {key: 0 for key in COUNT_KEYS}
    rows: list[dict[str, Any]] = []
    for stratum in plan["strata"]:
        level = str(stratum["risk_level"])
        members = [row for row in statuses.values() if row["risk_level"] == level]
        for row in members:
            if row["status"] in totals:
                totals[row["status"]] += 1
        bound = stratum_bound(
            int(stratum["population"]),
            int(stratum["sample_size"]),
            members,
            delivered,
            level,
            alpha,
        )
        rows.append(
            {
                "risk_level": level,
                "population": int(stratum["population"]),
                "inclusion_probability": float(stratum["inclusion_probability"]),
                **bound,
            }
        )
    return rows, totals


def estimate_delivery_audit(
    plan: dict[str, Any],
    frame: dict[str, Any],
    labels: list[dict[str, Any]],
    *,
    output_root: Path | None = None,
    thresholds: dict[str, float] | None = None,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    if frame.get("schema_version") != AUDIT_FRAME_SCHEMA:
        raise AuditError("抽样框 schema 不受支持")
    verify_frame(frame)
    if str(plan["frame_digest"]) != str(frame["frame_digest"]):
        raise AuditError("抽样计划绑定的框摘要与当前批次不一致")
    statuses = apply_labels(plan, labels, output_root=output_root)
    delivered = list(frame["delivered_files"])
    total_files = len(delivered)
    total_bytes = sum(int(row["output_bytes"]) for row in delivered)
    estimable = bool(plan["estimable"])
    alpha = (1.0 - confidence) / max(1, len(plan["strata"]))
    limits = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        limits.update({key: float(value) for key, value in thresholds.items()})

    strata_rows, totals = _strata_rows(plan, delivered, statuses, alpha)
    estimate_files = 0.0
    estimate_bytes = 0.0
    for stratum, row in zip(plan["strata"], strata_rows):
        probability = float(stratum["inclusion_probability"])
        if probability <= 0:
            continue
        estimate_files += row["observed_wrong"] / probability
        estimate_bytes += row["confirmed_wrong_bytes"] / probability
    complete_response = all(row["non_informative"] == 0 for row in strata_rows)
    census = (
        estimable
        and complete_response
        and all(int(s["sample_size"]) == int(s["population"]) for s in plan["strata"])
    )
    confirmed_wrong_files = totals["wrong"]
    confirmed_bytes = sum(row["confirmed_wrong_bytes"] for row in strata_rows)
    if census:
        upper_files: float | None = float(confirmed_wrong_files)
        upper_bytes: float | None = float(confirmed_bytes)
        interval = "census_no_sampling_variance"
    elif estimable:
        upper_files = min(
            float(sum(row["upper_wrong_files_95"] for row in strata_rows)), float(total_files)
        )
        upper_bytes = min(
            float(sum(row["upper_exposed_bytes_95"] for row in strata_rows)), float(total_bytes)
        )
        interval = "design_based_95_bonferroni"
    else:
        upper_files = None
        upper_bytes = None
        interval = "not_estimable"
    lower_files: float | None = float(confirmed_wrong_files) if estimable else None
    lower_bytes: float | None = float(confirmed_bytes) if estimable else None
    file_lower_ratio = _ratio(lower_files, total_files)
    file_upper_ratio = _ratio(upper_files, total_files)
    byte_lower_ratio = _ratio(lower_bytes, total_bytes)
    byte_upper_ratio = _ratio(upper_bytes, total_bytes)
    return {
        "schema_version": ESTIMATE_SCHEMA,
        "kind": "postdelivery_audit_estimate",
        "batch_id": frame["batch_id"],
        "batch_key": frame["batch_key"],
        "frame_digest": frame["frame_digest"],
        "plan_digest": plan["plan_digest"],
        "estimable": estimable,
        "not_estimable_reason": plan["blocking_reason"],
        "estimate_type": "census"
        if census
        else ("design_weighted_estimate" if estimable else None),
        "point_estimate_scope": "confirmed_labels_only_no_nonresponse_as_correct",
        "complete_response": complete_response,
        "weights": {
            "file": "1 / inclusion_probability",
            "bytes": "output_bytes / inclusion_probability",
            "byte_metric": "exposure_of_utf8_output_bytes_in_wrong_files_not_exact_error_bytes",
        },
        "total_output_bytes": total_bytes,
        "unit_counts": {
            "delivered_files": total_files,
            "delivered_output_bytes": total_bytes,
            "sampled_files": len(statuses),
            "responded_files": totals["wrong"] + totals["correct"],
            "wrong_files_observed": totals["wrong"],
            "correct_files_observed": totals["correct"],
            "undecidable_files": totals["undecidable"],
            "no_response_files": totals["no_response"],
            "missing_output_files": totals["output_missing"],
            "unreviewed_files_never_counted_correct": True,
        },
        "file_lens": {
            "wrong_files_estimate": estimate_files if estimable else None,
            "wrong_file_ratio_estimate": _ratio(estimate_files, total_files)
            if estimable
            else None,
            "lower_bound": lower_files,
            "upper_bound_95": upper_files,
            "lower_ratio": file_lower_ratio,
            "upper_ratio_95": file_upper_ratio,
            "denominator_files": total_files,
            "lower_bound_basis": "confirmed_wrong_files_in_sample",
            "interval": interval,
        },
        "byte_lens": {
            "exposed_wrong_output_bytes_estimate": estimate_bytes if estimable else None,
            "exposed_wrong_output_byte_ratio_estimate": _ratio(estimate_bytes, total_bytes)
            if estimable
            else None,
            "lower_bound": lower_bytes,
            "upper_bound_95": upper_bytes,
            "lower_ratio": byte_lower_ratio,
            "upper_ratio_95": byte_upper_ratio,
            "denominator_output_bytes": total_bytes,
            "lower_bound_basis": "confirmed_wrong_file_output_bytes",
            "interval": interval,
            "not_exact_error_bytes": True,
        },
        "joint_confidence": confidence,
        "confidence_allocation": "bonferroni_equal_split_across_nonempty_strata",
        "per_stratum_alpha": alpha,
        "strata": strata_rows,
        "label_status": sorted(statuses.values(), key=lambda row: str(row["rel_path"])),
        "thresholds": {
            "file_ratio": limits["files"],
            "byte_ratio": limits["bytes"],
            "file_verdict": _threshold_verdict(
                file_lower_ratio, file_upper_ratio, limits["files"], estimable
            ),
            "byte_verdict": _threshold_verdict(
                byte_lower_ratio, byte_upper_ratio, limits["bytes"], estimable
            ),
        },
        "notes": [
            "未回应、undecidable 或输出缺失的文件不计为 correct；也不进入 respondent-only 点估计。",
            "字节暴露上界在每层错误文件数上界内按输出字节数从大到小分配，不能用文件数界乘平均文件大小。",
            "标签只影响审计输出，不反馈训练，也不修改自动交付门槛。",
        ],
    }
