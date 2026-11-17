"""事后人工抽样审计的公共入口。

- ``audit_common``：常量、分层无放回抽样计划与保守上界工具；
- ``audit_labels``：批次/哈希/计划绑定的人工标签校验；
- ``audit_estimate``：文件数口径与输出字节暴露口径的估计。

审计结果只消费已经交付的批次清单，不修改编码裁决、转码文件、台账或自动
交付门槛；人工标签只影响审计输出，不反馈训练。
"""

from __future__ import annotations

from typing import Any

from .audit_common import (
    DEFAULT_CONFIDENCE,
    DEFAULT_THRESHOLDS,
    ESTIMATE_SCHEMA,
    LABEL_SCHEMA,
    PLAN_SCHEMA,
    TAG_LABELS,
    AuditError,
    build_audit_plan,
    digest,
)
from .audit_estimate import estimate_delivery_audit
from .audit_labels import apply_labels, make_label, validate_label

__all__ = [
    "AuditError",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_THRESHOLDS",
    "ESTIMATE_SCHEMA",
    "LABEL_SCHEMA",
    "PLAN_SCHEMA",
    "TAG_LABELS",
    "apply_labels",
    "build_audit_plan",
    "digest",
    "estimate_delivery_audit",
    "make_label",
    "validate_label",
]


def run_audit(
    frame: dict[str, Any],
    *,
    budget: int,
    seed: int | str = 0,
    labels: list[dict[str, Any]] | None = None,
    output_root: Any = None,
    thresholds: dict[str, float] | None = None,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """一步完成抽样并估计；``labels`` 为空时全部按未回应处理。"""
    plan = build_audit_plan(frame, budget=budget, seed=seed)
    estimate = estimate_delivery_audit(
        plan,
        frame,
        list(labels or []),
        output_root=output_root,
        thresholds=thresholds,
        confidence=confidence,
    )
    return {"frame": frame, "plan": plan, "estimate": estimate}
