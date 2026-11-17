"""校准门槛在新本地响应上的应用与交付记录。

应用层只消费离线校准工件（``calibration.CalibrationResult``），不重新估计
任何统计量。对每个文件保留原始 resolver 的 encoding 决策与全部诊断证据，
另外给出自动交付/拒判结论、文本等价类与风险预算证据。拒判时不写 UTF-8
产物、不覆盖任何既有文件，也不会伪装成转码成功。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import ERROR_CODES
from .calibration import (
    ATTRIBUTION_UNRESOLVED,
    REJECT_BINDING_MISMATCH,
    REJECT_NO_PROMOTED_RULE,
    CalibrationResult,
    GateDecision,
    RiskGate,
    load_calibration,
)
from .config import Config
from .models import Decision, SourceFile, WarningItem


@dataclass(frozen=True)
class DeliveryVerdict:
    gate: GateDecision
    auto_deliver: bool
    warning: WarningItem | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.gate.contract,
            "auto_deliver": self.auto_deliver,
            "encoding_decision": self.gate.encoding,
            "confidence": self.gate.confidence,
            "rule_id": self.gate.rule_id,
            "text_equivalence_class": self.gate.text_equivalence_class,
            "label_certain": self.gate.label_certain,
            "encoding_attribution_resolved": self.gate.encoding_attribution_resolved,
            "reject_reasons": list(self.gate.reject_reasons),
            "risk_budget": self.gate.risk_budget,
            "validated_error_rate_upper_bound": self.gate.validated_upper_bound,
            "annotation_digest": self.gate.annotation_digest,
            "rule_version": self.gate.rule_version,
        }


def build_gate(
    artifact_path: str,
    contract: str,
    config: Config,
) -> RiskGate:
    result: CalibrationResult = load_calibration(artifact_path)
    return RiskGate(result, contract, candidate_encodings=config.candidate_encodings)


def _declared_encoding(source: SourceFile) -> str | None:
    """复用 sidecar 的 HTTP 声明作为声明可靠性输入；无 sidecar 则为 None。"""
    headers = source.sidecar.get("headers") if source.sidecar else None
    if not isinstance(headers, dict):
        return None
    for name, value in headers.items():
        if str(name).lower() == "content-type" and isinstance(value, str):
            match = None
            for token in value.split(";"):
                stripped = token.strip().lower()
                if stripped.startswith("charset="):
                    match = stripped.split("=", 1)[1].strip("\"'")
                    break
            if match:
                return match
    return None


def assess_file(
    gate: RiskGate,
    raw: bytes,
    source: SourceFile,
    decision: Decision,
    candidate_encodings: tuple[str, ...],
) -> DeliveryVerdict:
    """对单个新响应应用门槛；结论与原 encoding 决策并列、互不覆盖。"""
    declared = _declared_encoding(source)
    gate_decision = gate.assess(
        raw,
        candidate_encodings,
        declared_encoding=declared,
    )
    warning: WarningItem | None = None
    if not gate_decision.auto_deliver:
        if REJECT_BINDING_MISMATCH in gate_decision.reject_reasons:
            message = (
                "校准工件与当前规则版本或候选编码集合不一致，"
                "必须重新校准，本次一律拒判"
            )
        elif REJECT_NO_PROMOTED_RULE in gate_decision.reject_reasons:
            message = (
                "该合同没有通过独立验证的自动交付规则，"
                "证据不足，一律转人工复核"
            )
        else:
            message = (
                "风险校准门槛拒判："
                + "、".join(gate_decision.reject_reasons)
                + f"；原始 encoding 决策仍为 {decision.encoding}，"
                "不写入 UTF-8 产物"
            )
        warning = WarningItem("W_RISK_GATE_REJECTED", "high", message)
    elif not gate_decision.encoding_attribution_resolved:
        warning = WarningItem(
            "W_ENCODING_ATTRIBUTION_UNRESOLVED",
            "low",
            ERROR_CODES["W_ENCODING_ATTRIBUTION_UNRESOLVED"]
            + f"；文本等价类 {gate_decision.text_equivalence_class}，"
            f"归因记录为 {ATTRIBUTION_UNRESOLVED}",
        )
    return DeliveryVerdict(
        gate=gate_decision,
        auto_deliver=gate_decision.auto_deliver,
        warning=warning,
    )
