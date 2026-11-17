"""端到端流水线：扫描 → 证据 → 决策 → 风险门槛 → 转码 → 诊断 → 台账 → 报告。"""

from __future__ import annotations

from typing import Any

from .config import Config
from .evidence import collect_evidence
from .gate import DeliveryVerdict, assess_file, build_gate
from .ledger import record_batch
from .manifest import build_file_entry, build_manifest, write_manifest
from .mojibake import diagnose_bytes, to_warning_items
from .models import WarningItem
from .reporting import write_reports
from .resolver import resolve
from .scanner import ScanError, scan
from .scorer import analyze_candidates
from .transcoder import transcode


class PipelineError(RuntimeError):
    """流水线不可恢复错误。"""


def _transcode_warning(result: Any) -> WarningItem:
    return WarningItem(
        code="E_UNDECODABLE",
        severity="high",
        message=f"转码失败：{result.error or '未知解码错误'}",
    )


def run(
    config: Config,
    now: str,
    gate_artifact: str | None = None,
    gate_contract: str | None = None,
) -> dict[str, Any]:
    """运行一个确定性批次并返回可打印摘要。

    提供 ``gate_artifact`` 时启用风险门槛：先完成与原先完全一致的证据采集、
    候选评分与单文件 encoding 裁决，再由校准工件决定自动交付或拒判。拒判
    文件不调用转码、不写任何 UTF-8 产物，manifest 中 ``transcode`` 为 null、
    ``delivery.auto_deliver`` 为 false，绝不伪装成成功。
    """
    config.ensure_directories()
    try:
        sources = scan(config)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc

    gate = None
    if gate_artifact is not None:
        if not gate_contract:
            raise PipelineError("启用风险门槛时必须指定 gate_contract")
        gate = build_gate(gate_artifact, gate_contract, config)

    entries: list[dict[str, Any]] = []
    for source in sources:
        try:
            raw = source.path.read_bytes()
        except OSError as exc:
            raise PipelineError(f"无法读取 {source.rel_path}: {exc}") from exc
        evidence = collect_evidence(source, raw, config)
        candidates = analyze_candidates(raw, config.candidate_encodings)
        decision, evidence, warnings = resolve(raw, source, evidence, candidates, config)
        mojibake = diagnose_bytes(raw, decision.encoding, config)
        warnings.extend(to_warning_items(mojibake))

        delivery: DeliveryVerdict | None = None
        output = None
        if gate is not None:
            delivery = assess_file(
                gate, raw, source, decision, config.candidate_encodings
            )
            if delivery.warning is not None:
                warnings.append(delivery.warning)
            if not delivery.auto_deliver:
                entries.append(
                    build_file_entry(
                        source,
                        raw,
                        evidence,
                        candidates,
                        decision,
                        None,
                        mojibake,
                        warnings,
                        delivery=delivery.to_dict(),
                    )
                )
                continue
        output = transcode(source, raw, decision.encoding, config)
        if not output.success and not any(
            item.code == "E_UNDECODABLE" for item in warnings
        ):
            warnings.append(_transcode_warning(output))
        entries.append(
            build_file_entry(
                source,
                raw,
                evidence,
                candidates,
                decision,
                output,
                mojibake,
                warnings,
                delivery=delivery.to_dict() if delivery is not None else None,
            )
        )

    manifest = build_manifest(config, now, entries)
    if gate is not None:
        manifest["risk_gate"] = {
            "contract": gate.contract,
            "annotation_digest": gate.result.annotation_digest,
            "rule_version": gate.result.rule_version,
            "candidate_encodings": list(gate.result.candidate_encodings),
            "promoted": gate.rule is not None,
            "selected_rule": gate.rule.to_dict() if gate.rule else None,
            "risk_budget": gate.risk_budget,
            "validated_error_rate_upper_bound": gate.validated_bound,
            "binding": gate.binding_detail,
        }
    manifest_path = write_manifest(config, manifest)
    ledger_summary = record_batch(config, manifest, now)
    report_paths = write_reports(config, manifest, ledger_summary, now)
    return {
        "batch_id": ledger_summary["batch_id"],
        "manifest": manifest_path.as_posix(),
        "database": config.db_path.as_posix(),
        "reports": {name: path.as_posix() for name, path in report_paths.items()},
        "summary": manifest["summary"],
        "ledger": ledger_summary,
    }
