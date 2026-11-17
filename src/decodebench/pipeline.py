"""端到端流水线：扫描 → 证据 → 决策 → 转码 → 诊断 → 台账 → 报告。

带本地状态合成 sidecar 的 304 走离线归属入口（见 pipeline_validation），
其零字节不参与普通转码，也绝不产生伪空文本；其余文件沿用逐文件流程。
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .evidence import collect_evidence
from .ledger import record_batch
from .manifest import build_file_entry, build_manifest, write_manifest
from .mojibake import diagnose_bytes, to_warning_items
from .models import SourceFile, WarningItem
from .pipeline_validation import process_validation_event
from .reporting import write_reports
from .resolver import resolve
from .scanner import ScanError, is_validation_response, scan
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


def _process_ordinary_file(source: SourceFile, config: Config) -> dict[str, Any]:
    try:
        raw = source.path.read_bytes()
    except OSError as exc:
        raise PipelineError(f"无法读取 {source.rel_path}: {exc}") from exc
    evidence = collect_evidence(source, raw, config)
    candidates = analyze_candidates(raw, config.candidate_encodings)
    decision, evidence, warnings = resolve(raw, source, evidence, candidates, config)
    output = transcode(source, raw, decision.encoding, config)
    mojibake = diagnose_bytes(raw, decision.encoding, config)
    warnings.extend(to_warning_items(mojibake))
    if not output.success and not any(
        item.code == "E_UNDECODABLE" for item in warnings
    ):
        warnings.append(_transcode_warning(output))
    return build_file_entry(
        source, raw, evidence, candidates, decision, output, mojibake, warnings
    )


def run(config: Config, now: str) -> dict[str, Any]:
    """运行一个确定性批次并返回可打印摘要。"""
    config.ensure_directories()
    try:
        sources = scan(config)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc

    validation_sources = [s for s in sources if is_validation_response(s)]
    ordinary_sources = [s for s in sources if not is_validation_response(s)]
    entries = [_process_ordinary_file(source, config) for source in ordinary_sources]
    donor_entries = {item["rel_path"]: item for item in entries}
    validation_events = [
        process_validation_event(item, sources, donor_entries, config)
        for item in validation_sources]

    manifest = build_manifest(config, now, entries, validation_events)
    manifest_path = write_manifest(config, manifest)
    ledger_summary = record_batch(config, manifest, now, validation_events)
    report_paths = write_reports(config, manifest, ledger_summary, now)
    return {
        "batch_id": ledger_summary["batch_id"],
        "manifest": manifest_path.as_posix(),
        "database": config.db_path.as_posix(),
        "reports": {name: path.as_posix() for name, path in report_paths.items()},
        "summary": manifest["summary"],
        "validation_events": len(validation_events),
        "ledger": ledger_summary,
    }
