"""端到端流水线：扫描 → 证据 → 决策 → 转码 → 诊断 → 修复候选 → 台账 → 报告。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .config import Config
from .evidence import collect_evidence
from .ledger import record_batch
from .manifest import build_file_entry, build_manifest, write_manifest
from .mojibake import build_repair_candidates, diagnose_bytes, to_warning_items
from .models import WarningItem
from .repair import FileRepairFindings, build_candidates_document
from .reporting import write_reports
from .resolver import resolve
from .scanner import ScanError, scan
from .scorer import analyze_candidates
from .transcoder import prepare_transcode_text, transcode
from .util import write_json


class PipelineError(RuntimeError):
    """流水线不可恢复错误。"""


def _transcode_warning(result: Any) -> WarningItem:
    return WarningItem(
        code="E_UNDECODABLE",
        severity="high",
        message=f"转码失败：{result.error or '未知解码错误'}",
    )


def run(config: Config, now: str) -> dict[str, Any]:
    """运行一个确定性批次并返回可打印摘要。"""
    config.ensure_directories()
    try:
        sources = scan(config)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc

    entries: list[dict[str, Any]] = []
    repair_findings: list[FileRepairFindings] = []
    for source in sources:
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

        file_repair: FileRepairFindings | None = None
        if output.success and output.output_rel_path is not None:
            # 用与转码完全相同的解码+声明重写步骤重建文本，
            # 保证候选偏移与转码产物逐字符对齐，且不读取/改动转码产物。
            decoded, _, decode_error, _, _ = prepare_transcode_text(
                raw,
                decision.encoding,
                config.transcode_errors,
                Path(source.rel_path).suffix,
                config.rewrite_declarations,
            )
            if decode_error is None and decoded is not None:
                file_repair = build_repair_candidates(
                    rel_path=source.rel_path,
                    source_sha256=source.sha256,
                    encoding=decision.encoding,
                    transcoded_text=decoded,
                    output_rel_path=output.output_rel_path,
                    output_sha256=output.output_sha256,
                )
                repair_findings.append(file_repair)
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
                file_repair,
            )
        )

    manifest = build_manifest(config, now, entries)
    manifest_path = write_manifest(config, manifest)
    candidates_document = build_candidates_document(
        repair_findings, config.fingerprint, RULE_VERSION
    )
    write_json(config.repair_candidates_path, candidates_document)
    ledger_summary = record_batch(config, manifest, now)
    report_paths = write_reports(config, manifest, ledger_summary, now)
    return {
        "batch_id": ledger_summary["batch_id"],
        "manifest": manifest_path.as_posix(),
        "repair_candidates": config.repair_candidates_path.as_posix(),
        "database": config.db_path.as_posix(),
        "reports": {name: path.as_posix() for name, path in report_paths.items()},
        "summary": manifest["summary"],
        "repair_summary": candidates_document["summary"],
        "ledger": ledger_summary,
    }
