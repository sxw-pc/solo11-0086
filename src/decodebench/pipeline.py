"""端到端流水线：扫描 → 解封装 → 证据 → 决策 → 转码 → 诊断 → 台账 → 报告。"""

from __future__ import annotations

from typing import Any

from .config import Config
from .decompress import decompress, failure_message, failure_warning_code
from .evidence import collect_evidence
from .ledger import record_batch
from .manifest import build_file_entry, build_manifest, write_manifest
from .models import (
    Decision,
    DecompressResult,
    Evidence,
    SourceFile,
    WarningItem,
)
from .mojibake import diagnose_bytes, to_warning_items
from .reporting import write_reports
from .resolver import resolve
from .scanner import ScanError, scan
from .scorer import analyze_candidates
from .transcoder import discard_output, failed_result, transcode


class PipelineError(RuntimeError):
    """流水线不可恢复错误。"""


def _decompress_evidence(result: DecompressResult) -> list[Evidence]:
    if result.status == "none":
        return []
    failure = result.failure or {}
    if failure.get("code") == "E_CONTENT_ENCODING_INVALID":
        return [
            Evidence(
                source="content_encoding",
                declared=result.declared,
                offset=None,
                line=None,
                matches_decision=False,
                note=f"Content-Encoding 声明不可用：{failure.get('message')}",
            )
        ]
    return [
        Evidence(
            source="content_encoding",
            declared="gzip",
            offset=failure.get("offset"),
            line=None,
            note=(
                f"可信本地 sidecar 声明 Content-Encoding: {result.declared or 'gzip'}；"
                f"离线解封装状态 {result.status}"
            ),
        )
    ]


def _decompress_warning(result: DecompressResult) -> WarningItem:
    return WarningItem(
        code=failure_warning_code(result),
        severity="high",
        message=f"解封装失败：{failure_message(result)}",
    )


def _transcode_warning(result: Any) -> WarningItem:
    return WarningItem(
        code="E_UNDECODABLE",
        severity="high",
        message=f"转码失败：{result.error or '未知解码错误'}",
    )


def _analyze_body(
    source: SourceFile,
    raw: bytes,
    body: bytes,
    result: DecompressResult,
    config: Config,
    partial: bool,
) -> dict[str, Any]:
    evidence = _decompress_evidence(result) + collect_evidence(source, body, config)
    candidates = analyze_candidates(body, config.candidate_encodings)
    decision, evidence, warnings = resolve(body, source, evidence, candidates, config)
    output = transcode(source, body, decision.encoding, config, partial=partial)
    mojibake = diagnose_bytes(body, decision.encoding, config)
    warnings.extend(to_warning_items(mojibake))
    if partial:
        if output.output_sha256 is not None:
            warnings.append(
                WarningItem(
                    "W_GZIP_PARTIAL_PREFIX",
                    "high",
                    f"整体验收失败，仅归档已验证前缀 {len(body)} 字节；"
                    "partial 产物不可当作完整文件，也不计入成功转码",
                )
            )
        else:
            warnings.append(_transcode_warning(output))
        warnings.append(_decompress_warning(result))
    elif not output.success and not any(
        item.code == "E_UNDECODABLE" for item in warnings
    ):
        warnings.append(_transcode_warning(output))
    return build_file_entry(
        source, raw, evidence, candidates, decision, output, mojibake, warnings,
        decompress=result, body=body,
    )


def _strict_failure(
    source: SourceFile,
    raw: bytes,
    result: DecompressResult,
    config: Config,
) -> dict[str, Any]:
    """整体验收失败且不发布正文：不做字符集猜测，不保留旧产物。"""
    discard_output(source, config)
    evidence = _decompress_evidence(result)
    decision = Decision(
        encoding="",
        confidence=0.0,
        method="unresolved",
        reason=(
            "解封装未通过验收且授权路线不发布正文；"
            "没有经过校验的正文字节可供字符集裁决"
        ),
    )
    warnings = [_decompress_warning(result)]
    if source.sidecar_error:
        warnings.append(
            WarningItem("W_SIDECAR_INVALID", "medium", source.sidecar_error)
        )
    output = failed_result(
        source,
        "",
        config,
        failure_message(result),
        decoded_sha256=result.decoded_sha256,
        decoded_size=result.decoded_size,
    )
    return build_file_entry(
        source, raw, evidence, [], decision, output, None,
        warnings, decompress=result,
    )


def _pre_read_failure(source: SourceFile, config: Config) -> DecompressResult | None:
    """在读取实体前就能确定的失败：不可用声明与解封装前字节上限。"""
    if not config.content_encoding_enabled:
        return None
    if source.content_encoding_error:
        result = decompress(source, b"", config)
        result.entity_size = source.size
        return result
    if source.content_encoding_raw is None or source.size <= config.entity_max_bytes:
        return None
    message = (
        f"实体 {source.size} 字节超过解封装前上限 {config.entity_max_bytes}；"
        "未载入实体进行解压，未分配解压缓冲"
    )
    return DecompressResult(
        status="strict_failed",
        success=False,
        declared=source.content_encoding_raw,
        reason="gzip 实体超过解封装前字节上限",
        entity_sha256=source.sha256,
        entity_size=source.size,
        decoded_sha256=None,
        decoded_size=0,
        published_body=False,
        partial_prefix=False,
        members=[],
        verified_members=0,
        failure={
            "code": "E_GZIP_ENTITY_LIMIT",
            "message": message,
            "member_index": None,
            "offset": 0,
            "detail_offset": None,
        },
        limits={
            "max_members": config.gzip_max_members,
            "entity_max_bytes": config.entity_max_bytes,
            "inflate_max_bytes": config.inflate_max_bytes,
            "max_expansion_ratio": config.max_expansion_ratio,
        },
        body=None,
    )


def _process(source: SourceFile, raw: bytes, config: Config) -> dict[str, Any]:
    result = decompress(source, raw, config)
    if result.status == "none":
        # 无 gzip 声明的旧样本：现有字节流程完全不变。
        return _analyze_body(source, raw, raw, result, config, partial=False)
    if result.status == "complete" and result.body is not None:
        return _analyze_body(source, raw, result.body, result, config, partial=False)
    if result.partial_prefix and result.body is not None:
        return _analyze_body(source, raw, result.body, result, config, partial=True)
    return _strict_failure(source, raw, result, config)


def run(config: Config, now: str) -> dict[str, Any]:
    """运行一个确定性批次并返回可打印摘要。"""
    config.ensure_directories()
    try:
        sources = scan(config)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc

    entries: list[dict[str, Any]] = []
    for source in sources:
        pre_failure = _pre_read_failure(source, config)
        if pre_failure is not None:
            entries.append(_strict_failure(source, b"", pre_failure, config))
            continue
        try:
            raw = source.path.read_bytes()
        except OSError as exc:
            raise PipelineError(f"无法读取 {source.rel_path}: {exc}") from exc
        entries.append(_process(source, raw, config))

    manifest = build_manifest(config, now, entries)
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
