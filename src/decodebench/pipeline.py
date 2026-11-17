"""端到端流水线：扫描 → 证据 → 决策 → 转码 → 诊断 → 台账 → 报告。"""

from __future__ import annotations

from typing import Any

from .assembly import assemble_entities
from .config import Config
from .evidence import collect_assembled_evidence, collect_evidence
from .fragments import load_fragments
from .ledger import record_batch
from .manifest import (
    build_assembly_entry,
    build_entity_entry,
    build_file_entry,
    build_fragment_entry,
    build_manifest,
    write_manifest,
)
from .mojibake import diagnose_bytes, to_warning_items
from .models import (
    Decision,
    EntityResult,
    LoadedFragment,
    SourceFile,
    TranscodeResult,
    WarningItem,
)
from .reporting import write_reports
from .resolver import resolve
from .scanner import assembled_source, scan
from .scanner import ScanError
from .scorer import analyze_candidates
from .transcoder import transcode


class PipelineError(RuntimeError):
    """流水线不可恢复错误。"""


def _transcode_warning(result: TranscodeResult) -> WarningItem:
    return WarningItem(
        code="E_UNDECODABLE",
        severity="high",
        message=f"转码失败：{result.error or '未知解码错误'}",
    )


def _resolve_and_transcode(
    source: SourceFile,
    raw: bytes,
    config: Config,
    evidence: list[Any],
) -> tuple[Any, Decision, list[Any], list[WarningItem], TranscodeResult, Any]:
    candidates = analyze_candidates(raw, config.candidate_encodings)
    decision, evidence, warnings = resolve(raw, source, evidence, candidates, config)
    output = transcode(source, raw, decision.encoding, config)
    mojibake = diagnose_bytes(raw, decision.encoding, config)
    warnings.extend(to_warning_items(mojibake))
    if not output.success and not any(
        item.code == "E_UNDECODABLE" for item in warnings
    ):
        warnings.append(_transcode_warning(output))
    return candidates, decision, evidence, warnings, output, mojibake


def _regular_entry(source: SourceFile, config: Config) -> dict[str, Any]:
    try:
        raw = source.path.read_bytes()
    except OSError as exc:
        raise PipelineError(f"无法读取 {source.rel_path}: {exc}") from exc
    evidence = collect_evidence(source, raw, config)
    candidates, decision, evidence, warnings, output, mojibake = _resolve_and_transcode(
        source, raw, config, evidence
    )
    return build_file_entry(
        source, raw, evidence, candidates, decision, output, mojibake, warnings
    )


def _selected_fragments(
    result: EntityResult, loaded: list[LoadedFragment]
) -> list[LoadedFragment]:
    if result.selected is None:
        return []
    rel_paths = {item.rel_path for item in result.selected.fragments}
    return sorted(
        (item for item in loaded if item.rel_path in rel_paths),
        key=lambda item: item.rel_path,
    )


def _entity_sidecar(
    selected: list[LoadedFragment],
) -> tuple[dict[str, Any], str | None]:
    """只有所有选中片段的响应头一致时，才把 sidecar 头当作实体证据。"""
    if not selected:
        return {}, None
    headers = [item.source.sidecar.get("headers") for item in selected]
    paths = [item.source.sidecar_rel for item in selected]
    first = headers[0]
    if first and all(value == first for value in headers):
        return {"headers": first}, next((path for path in paths if path), None)
    return {}, None


def _entity_entry(
    result: EntityResult,
    loaded: list[LoadedFragment],
    config: Config,
) -> dict[str, Any]:
    entry = build_assembly_entry(result)
    if not result.complete or result.assembled is None or result.selected is None:
        return entry
    raw = result.assembled
    selected = _selected_fragments(result, loaded)
    sidecar, sidecar_rel = _entity_sidecar(selected)
    mtime = selected[0].source.mtime if selected else ""
    source = assembled_source(
        result.entity_id, raw, result.assembled_sha256 or "", mtime, sidecar, sidecar_rel
    )
    note = (
        f"由 entity_id={result.entity_id} 的 "
        f"{len(result.selected.fragments)} 个片段在完整实体字节上组装；"
        "BOM/文档声明只在组装字节上解释"
    )
    evidence = collect_assembled_evidence(source, raw, config, note)
    candidates, decision, evidence, warnings, output, mojibake = _resolve_and_transcode(
        source, raw, config, evidence
    )
    file_entry = build_file_entry(
        source, raw, evidence, candidates, decision, output, mojibake, warnings
    )
    return build_entity_entry(result, file_entry)


def run(config: Config, now: str) -> dict[str, Any]:
    """运行一个确定性批次并返回可打印摘要。"""
    config.ensure_directories()
    try:
        sources = scan(config)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc

    declared = [
        source
        for source in sources
        if source.fragment is not None or source.fragment_error is not None
    ]
    regular = [
        source
        for source in sources
        if source.fragment is None and source.fragment_error is None
    ]
    loaded, declaration_issues = load_fragments(declared)
    results = assemble_entities(loaded, config) if loaded else []

    assembled_paths = {
        fragment.rel_path
        for result in results
        if result.complete and result.selected is not None
        for fragment in result.selected.fragments
    }
    # 合同关闭时，声明了分段的文件也按普通文件单独处理，不做组装。
    if config.assembly_contract == "off":
        regular = sorted(
            regular
            + [source for source in declared if source.fragment is not None],
            key=lambda item: item.rel_path,
        )
        results = []
        assembled_paths = set()
    entries: list[dict[str, Any]] = []
    for source in regular:
        entries.append(_regular_entry(source, config))

    entity_entries: list[dict[str, Any]] = []
    fragment_entries: list[dict[str, Any]] = []
    for result in results:
        entry = _entity_entry(result, loaded, config)
        entity_entries.append(entry)
        for fragment in result.fragments:
            fragment_entries.append(
                build_fragment_entry(
                    result, fragment, fragment.rel_path in assembled_paths
                )
            )
    assembly = {
        "contract": config.assembly_contract,
        "priority_capture_ids": list(config.assembly_priority_capture_ids),
        "max_combinations_per_entity": config.assembly_max_combinations,
        "declaration_issues": declaration_issues,
        "entities": entity_entries,
        "fragments": fragment_entries,
        "summary": _assembly_summary(results, regular, assembled_paths),
    }
    manifest = build_manifest(config, now, entries, assembly)
    manifest_path = write_manifest(config, manifest)
    ledger_summary = record_batch(config, manifest, now)
    report_paths = write_reports(config, manifest, ledger_summary, now)
    return {
        "batch_id": ledger_summary["batch_id"],
        "manifest": manifest_path.as_posix(),
        "database": config.db_path.as_posix(),
        "reports": {name: path.as_posix() for name, path in report_paths.items()},
        "summary": manifest["summary"],
        "assembly": assembly["summary"],
        "ledger": ledger_summary,
    }


def _assembly_summary(
    results: list[EntityResult],
    regular: list[SourceFile],
    assembled_paths: set[str],
) -> dict[str, Any]:
    return {
        "entities_total": len(results),
        "entities_complete": sum(1 for item in results if item.complete),
        "entities_ambiguous": sum(1 for item in results if item.status == "ambiguous"),
        "entities_incomplete": sum(
            1 for item in results if item.status not in {"complete", "ambiguous"}
        ),
        "fragments_declared": sum(len(item.fragments) for item in results),
        "fragments_assembled": len(assembled_paths),
        "files_regular": len(regular),
        "files_consumed_by_entities": len(assembled_paths),
    }
