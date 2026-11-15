"""生成字段顺序稳定的 JSON、Markdown 与自包含 HTML 报告。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .config import Config
from .report_html import render_html
from .util import write_json, write_text


def build_report(
    manifest: dict[str, Any],
    ledger_summary: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for item in manifest["files"]:
        decision = item["decision"]
        files.append(
            {
                "rel_path": item["rel_path"],
                "encoding": decision["encoding"],
                "confidence": decision["confidence"],
                "method": decision["method"],
                "conflict": bool(decision["conflicts"]),
                "error_codes": list(decision["error_codes"]),
                "transcode_success": bool(item["transcode"]["success"]),
                "output_rel_path": item["transcode"]["output_rel_path"],
                "output_sha256": item["transcode"]["output_sha256"],
                "risk_level": item["mojibake"]["level"],
                "warning_count": item["warning_count"],
                "warning_codes": sorted({str(row["code"]) for row in item["warnings"]}),
            }
        )
    files.sort(key=lambda row: str(row["rel_path"]))
    return {
        "schema_version": "1.0",
        "project": "decodebench",
        "generated_at": now,
        "rule_version": RULE_VERSION,
        "config_fingerprint": manifest["config_fingerprint"],
        "batch_id": ledger_summary["batch_id"],
        "scan_root": manifest["scan_root"],
        "summary": manifest["summary"],
        "warning_distribution": manifest["summary"]["warning_distribution"],
        "files": files,
        "ledger": ledger_summary,
    }


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    ledger = report["ledger"]
    lines = [
        "# 采文解码台诊断报告",
        "",
        f"- 批次日：{report['generated_at']}",
        f"- 批次 ID：`{report['batch_id']}`",
        f"- 规则版本：`{report['rule_version']}`",
        f"- 扫描根：`{report['scan_root']}`",
        "",
        "## 摘要",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| 文件总数 | {summary['files_total']} |",
        f"| 冲突文件数 | {summary['conflict_files']} |",
        f"| 转码成功数 | {summary['transcode_success']} |",
        f"| 转码失败数 | {summary['transcode_failed']} |",
        f"| 有警告文件数 | {summary['files_with_warnings']} |",
        f"| 警告总数 | {summary['warnings_total']} |",
        "",
        "## 警告分布",
        "",
        "| 错误码 | 级别 | 数量 |",
        "| --- | --- | ---: |",
    ]
    if report["warning_distribution"]:
        for item in report["warning_distribution"]:
            lines.append(
                f"| {_cell(item['code'])} | {_cell(item['severity'])} | {item['count']} |"
            )
    else:
        lines.append("| 无 | - | 0 |")
    lines.extend(
        [
            "",
            "## 文件决策明细",
            "",
            "| 相对路径 | 编码 | 置信度 | 方法 | 冲突 | 转码 | 风险 | 警告 |",
            "| --- | --- | ---: | --- | --- | --- | --- | ---: |",
        ]
    )
    for item in report["files"]:
        lines.append(
            "| {path} | {encoding} | {confidence:.6f} | {method} | {conflict} | "
            "{transcode} | {risk} | {warnings} |".format(
                path=_cell(item["rel_path"]),
                encoding=_cell(item["encoding"]),
                confidence=float(item["confidence"]),
                method=_cell(item["method"]),
                conflict="是" if item["conflict"] else "否",
                transcode="成功" if item["transcode_success"] else "失败",
                risk=_cell(item["risk_level"]),
                warnings=item["warning_count"],
            )
        )
    lines.extend(
        [
            "",
            "## SQLite 台账摘要",
            "",
            "| 表/指标 | 数值 |",
            "| --- | ---: |",
            f"| 批内文件 | {ledger['files_in_batch']} |",
            f"| 批内冲突文件 | {ledger['conflict_files']} |",
            f"| 批内转码文件 | {ledger['transcoded_files']} |",
            f"| 证据行 | {ledger['evidence_rows']} |",
            f"| 决策行 | {ledger['decision_rows']} |",
            f"| 警告行 | {ledger['warning_rows']} |",
            f"| files 表总行数 | {ledger['files_table_total']} |",
            f"| batches 表总行数 | {ledger['batches_table_total']} |",
            "",
            "> 本报告仅依据本地落盘字节生成，不发起网络请求，不做自动二次修复。",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(
    config: Config,
    manifest: dict[str, Any],
    ledger_summary: dict[str, Any],
    now: str,
) -> dict[str, Path]:
    report = build_report(manifest, ledger_summary, now)
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": config.reports_dir / "report.json",
        "markdown": config.reports_dir / "report.md",
        "html": config.reports_dir / "report.html",
    }
    write_json(paths["json"], report)
    write_text(paths["markdown"], render_markdown(report))
    write_text(paths["html"], render_html(report))
    return paths
