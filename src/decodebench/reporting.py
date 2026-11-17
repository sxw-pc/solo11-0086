"""生成字段顺序稳定的 JSON、Markdown 与自包含 HTML 报告。

build_report 是统一投影的报告入口：同一份内部证据按合同生成
local_forensic（完整取证）或 share_review（受控共享）视图，
三种格式（JSON/Markdown/HTML）始终来自同一次投影，字段天然一致。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .config import Config
from .manifest import build_internal_rows
from .projection import (
    CONTRACT_LOCAL_FORENSIC,
    CONTRACT_SHARE_REVIEW,
    CONTRACTS,
    FORENSIC_FILE_FIELDS,
    SharePolicy,
    build_shared_view,
    new_export_secret,
)
from .report_html import render_html
from .util import write_json, write_text


def build_report(
    manifest: dict[str, Any],
    ledger_summary: dict[str, Any] | None,
    now: str,
    *,
    contract: str = CONTRACT_LOCAL_FORENSIC,
    policy: SharePolicy | None = None,
    export_secret: str | None = None,
) -> dict[str, Any]:
    """按合同投影内部证据。

    local_forensic：保留路径、哈希与精确计数（既有 report.json 结构）。
    share_review：只允许显式允许清单字段，敏感维度经联合发布检查。
    """
    if contract not in CONTRACTS:
        raise ValueError(f"未知使用合同: {contract}")
    rows = build_internal_rows(manifest)
    if contract == CONTRACT_SHARE_REVIEW:
        policy = policy or SharePolicy()
        secret = export_secret or new_export_secret()
        return build_shared_view(rows, manifest["summary"], policy, now, secret)
    if ledger_summary is None:
        raise ValueError("local_forensic 视图需要台账摘要")
    files = [{key: row[key] for key in FORENSIC_FILE_FIELDS} for row in rows]
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


def _share_value(value: Any) -> str:
    """共享视图单元格：区间、抑制标记与原值的统一可读表示。"""
    if isinstance(value, dict) and "min" in value and "max" in value:
        return f"{value['min']}–{value['max']}"
    if value == "suppressed":
        return "已抑制"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "无"
    if value is True:
        return "是"
    if value is False:
        return "否"
    return str(value)


def _distribution_md(title: str, distribution: Any, headers: str, key: str) -> list[str]:
    lines = ["", f"## {title}", ""]
    if isinstance(distribution, str):
        lines.append("已抑制：低样本组联合发布检查未通过，精确分布不发布。")
        return lines
    lines.append(headers)
    if not distribution:
        lines.append("| 无 | - | 0 |" if key == "code" else "| 无 | 0 |")
    for item in distribution:
        label = _cell(str(item.get(key) or item.get("method")))
        if key == "code":
            lines.append(f"| {label} | {_cell(item['severity'])} | {_share_value(item['count'])} |")
        else:
            lines.append(f"| {label} | {_share_value(item['count'])} |")
    return lines


def render_shared_markdown(view: dict[str, Any]) -> str:
    """share_review 视图的 Markdown 渲染（与 JSON/HTML 同一次投影）。"""
    summary = view["summary"]
    disclosure = view["disclosure"]
    lines = [
        "# 采文解码台受控共享视图",
        "",
        f"- 合同：`{view['contract']}`",
        f"- 导出 ID：`{view['export_id']}`",
        f"- 生成时间：{view['generated_at']}",
        f"- 规则版本：`{view['rule_version']}`",
        f"- 审计联系：{view['audit_contact']}",
        f"- 发布路线：`{disclosure['route']}`（最小组样本量 k={disclosure['min_group_size']}）",
        "",
        "## 摘要",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
    ]
    for label, key in (
        ("文件总数", "files_total"), ("转码成功数", "transcode_success"),
        ("转码失败数", "transcode_failed"), ("冲突文件数", "conflict_files"),
        ("含警告文件数", "files_with_warnings"), ("警告总数", "warnings_total"),
    ):
        lines.append(f"| {label} | {_share_value(summary[key])} |")
    lines += _distribution_md("方法分布", summary["method_distribution"],
                              "| 方法 | 数量 |\n| --- | ---: |", "method")
    lines += _distribution_md("风险分布", summary["risk_distribution"],
                              "| 等级 | 文件数 |\n| --- | ---: |", "level")
    lines += _distribution_md("警告分布", summary["warning_distribution"],
                              "| 错误码 | 级别 | 数量 |\n| --- | --- | ---: |", "code")
    lines += [
        "",
        "## 文件决策明细（匿名代号）",
        "",
        "| 文件代号 | 编码 | 置信区间 | 方法 | 转码 | 风险 | 警告数 | 冲突 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in view["files"]:
        lines.append(
            "| {token} | {encoding} | {band} | {method} | {transcode} | {risk} | "
            "{warnings} | {conflict} |".format(
                token=_cell(item["file_token"]), encoding=_cell(item["encoding"]),
                band=_cell(item["confidence_band"]), method=_cell(item["method"]),
                transcode="成功" if item["transcode_success"] else "失败",
                risk=_share_value(item["risk_level"]),
                warnings=_share_value(item["warning_count"]),
                conflict=_share_value(item["conflict"]),
            )
        )
    if not view["files"]:
        lines.append("| 无 | - | - | - | - | - | - | - |")
    lines += ["", "## 披露说明", ""]
    lines.append(f"- 可见逐文件字段：{', '.join(disclosure['visible_file_fields'])}")
    lines.append(f"- 抑制的内部字段：{', '.join(disclosure['suppressed_internal_fields'])}")
    lines.append("- 保留结论：" + "；".join(disclosure["retained_conclusions"]))
    if disclosure["undeterminable_conclusions"]:
        lines.append("- 无法从共享数据判断：" + "；".join(disclosure["undeterminable_conclusions"]))
    lines += [
        f"- {disclosure['token_note']}",
        f"- {disclosure['mapping_note']}",
        "",
        "> 本共享视图不包含路径、哈希、证据片段、精确时间戳或内部输出位置；不发起网络请求。",
        "",
    ]
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    if report.get("contract") == CONTRACT_SHARE_REVIEW:
        return render_shared_markdown(report)
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
