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
    audit: dict[str, Any] | None = None,
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
    report: dict[str, Any] = {
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
    if audit is not None:
        report["postdelivery_audit"] = audit
    return report


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _fmt_ratio(value: float | None) -> str:
    return "—" if value is None else f"{float(value) * 100:.2f}%"


def _fmt_number(value: float | None) -> str:
    return "—" if value is None else f"{float(value):.2f}"


def _audit_lines(audit: dict[str, Any]) -> list[str]:
    files = audit["file_lens"]
    byt = audit["byte_lens"]
    counts = audit["unit_counts"]
    thresholds = audit["thresholds"]
    lines = [
        "",
        "## 事后人工抽样审计",
        "",
        f"- 绑定批次：`{audit['batch_id']}`",
        f"- 抽样框摘要：`{audit['frame_digest']}`",
        f"- 抽样计划摘要：`{audit['plan_digest']}`",
        f"- 估计类型：`{audit['estimate_type'] or '不可估'}`",
        f"- 可估计：{'是' if audit['estimable'] else '否'}"
        + (f"（{audit['not_estimable_reason']}）" if audit["not_estimable_reason"] else ""),
        f"- 交付文件 / 输出字节：{counts['delivered_files']} / {counts['delivered_output_bytes']}",
        f"- 已审 / 已回应：{counts['sampled_files']} / {counts['responded_files']}"
        f"（wrong {counts['wrong_files_observed']}，correct {counts['correct_files_observed']}）",
        f"- undecidable / 未回应 / 输出缺失：{counts['undecidable_files']} / "
        f"{counts['no_response_files']} / {counts['missing_output_files']}",
        f"- 联合置信度：{audit['joint_confidence']}（{audit['confidence_allocation']}）",
        "",
        "| 口径 | 点估计 | 点估计占比 | 95% 下界 | 95% 上界 | 整改结论 |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
        f"| 错误文件数（权重 1/π） | {_fmt_number(files['wrong_files_estimate'])} | "
        f"{_fmt_ratio(files['wrong_file_ratio_estimate'])} | "
        f"{_fmt_ratio(files['lower_ratio'])} | {_fmt_ratio(files['upper_ratio_95'])} | "
        f"{thresholds['file_verdict']} |",
        f"| 错误文件中的 UTF-8 输出字节（权重 输出字节/π） | "
        f"{_fmt_number(byt['exposed_wrong_output_bytes_estimate'])} | "
        f"{_fmt_ratio(byt['exposed_wrong_output_byte_ratio_estimate'])} | "
        f"{_fmt_ratio(byt['lower_ratio'])} | {_fmt_ratio(byt['upper_ratio_95'])} | "
        f"{thresholds['byte_verdict']} |",
        "",
        f"> 文件整改告警线 {_fmt_ratio(thresholds['file_ratio'])}；"
        f"字节暴露告警线 {_fmt_ratio(thresholds['byte_ratio'])}。"
        "字节口径衡量的是“错误文件中的输出字节暴露”，不是精确的错误字节数。",
        "",
        "| 风险层 | 总体 | 样本 | 入样概率 | 回应 | 实测错误 | 错误数上界 | 字节上界 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in audit["strata"]:
        lines.append(
            f"| {_cell(row['risk_level'])} | {row['population']} | {row['sample_size']} | "
            f"{row['inclusion_probability']:.6f} | {row['responded']} | "
            f"{row['observed_wrong']} | {row['upper_wrong_files_95']} | "
            f"{row['upper_exposed_bytes_95']} |"
        )
    lines.extend(["", "> 人工标签只影响审计输出；未回应文件不计为 correct，"
                  "风险等级高也不自动计为 wrong。", ""])
    return lines


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
        ]
    )
    if "postdelivery_audit" in report:
        lines.extend(_audit_lines(report["postdelivery_audit"]))
    lines.extend(
        [
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
    audit: dict[str, Any] | None = None,
) -> dict[str, Path]:
    report = build_report(manifest, ledger_summary, now, audit)
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
