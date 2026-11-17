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
        delivery = item.get("delivery")
        row = {
            "rel_path": item["rel_path"],
            "encoding": decision["encoding"],
            "confidence": decision["confidence"],
            "method": decision["method"],
            "conflict": bool(decision["conflicts"]),
            "error_codes": list(decision["error_codes"]),
            "transcode_success": (
                bool(item["transcode"]["success"]) if item["transcode"] else False
            ),
            "output_rel_path": (
                item["transcode"]["output_rel_path"] if item["transcode"] else None
            ),
            "output_sha256": (
                item["transcode"]["output_sha256"] if item["transcode"] else None
            ),
            "risk_level": item["mojibake"]["level"],
            "warning_count": item["warning_count"],
            "warning_codes": sorted({str(row["code"]) for row in item["warnings"]}),
        }
        if delivery is not None:
            row["delivery"] = {
                "contract": delivery["contract"],
                "auto_deliver": bool(delivery["auto_deliver"]),
                "rule_id": delivery["rule_id"],
                "text_equivalence_class": delivery["text_equivalence_class"],
                "label_certain": bool(delivery["label_certain"]),
                "encoding_attribution_resolved": bool(
                    delivery["encoding_attribution_resolved"]
                ),
                "reject_reasons": list(delivery["reject_reasons"]),
                "risk_budget": delivery["risk_budget"],
                "validated_error_rate_upper_bound": delivery[
                    "validated_error_rate_upper_bound"
                ],
            }
        files.append(row)
    files.sort(key=lambda row: str(row["rel_path"]))
    report = {
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
    if "risk_gate" in manifest:
        report["risk_gate"] = manifest["risk_gate"]
    return report


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
                transcode="成功" if item["transcode_success"] else "失败/拒判",
                risk=_cell(item["risk_level"]),
                warnings=item["warning_count"],
            )
        )
    if "risk_gate" in report:
        gate = report["risk_gate"]
        lines.extend(
            [
                "",
                "## 风险校准门槛",
                "",
                f"- 发布合同：`{gate['contract']}`",
                f"- 规则版本：`{gate['rule_version']}`",
                f"- 标注摘要：`{gate['annotation_digest']}`",
                f"- 候选编码集合：{', '.join(gate['candidate_encodings'])}",
                f"- 风险预算：{gate['risk_budget']:.6f}",
                f"- 独立验证单侧精确上界：{gate['validated_error_rate_upper_bound']}",
                f"- 规则已推广：{'是' if gate['promoted'] else '否（全部拒判）'}",
                "",
                "| 相对路径 | 自动交付 | 规则 | 文本等价类 | 标签确定 | 编码归因 | 拒判原因 |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in report["files"]:
            delivery = item.get("delivery")
            if delivery is None:
                continue
            lines.append(
                "| {path} | {deliver} | {rule} | {equiv} | {label} | {attribution} | {reasons} |".format(
                    path=_cell(item["rel_path"]),
                    deliver="是" if delivery["auto_deliver"] else "否",
                    rule=_cell(delivery["rule_id"] or "-"),
                    equiv=_cell(delivery["text_equivalence_class"]),
                    label="是" if delivery["label_certain"] else "否",
                    attribution=(
                        "已定" if delivery["encoding_attribution_resolved"] else "未定"
                    ),
                    reasons=_cell("、".join(delivery["reject_reasons"]) or "-"),
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
