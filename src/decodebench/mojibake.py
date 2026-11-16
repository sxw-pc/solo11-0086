"""乱码风险诊断：只报告证据，不自动二次转码。

本模块的 analyze/diagnose_bytes 只定位证据。可逆修复候选由
build_repair_candidates 单独提供：候选必须通过严格的
“按错误字符集重新编码 → 按目标字符集解码”路径且逐字符可逆，
典型字串命中本身不等于可修复；未经人工批准一律保留原文。
"""

from __future__ import annotations

import re

from .config import Config
from .detectors import canonical_encoding
from .models import MojibakeReport, WarningItem
from .repair import FileRepairFindings, TYPICAL_MOJIBAKE, build_repair_findings

CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
SURROGATE_TRACE = re.compile(r"\\u[dD][89a-fA-F][0-9a-fA-F]{2}|[\ud800-\udfff]")
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _line_column(text: str, offset: int) -> tuple[int, int]:
    before = text[:offset]
    line = before.count("\n") + 1
    column = offset - before.rfind("\n")
    return line, column


def _snippet(text: str, start: int, end: int, radius: int = 30) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    value = text[left:right].replace("\r", "\\r").replace("\n", "\\n")
    return value[:120]


def _finding(code: str, severity: str, text: str, start: int, end: int, message: str) -> dict[str, object]:
    line, column = _line_column(text, start)
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "line": line,
        "column": column,
        "offset": start,
        "snippet": _snippet(text, start, end),
    }


def analyze(text: str, config: Config) -> MojibakeReport:
    """基于已解码文本定位替换字符、mojibake 与控制字符。"""
    findings: list[dict[str, object]] = []
    replacement_char = chr(0xFFFD)
    replacement_offsets = [index for index, char in enumerate(text) if char == replacement_char]
    if replacement_offsets:
        start = replacement_offsets[0]
        message = f"发现 {len(replacement_offsets)} 个 Unicode 替换字符"
        findings.append(
            _finding("W_REPLACEMENT_CHARS", "high", text, start, start + 1, message)
        )
    for sequence in TYPICAL_MOJIBAKE:
        start = text.find(sequence)
        if start < 0:
            continue
        findings.append(
            _finding(
                "W_MOJIBAKE_SEQUENCE",
                "high",
                text,
                start,
                start + len(sequence),
                f"发现典型 mojibake 序列 {sequence!r}",
            )
        )
        if sum(1 for item in findings if item["code"] == "W_MOJIBAKE_SEQUENCE") >= 5:
            break
    control_matches = list(CONTROL_PATTERN.finditer(text))
    control_ratio = len(control_matches) / max(1, len(text))
    control_severity = (
        "medium" if control_ratio > config.control_ratio_threshold else "low"
    )
    for match in control_matches[:5]:
        findings.append(
            _finding(
                "W_CONTROL_CHARS",
                control_severity,
                text,
                match.start(),
                match.end(),
                f"发现不可打印控制字符 U+{ord(match.group(0)):04X}",
            )
        )
    question_pattern = re.compile(r"\?{%d,}" % config.question_run_threshold)
    question = question_pattern.search(text)
    if question:
        findings.append(
            _finding(
                "W_QUESTION_RUNS",
                "low",
                text,
                question.start(),
                question.end(),
                f"发现连续 {len(question.group(0))} 个问号",
            )
        )
    for match in SURROGATE_TRACE.finditer(text):
        findings.append(
            _finding(
                "W_SURROGATE_TRACE",
                "high",
                text,
                match.start(),
                match.end(),
                "发现非法代理项痕迹",
            )
        )
        break

    findings.sort(key=lambda item: (int(item["offset"]), str(item["code"])))
    level = "none"
    for item in findings:
        severity = str(item["severity"])
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[level]:
            level = severity
    if level == "high":
        recommendation = "正文可能已损坏；不要自动反复猜编码，应回溯源响应头与原始字节。"
    elif level in {"low", "medium"}:
        recommendation = "保留源文件证据，建议人工核查后再决定是否重新采集或修复。"
    else:
        recommendation = "未发现乱码风险，可进入下游处理。"
    return MojibakeReport(level=level, findings=findings, recommendation=recommendation)


def diagnose_bytes(raw: bytes, encoding: str, config: Config) -> MojibakeReport:
    """诊断时使用替换模式解码，但不把替换结果写回转码输出。"""
    try:
        text = raw.decode(canonical_encoding(encoding), errors="replace")
    except (LookupError, ValueError):
        text = raw.decode("latin-1", errors="replace")
    return analyze(text.lstrip("\ufeff"), config)


def to_warning_items(report: MojibakeReport) -> list[WarningItem]:
    warnings: list[WarningItem] = []
    for finding in report.findings:
        warnings.append(
            WarningItem(
                code=str(finding["code"]),
                severity=str(finding["severity"]),
                message=str(finding["message"]),
                line=int(finding["line"]),
                offset=int(finding["offset"]),
                snippet=str(finding["snippet"]),
            )
        )
    return warnings


def build_repair_candidates(
    rel_path: str,
    source_sha256: str,
    encoding: str,
    transcoded_text: str,
    output_rel_path: str | None,
    output_sha256: str | None,
) -> FileRepairFindings:
    """基于转码后的 UTF-8 文本生成可逆修复候选证据。

    仅枚举证据，不修改任何文件。含 U+FFFD、不可逆字符或相互重叠的候选
    会被标记为 blocked / ineligible，等待人工在独立批准文件中裁决。
    真实字面量与误码同形片段无法仅凭字符区分，因此按偏移分别列出。
    """
    return build_repair_findings(
        rel_path=rel_path,
        source_sha256=source_sha256,
        encoding=encoding,
        text=transcoded_text,
        transcode_output_rel_path=output_rel_path,
        transcode_output_sha256=output_sha256,
    )
