"""统一投影：同一份内部证据按使用合同生成 local_forensic / share_review 视图。

local_forensic 面向获授权本地审计员，保留路径、字节摘要、证据片段与精确计数。
share_review 面向外部复核者：视图从显式允许清单构造（而非对内部 manifest
删除字段），只保留本次导出的不透明文件代号、编码决策，以及通过联合发布
检查的类别/汇总。联合发布检查按敏感画像（风险等级 × 警告码集合 × 冲突
标记）分组，样本量不足的组受保护；只要存在受保护文件，风险/警告/冲突
三个敏感维度整体受限，行级标签与汇总总计同步抑制（suppress）或降精度
（interval），保证任何行、列总计都无法补集反推被藏单元。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import Counter
from dataclasses import dataclass
from typing import Any

from . import RULE_VERSION
from .manifest import summarize

CONTRACT_LOCAL_FORENSIC = "local_forensic"
CONTRACT_SHARE_REVIEW = "share_review"
CONTRACTS = (CONTRACT_LOCAL_FORENSIC, CONTRACT_SHARE_REVIEW)
ROUTE_SUPPRESS = "suppress"
ROUTE_INTERVAL = "interval"
ROUTES = (ROUTE_SUPPRESS, ROUTE_INTERVAL)
DEFAULT_AUDIT_CONTACT = "local-audit@example.invalid"
DEFAULT_MIN_GROUP_SIZE = 2

# 两种合同的逐文件字段都是显式允许清单；共享视图只能由 SHARED_FILE_FIELDS 构造。
FORENSIC_FILE_FIELDS = (
    "rel_path", "encoding", "confidence", "method", "conflict", "error_codes",
    "transcode_success", "output_rel_path", "output_sha256", "risk_level",
    "warning_count", "warning_codes",
)
SHARED_FILE_FIELDS = (
    "file_token", "encoding", "confidence_band", "method", "transcode_success",
    "risk_level", "warning_count", "warning_codes", "conflict", "error_codes",
)
# 共享视图禁止出现的内部字段（机器检查与文档共用同一份清单）。
SUPPRESSED_INTERNAL_FIELDS = (
    "rel_path", "source_size", "source_sha256", "source_mtime", "sidecar", "bom",
    "evidence", "statistical_candidates", "decision", "transcode", "mojibake",
    "warnings", "scan_root", "config_snapshot", "config_fingerprint", "batch_id",
    "ledger", "output_rel_path", "output_sha256", "snippet", "note", "message",
)
SHARED_TOP_LEVEL_FIELDS = (
    "schema_version", "project", "contract", "generated_at", "rule_version",
    "export_id", "audit_contact", "disclosure", "summary", "files",
)
# interval 路线下受保护文件的风险区间带：high 与 medium、none 与 low 不可区分。
RISK_BANDS = {"none": "none_or_low", "low": "none_or_low",
              "medium": "medium_or_high", "high": "medium_or_high"}

# 共享包的可机器检查 schema：预期可见字段、抑制字段与导出批次身份。
SHARE_SCHEMA: dict[str, Any] = {
    "schema": "decodebench.share/1.0",
    "contract": CONTRACT_SHARE_REVIEW,
    "top_level_fields": list(SHARED_TOP_LEVEL_FIELDS),
    "file_fields": list(SHARED_FILE_FIELDS),
    "summary_fields": [
        "files_total", "transcode_success", "transcode_failed", "method_distribution",
        "conflict_files", "files_with_warnings", "warnings_total",
        "risk_distribution", "warning_distribution",
    ],
    "suppressed_internal_fields": list(SUPPRESSED_INTERNAL_FIELDS),
    "export_identity": {
        "export_id": "X- 前缀随机导出标识，由本次导出的随机密钥派生",
        "file_token": "F- 前缀匿名代号，HMAC-SHA256(密钥, 路径) 派生而非普通哈希，"
        "仅在本包 JSON/Markdown/HTML 内一致",
        "linkability": "每次导出默认新随机密钥，独立导出之间不可关联",
        "mapping": "代号映射表不随包发布，也不写入任何输出",
    },
    "routes": {
        "suppress": "低样本组的行级标签与相关精确总计同时隐藏",
        "interval": "低样本组计数转为 {min,max} 区间、风险转为区间带，无法反算精确值",
    },
    "field_notes": "字段语义见 docs/SHARING.md 与 docs/REPORT_SCHEMA.md",
}
FORENSIC_SCHEMA: dict[str, Any] = {
    "schema": "decodebench.forensic/1.0",
    "contract": CONTRACT_LOCAL_FORENSIC,
    "description": "本地取证视图：保留路径、字节摘要、证据片段与精确计数，"
    "仅供获授权本地审计，不得离开本机受控环境。",
    "file_fields": list(FORENSIC_FILE_FIELDS),
}


@dataclass(frozen=True)
class SharePolicy:
    """共享发布策略：路线、最小组样本量与审计联系。"""

    route: str = ROUTE_SUPPRESS
    min_group_size: int = DEFAULT_MIN_GROUP_SIZE
    audit_contact: str = DEFAULT_AUDIT_CONTACT

    def __post_init__(self) -> None:
        if self.route not in ROUTES:
            raise ValueError(f"未知共享路线: {self.route}")
        if not isinstance(self.min_group_size, int) or self.min_group_size < 2:
            raise ValueError("min_group_size 必须是 >=2 的整数")
        if not self.audit_contact.strip():
            raise ValueError("audit_contact 不能为空")


def new_export_secret() -> str:
    """每次导出默认使用新的随机密钥，保证独立导出之间不可关联。"""
    return secrets.token_hex(16)


def _derive(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def export_identity(secret: str) -> str:
    return "X-" + _derive(secret, "decodebench/export")[:12]


def file_token(secret: str, rel_path: str) -> str:
    """匿名文件代号：带密钥的 HMAC，而非对路径的普通哈希。"""
    return "F-" + _derive(secret, "file/" + rel_path)[:10]


def confidence_band(value: float) -> str:
    score = float(value)
    for bound, band in ((0.9, "0.90-1.00"), (0.7, "0.70-0.90"), (0.55, "0.55-0.70")):
        if score >= bound:
            return band
    return "0.00-0.55"


def _interval(count: int, k: int, upper: int | None = None) -> dict[str, int]:
    """把精确计数转为包含真实值的区间，保证无法反算被藏单元。"""
    low, high = max(0, int(count) - (k - 1)), int(count) + (k - 1)
    return {"min": low, "max": min(high, upper) if upper is not None else high}


def _profile(row: dict[str, Any]) -> tuple[Any, ...]:
    return (str(row["risk_level"]), tuple(row["warning_codes"]), bool(row["conflict"]))


def joint_release(rows: list[dict[str, Any]], k: int) -> dict[str, Any]:
    """联合发布检查：低样本组受保护；存在受保护文件则敏感维度整体受限。"""
    groups = Counter(_profile(row) for row in rows)
    protected = {i for i, row in enumerate(rows) if groups[_profile(row)] < k}
    return {"protected": protected, "restricted": bool(protected)}


def summarize_internal(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """从内部行重建汇总（复用 manifest.summarize，供复核台使用）。"""
    entries = [
        {
            "decision": {"conflicts": [1] if row["conflict"] else [],
                         "method": row["method"]},
            "transcode": {"success": row["transcode_success"]},
            "mojibake": {"level": row["risk_level"]},
            "warnings": row["warning_details"],
        }
        for row in rows
    ]
    return summarize(entries)


def _project_summary(summary: dict[str, Any], policy: SharePolicy, restricted: bool) -> dict[str, Any]:
    projected: dict[str, Any] = {
        "files_total": summary["files_total"],
        "transcode_success": summary["transcode_success"],
        "transcode_failed": summary["transcode_failed"],
        "method_distribution": [dict(item) for item in summary["method_distribution"]],
    }
    keys = ("conflict_files", "files_with_warnings", "warnings_total",
            "risk_distribution", "warning_distribution")
    if not restricted:
        projected.update({key: summary[key] for key in keys})
        return projected
    if policy.route == ROUTE_INTERVAL:
        k, total = policy.min_group_size, summary["files_total"]
        projected["conflict_files"] = _interval(summary["conflict_files"], k, total)
        projected["files_with_warnings"] = _interval(summary["files_with_warnings"], k, total)
        projected["warnings_total"] = _interval(summary["warnings_total"], k)
        projected["risk_distribution"] = [
            {"level": item["level"], "count": _interval(item["count"], k, total)}
            for item in summary["risk_distribution"]
        ]
        projected["warning_distribution"] = [
            {"code": item["code"], "severity": item["severity"],
             "count": _interval(item["count"], k)}
            for item in summary["warning_distribution"]
        ]
        return projected
    projected.update({key: "suppressed" for key in keys})
    return projected


def _project_rows(rows, policy, secret, protected) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        item: dict[str, Any] = {
            "file_token": file_token(secret, str(row["rel_path"])),
            "encoding": row["encoding"],
            "confidence_band": confidence_band(row["confidence"]),
            "method": row["method"],
            "transcode_success": bool(row["transcode_success"]),
        }
        if index not in protected:
            item.update({
                "risk_level": row["risk_level"],
                "warning_count": row["warning_count"],
                "warning_codes": list(row["warning_codes"]),
                "conflict": bool(row["conflict"]),
                "error_codes": list(row["error_codes"]),
            })
        elif policy.route == ROUTE_INTERVAL:
            item.update({
                "risk_level": RISK_BANDS.get(str(row["risk_level"]), "suppressed"),
                "warning_count": _interval(row["warning_count"], policy.min_group_size),
                "warning_codes": "suppressed",
                "conflict": "suppressed",
                "error_codes": "suppressed",
            })
        else:
            item.update({key: "suppressed" for key in (
                "risk_level", "warning_count", "warning_codes", "conflict", "error_codes")})
        projected.append(item)
    return projected


def _disclosure(policy: SharePolicy, restricted: bool, protected_count: int) -> dict[str, Any]:
    if not restricted:
        status = "exact"
    else:
        status = "interval" if policy.route == ROUTE_INTERVAL else "suppressed"
    retained = [
        "每份响应的编码决策、决策方法类别、置信度区间带与转码状态",
        "文件总数、转码成功/失败数与方法分布等不含敏感维度的精确计数",
    ]
    undeterminable: list[str] = []
    if restricted:
        retained.append("未受保护文件的风险等级、警告类别与冲突标记（所属类别组样本量达标）")
        undeterminable = [
            "各乱码风险等级的精确文件数（含任何唯一高风险状态）",
            "警告类别分布、警告总数与含警告文件数的精确值",
            "冲突文件数的精确值",
            "受保护文件的风险等级、警告码、警告数、冲突标记与错误码",
        ]
    else:
        retained.append("风险等级、警告类别与冲突的精确分布（所有类别组样本量达标）")
    return {
        "contract": CONTRACT_SHARE_REVIEW,
        "route": policy.route,
        "min_group_size": policy.min_group_size,
        "protected_files": protected_count,
        "visible_file_fields": list(SHARED_FILE_FIELDS),
        "suppressed_internal_fields": list(SUPPRESSED_INTERNAL_FIELDS),
        "dimensions": {
            "risk_level": {"status": status},
            "warning_codes": {"status": status},
            "conflict": {"status": status},
        },
        "retained_conclusions": retained,
        "undeterminable_conclusions": undeterminable,
        "token_note": "文件代号由本次导出的随机密钥经 HMAC 派生，仅在本包内一致；"
        "不同导出默认不可关联，也不是对路径的普通哈希。",
        "mapping_note": "代号与源文件的映射表不随包发布，也不写入任何输出；"
        "本包不引用内部输出路径。",
    }


def build_shared_view(rows, summary, policy: SharePolicy, now: str, secret: str) -> dict[str, Any]:
    """share_review 合同视图：统一投影的共享侧入口。"""
    release = joint_release(rows, policy.min_group_size)
    return {
        "schema_version": "1.0",
        "project": "decodebench",
        "contract": CONTRACT_SHARE_REVIEW,
        "generated_at": now,
        "rule_version": RULE_VERSION,
        "export_id": export_identity(secret),
        "audit_contact": policy.audit_contact,
        "disclosure": _disclosure(policy, release["restricted"], len(release["protected"])),
        "summary": _project_summary(summary, policy, release["restricted"]),
        "files": _project_rows(rows, policy, secret, release["protected"]),
    }
