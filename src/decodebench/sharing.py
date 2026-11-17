"""受控共享导出：把统一投影的结果写成可发布的合同包。

local_forensic 包面向获授权本地审计员（附完整内部 manifest 供核对字节）；
share_review 包只含匿名代号、编码决策与通过联合发布检查的类别/汇总，
以及可机器检查的 schema。共享包不引用内部输出路径、不含代号映射表、
不含源文件或转码正文；所有内容在本地落盘，不上传、不监听任何地址。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Config
from .ledger import batch_identity
from .ledger_queries import batch_summary
from .pipeline import PipelineError
from .projection import (
    CONTRACT_LOCAL_FORENSIC,
    CONTRACT_SHARE_REVIEW,
    CONTRACTS,
    FORENSIC_SCHEMA,
    SHARE_SCHEMA,
    SharePolicy,
    new_export_secret,
)
from .report_html import render_html
from .reporting import build_report, render_markdown
from .util import write_json, write_text


def _load_manifest(config: Config) -> dict[str, Any]:
    if not config.manifest_path.is_file():
        raise PipelineError(f"缺少 manifest.json（{config.manifest_path}），请先运行 pipeline")
    try:
        return json.loads(config.manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PipelineError(f"manifest.json 读取失败: {exc}") from exc


def _package_dir(config: Config, contract: str, output_dir: str | None) -> Path:
    directory = Path(output_dir).resolve() if output_dir else config.export_dir / contract
    if directory == config.scan_root or config.scan_root in directory.parents:
        raise PipelineError("共享包目录不得位于扫描源目录内，以保护源文件")
    return directory


def build_export(
    config: Config,
    *,
    contract: str,
    now: str,
    route: str | None = None,
    min_group_size: int | None = None,
    secret: str | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """按合同导出发布包，返回可打印的摘要。"""
    if contract not in CONTRACTS:
        raise PipelineError(f"未知使用合同: {contract}")
    manifest = _load_manifest(config)
    ledger_summary: dict[str, Any] | None = None
    if contract == CONTRACT_LOCAL_FORENSIC:
        _, batch_id = batch_identity(manifest["files"], config)
        ledger_summary = batch_summary(config.db_path, batch_id)
        if ledger_summary is None:
            raise PipelineError("缺少 SQLite 台账或对应批次，请先运行 pipeline")
    policy = SharePolicy(
        route=route or config.share_route,
        min_group_size=min_group_size or config.share_min_group_size,
        audit_contact=config.share_audit_contact,
    )
    report = build_report(
        manifest, ledger_summary, now,
        contract=contract, policy=policy, export_secret=secret or new_export_secret(),
    )
    directory = _package_dir(config, contract, output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stem = "share" if contract == CONTRACT_SHARE_REVIEW else "forensic"
    schema = SHARE_SCHEMA if contract == CONTRACT_SHARE_REVIEW else FORENSIC_SCHEMA
    paths = {
        "json": directory / f"{stem}.json",
        "markdown": directory / f"{stem}.md",
        "html": directory / f"{stem}.html",
        "schema": directory / f"{stem}_schema.json",
    }
    write_json(paths["json"], report)
    write_text(paths["markdown"], render_markdown(report))
    write_text(paths["html"], render_html(report))
    write_json(paths["schema"], schema)
    if contract == CONTRACT_LOCAL_FORENSIC:
        # 取证包附完整内部 manifest，便于获授权审计员在本机核对字节证据。
        paths["manifest"] = directory / "manifest.json"
        write_json(paths["manifest"], manifest)
    result: dict[str, Any] = {
        "contract": contract,
        "package_dir": directory.as_posix(),
        "files": {name: path.as_posix() for name, path in paths.items()},
    }
    if contract == CONTRACT_SHARE_REVIEW:
        result["export_id"] = report["export_id"]
        result["route"] = policy.route
        result["protected_files"] = report["disclosure"]["protected_files"]
    else:
        result["batch_id"] = report["batch_id"]
    return result
