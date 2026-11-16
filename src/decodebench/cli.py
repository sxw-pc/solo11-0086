"""命令行入口：pipeline、离线修复候选/批准与只读 serve。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import RULE_VERSION
from .config import Config, ConfigError, load_config
from .ledger import record_repairs
from .mojibake import build_repair_candidates
from .pipeline import PipelineError, run
from .repair import (
    RepairError,
    apply_approval,
    build_candidates_document,
    load_approval,
    make_approval_template,
)
from .scanner import scan
from .transcoder import prepare_transcode_text
from .util import write_json
from .web import serve


def parse_now(value: str | None) -> str:
    if value is None:
        moment = datetime.now(timezone.utc)
    else:
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"--now 不是有效 ISO-8601 时间: {value}") from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decodebench",
        description="本地采集响应编码证据诊断与 UTF-8 转码归档",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    pipeline = subparsers.add_parser("pipeline", help="运行端到端批处理")
    pipeline.add_argument("--config", required=True, help="YAML 配置路径")
    pipeline.add_argument("--now", help="固定批次时间，ISO-8601；用于 golden 回归")

    candidates = subparsers.add_parser(
        "repair-candidates",
        help="离线重建可逆乱码修复候选并生成人工批准模板（不改动任何文件）",
    )
    candidates.add_argument("--config", required=True, help="YAML 配置路径")
    candidates.add_argument(
        "--output",
        help="批准模板输出路径；默认写入输出目录下 repair_approval.template.json",
    )

    approve = subparsers.add_parser(
        "repair-apply",
        help="校验人工批准文件并在独立修复副本中执行获批片段替换",
    )
    approve.add_argument("--config", required=True, help="YAML 配置路径")
    approve.add_argument("--approval", required=True, help="人工填写的批准 JSON 文件")
    approve.add_argument("--now", help="固定执行时间，ISO-8601；用于回归")

    serve_parser = subparsers.add_parser("serve", help="启动只读本地复核台")
    serve_parser.add_argument("--config", required=True, help="YAML 配置路径")
    return parser


def _rebuild_repair_findings(config):
    """离线重放扫描→裁决→转码文本步骤，重建与清单一致的修复候选证据。"""
    from .evidence import collect_evidence
    from .resolver import resolve
    from .scorer import analyze_candidates
    from .transcoder import transcode

    findings_per_file = []
    for source in scan(config):
        raw = source.path.read_bytes()
        evidence = collect_evidence(source, raw, config)
        statistical = analyze_candidates(raw, config.candidate_encodings)
        decision, evidence, _warnings = resolve(
            raw, source, evidence, statistical, config
        )
        output = transcode(source, raw, decision.encoding, config)
        if not output.success or output.output_rel_path is None:
            continue
        text, _, error, _, _ = prepare_transcode_text(
            raw,
            decision.encoding,
            config.transcode_errors,
            Path(source.rel_path).suffix,
            config.rewrite_declarations,
        )
        if error is not None or text is None:
            continue
        findings_per_file.append(
            build_repair_candidates(
                rel_path=source.rel_path,
                source_sha256=source.sha256,
                encoding=decision.encoding,
                transcoded_text=text,
                output_rel_path=output.output_rel_path,
                output_sha256=output.output_sha256,
            )
        )
    return findings_per_file


def _cmd_repair_candidates(config: Config, output: str | None) -> dict:
    config.ensure_directories()
    findings_per_file = _rebuild_repair_findings(config)
    document = build_candidates_document(
        findings_per_file, config.fingerprint, RULE_VERSION
    )
    write_json(config.repair_candidates_path, document)
    template = make_approval_template(document)
    template_path = Path(output) if output else config.out_dir / "repair_approval.template.json"
    write_json(template_path, template)
    return {
        "repair_candidates": config.repair_candidates_path.as_posix(),
        "approval_template": template_path.resolve().as_posix(),
        "summary": document["summary"],
    }


def _cmd_repair_apply(config: Config, approval_path: Path, now: str) -> dict:
    config.ensure_directories()
    if not approval_path.is_file():
        raise RepairError(f"批准文件不存在: {approval_path}")
    findings_per_file = _rebuild_repair_findings(config)
    approval = load_approval(approval_path)
    applied = apply_approval(
        approval_path,
        findings_per_file,
        config.transcode_dir,
        config.repair_dir,
        now=now,
    )
    approval_sha = hashlib.sha256(approval_path.read_bytes()).hexdigest()
    ledger = record_repairs(
        config, approval, approval_sha, [item.to_dict() for item in applied], now
    )
    return {
        "approval_sha256": approval_sha,
        "repair_dir": config.repair_dir.as_posix(),
        "applied_manifest": (config.repair_dir / "applied_repairs.json").as_posix(),
        "files": [item.to_dict() for item in applied],
        "ledger": ledger,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "pipeline":
            now = parse_now(args.now)
            result = run(config, now)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "repair-candidates":
            result = _cmd_repair_candidates(config, args.output)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "repair-apply":
            now = parse_now(args.now)
            result = _cmd_repair_apply(config, Path(args.approval), now)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "serve":
            print(
                f"只读复核台: http://{config.web_host}:{config.web_port}/",
                file=sys.stderr,
                flush=True,
            )
            serve(config)
            return 0
    except (ConfigError, PipelineError, RepairError, ValueError, OSError) as exc:
        print(f"decodebench: {exc}", file=sys.stderr)
        return 2
    return 2
