"""命令行入口：pipeline、风险校准与只读 serve。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .calibration import (
    CONTRACTS,
    CalibrationError,
    calibrate,
    load_annotations,
    write_calibration,
)
from .config import ConfigError, load_config
from .detectors import canonical_encoding
from .pipeline import PipelineError, run
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
    pipeline.add_argument(
        "--gate-artifact",
        help="离线风险校准工件路径；提供后启用自动交付/拒判门槛",
    )
    pipeline.add_argument(
        "--gate-contract",
        choices=CONTRACTS,
        help="门槛适用的发布合同（forensic_archive / search_index）",
    )
    calibrate_parser = subparsers.add_parser(
        "calibrate",
        help="用离线合成标注响应校准自动交付风险门槛",
    )
    calibrate_parser.add_argument("--config", required=True, help="YAML 配置路径")
    calibrate_parser.add_argument(
        "--annotations", required=True, help="合成标注 JSON（base64 原始字节）路径"
    )
    calibrate_parser.add_argument(
        "--output", required=True, help="校准工件输出路径（JSON）"
    )
    calibrate_parser.add_argument(
        "--risk-budget",
        type=float,
        default=0.05,
        help="合同错误文本率风险预算（默认 0.05）",
    )
    calibrate_parser.add_argument(
        "--confidence-level",
        type=float,
        default=0.95,
        help="单侧精确上界置信水平（默认 0.95）",
    )
    calibrate_parser.add_argument(
        "--validation-ratio",
        type=float,
        default=0.3,
        help="来源组进入独立验证集的比例（默认 0.3）",
    )
    calibrate_parser.add_argument(
        "--annotation-set-id",
        default="synthetic-offline-v1",
        help="标注集标识，写入工件摘要",
    )
    serve_parser = subparsers.add_parser("serve", help="启动只读本地复核台")
    serve_parser.add_argument("--config", required=True, help="YAML 配置路径")
    return parser


def _run_calibrate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    samples = load_annotations(Path(args.annotations))
    result = calibrate(
        samples,
        tuple(canonical_encoding(item) for item in config.candidate_encodings),
        risk_budget=args.risk_budget,
        confidence_level=args.confidence_level,
        validation_ratio=args.validation_ratio,
        annotation_set_id=args.annotation_set_id,
    )
    output = write_calibration(Path(args.output), result)
    summary = {
        "artifact": output.as_posix(),
        "annotation_digest": result.annotation_digest,
        "rule_version": result.rule_version,
        "candidate_encodings": list(result.candidate_encodings),
        "groups": {
            "total": result.annotation_summary["groups_total"],
            "tuning": result.annotation_summary["tuning_groups"],
            "validation": result.annotation_summary["validation_groups"],
        },
        "contracts": [
            {
                "contract": item.contract,
                "promoted": item.promoted,
                "selected_rule": item.selected_rule.to_dict()
                if item.selected_rule
                else None,
                "rejection_reason": item.rejection_reason,
                "validation": item.validation.to_dict() if item.validation else None,
            }
            for item in result.contracts
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "calibrate":
            return _run_calibrate(args)
        config = load_config(args.config)
        if args.command == "pipeline":
            now = parse_now(args.now)
            if bool(args.gate_artifact) != bool(args.gate_contract):
                raise ValueError("--gate-artifact 与 --gate-contract 必须同时提供")
            result = run(
                config,
                now,
                gate_artifact=args.gate_artifact,
                gate_contract=args.gate_contract,
            )
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
    except (ConfigError, PipelineError, CalibrationError, ValueError, OSError) as exc:
        print(f"decodebench: {exc}", file=sys.stderr)
        return 2
    return 2
