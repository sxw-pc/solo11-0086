"""命令行入口：pipeline 与只读 serve。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .config import Config, ConfigError, load_config, with_assembly
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
    assemble = subparsers.add_parser(
        "assemble-responses",
        help="只把有旁证的片段组装为完整实体后走现有证据与转码链",
    )
    assemble.add_argument("--config", required=True, help="YAML 配置路径")
    assemble.add_argument(
        "--contract",
        choices=("consensus", "authorized_capture"),
        help="覆盖配置中的 assembly.contract",
    )
    assemble.add_argument(
        "--authorized-capture",
        action="append",
        dest="authorized_captures",
        default=None,
        help="按优先级追加授权 capture_id，可重复",
    )
    assemble.add_argument("--now", help="固定批次时间，ISO-8601；用于 golden 回归")
    serve_parser = subparsers.add_parser("serve", help="启动只读本地复核台")
    serve_parser.add_argument("--config", required=True, help="YAML 配置路径")
    return parser


def _assemble_config(config: Config, args: argparse.Namespace) -> Config:
    contract = args.contract or config.assembly_contract
    captures = config.assembly_priority_capture_ids
    if args.authorized_captures is not None:
        captures = tuple(args.authorized_captures)
    if contract == "off":
        raise ConfigError(
            "assemble-responses 需要 assembly.contract=consensus 或 "
            "authorized_capture（可用 --contract 覆盖）"
        )
    return with_assembly(config, contract, captures)


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
        if args.command == "assemble-responses":
            now = parse_now(args.now)
            result = run(_assemble_config(config, args), now)
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
    except (ConfigError, PipelineError, ValueError, OSError) as exc:
        print(f"decodebench: {exc}", file=sys.stderr)
        return 2
    return 2
