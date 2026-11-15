"""命令行入口：pipeline 与只读 serve。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .config import ConfigError, load_config
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
    serve_parser = subparsers.add_parser("serve", help="启动只读本地复核台")
    serve_parser.add_argument("--config", required=True, help="YAML 配置路径")
    return parser


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
