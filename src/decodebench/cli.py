"""命令行入口：pipeline、export 与只读 serve。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .config import ConfigError, load_config
from .pipeline import PipelineError, run
from .projection import CONTRACTS, ROUTES
from .sharing import build_export
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
    export_parser = subparsers.add_parser(
        "export", help="按合同导出 local_forensic / share_review 发布包"
    )
    export_parser.add_argument("--config", required=True, help="YAML 配置路径")
    export_parser.add_argument(
        "--contract",
        choices=list(CONTRACTS),
        default="share_review",
        help="使用合同：local_forensic 本地取证 / share_review 受控共享（默认）",
    )
    export_parser.add_argument(
        "--route",
        choices=list(ROUTES),
        default=None,
        help="共享发布路线：suppress 抑制 / interval 区间（默认取配置）",
    )
    export_parser.add_argument(
        "--min-group-size",
        type=int,
        default=None,
        help="联合发布检查的最小组样本量（默认取配置，>=2）",
    )
    export_parser.add_argument(
        "--secret",
        default=None,
        help="固定导出密钥（用于可复现导出）；默认每次随机，导出不互相关联",
    )
    export_parser.add_argument("--output-dir", default=None, help="覆盖共享包输出目录")
    export_parser.add_argument("--now", help="固定导出时间，ISO-8601；用于 golden 回归")
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
        if args.command == "export":
            now = parse_now(args.now)
            result = build_export(
                config,
                contract=args.contract,
                now=now,
                route=args.route,
                min_group_size=args.min_group_size,
                secret=args.secret,
                output_dir=args.output_dir,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
    except (ConfigError, PipelineError, ValueError, OSError) as exc:
        print(f"decodebench: {exc}", file=sys.stderr)
        return 2
    return 2
