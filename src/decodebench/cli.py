"""命令行入口：pipeline、只读 serve 与事后抽样 audit。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .audit import AuditError, build_audit_plan, estimate_delivery_audit
from .config import ConfigError, load_config
from .ledger_queries import list_delivered_files
from .manifest import build_audit_frame
from .pipeline import PipelineError, run
from .web import serve


def run_audit_command(config, args) -> dict:
    """只读构造抽样框并估计；不写台账、不改裁决、不改交付门槛。"""
    manifest_path = config.manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    frame = build_audit_frame(manifest)
    ledger = list_delivered_files(config.db_path, frame["batch_id"])
    if [row["rel_path"] for row in ledger] != [
        unit["rel_path"] for unit in frame["delivered_files"]
    ]:
        raise AuditError("台账交付文件与抽样框不一致，拒绝继续审计")
    output_dir = config.transcode_dir
    seed: int | str = args.seed
    if isinstance(seed, str) and seed.lstrip("-").isdigit():
        seed = int(seed)
    plan = build_audit_plan(frame, budget=args.budget, seed=seed)
    labels = []
    if args.labels:
        from pathlib import Path

        labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    estimate = estimate_delivery_audit(plan, frame, labels, output_root=output_dir)
    return {"frame": frame, "plan": plan, "estimate": estimate}


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
    audit_parser = subparsers.add_parser(
        "audit", help="只读运行事后人工抽样审计（不改变裁决或交付）"
    )
    audit_parser.add_argument("--config", required=True, help="YAML 配置路径")
    audit_parser.add_argument("--budget", type=int, required=True, help="人工复核文件预算")
    audit_parser.add_argument("--seed", default="0", help="可注入抽样种子")
    audit_parser.add_argument(
        "--labels", help="人工标签 JSON 数组路径；省略则全部按未回应处理"
    )
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
        if args.command == "audit":
            print(json.dumps(run_audit_command(config, args), ensure_ascii=False, indent=2))
            return 0
    except (ConfigError, PipelineError, AuditError, ValueError, OSError) as exc:
        print(f"decodebench: {exc}", file=sys.stderr)
        return 2
    return 2
