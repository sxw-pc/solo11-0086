"""仅监听回环地址的只读本地复核台。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from flask import Flask, abort, render_template

from .config import Config
from .ledger_queries import get_batch, get_file_detail, list_batches, list_files
from .projection import (
    SharePolicy,
    build_shared_view,
    new_export_secret,
    summarize_internal,
)


def _decode_decision(detail: dict[str, Any]) -> None:
    decision = detail.get("decision")
    if not decision:
        return
    for source, target in (
        ("conflicts_json", "conflicts"),
        ("error_codes_json", "error_codes"),
    ):
        try:
            decision[target] = json.loads(decision.get(source) or "[]")
        except (TypeError, json.JSONDecodeError):
            decision[target] = []


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _ledger_internal_rows(db_path, batch_id: str) -> list[dict[str, Any]]:
    """把台账行重建为统一投影的输入行（仅本机使用，不直接对外）。"""
    rows: list[dict[str, Any]] = []
    for item in list_files(db_path, batch_id):
        detail = get_file_detail(db_path, batch_id, item["rel_path"]) or {}
        decision = detail.get("decision") or {}
        try:
            error_codes = json.loads(decision.get("error_codes_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            error_codes = []
        warnings = detail.get("warnings") or []
        rows.append(
            {
                "rel_path": item["rel_path"],
                "encoding": item["final_encoding"],
                "confidence": float(item["confidence"]),
                "method": item["method"],
                "conflict": int(item["conflict_count"]) > 0,
                "error_codes": [str(code) for code in error_codes],
                "transcode_success": bool(item["transcode_success"]),
                "output_rel_path": item["output_rel_path"],
                "output_sha256": item["output_sha256"],
                "risk_level": item["risk_level"],
                "warning_count": int(item["warning_count"]),
                "warning_codes": sorted({str(row["code"]) for row in warnings}),
                "warning_details": [
                    {"code": str(row["code"]), "severity": str(row["severity"])}
                    for row in warnings
                ],
            }
        )
    rows.sort(key=lambda row: str(row["rel_path"]))
    return rows


def _share_cell(value: Any) -> str:
    if isinstance(value, dict) and "min" in value and "max" in value:
        return f"{value['min']}–{value['max']}"
    if value == "suppressed":
        return "已抑制"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "无"
    if value is True:
        return "是"
    if value is False:
        return "否"
    return str(value)


def create_app(config: Config) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["DECODEBENCH_DB"] = str(config.db_path)
    app.template_filter("sharecell")(_share_cell)

    @app.get("/")
    def index():
        batches = list_batches(config.db_path)
        return render_template("index.html", batches=batches)

    @app.get("/batch/<batch_id>")
    def batch_detail(batch_id: str):
        batch = get_batch(config.db_path, batch_id)
        if batch is None:
            abort(404)
        files = list_files(config.db_path, batch_id)
        return render_template("batch.html", batch=batch, files=files)

    @app.get("/batch/<batch_id>/share")
    def batch_share(batch_id: str):
        batch = get_batch(config.db_path, batch_id)
        if batch is None:
            abort(404)
        rows = _ledger_internal_rows(config.db_path, batch_id)
        policy = SharePolicy(
            route=config.share_route,
            min_group_size=config.share_min_group_size,
            audit_contact=config.share_audit_contact,
        )
        # 预览代号每次访问都重新随机，预览之间也不默认可关联。
        view = build_shared_view(
            rows,
            summarize_internal(rows),
            policy,
            _utc_now(),
            new_export_secret(),
        )
        return render_template("share.html", batch=batch, view=view)

    @app.get("/file/<batch_id>/<path:rel_path>")
    def file_detail(batch_id: str, rel_path: str):
        detail = get_file_detail(config.db_path, batch_id, rel_path)
        if detail is None:
            abort(404)
        batch = get_batch(config.db_path, batch_id)
        _decode_decision(detail)
        return render_template("file.html", batch=batch, detail=detail)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "read_only": True}

    @app.after_request
    def hardening_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self'; "
            "script-src 'none'; object-src 'none'; base-uri 'none'"
        )
        return response

    return app


def serve(config: Config) -> None:
    if config.web_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("复核台只允许回环地址")
    app = create_app(config)
    app.run(
        host=config.web_host,
        port=config.web_port,
        debug=False,
        use_reloader=False,
    )
