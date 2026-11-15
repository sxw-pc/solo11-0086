"""仅监听回环地址的只读本地复核台。"""

from __future__ import annotations

import json
from typing import Any

from flask import Flask, abort, render_template

from .config import Config
from .ledger_queries import get_batch, get_file_detail, list_batches, list_files


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


def create_app(config: Config) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["DECODEBENCH_DB"] = str(config.db_path)

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
