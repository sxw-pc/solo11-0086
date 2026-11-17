"""304 验证事件与双合同视图的 SQLite 幂等写入。"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

def validation_identity(events: list[dict[str, Any]]) -> list[str]:
    """304 验证事件的确定性身份片段，纳入批次键。"""
    rows: list[str] = []
    for event in events:
        views = sorted(
            f"{v['contract']}:{v.get('view_rel_path')}:"
            f"{v.get('output_sha256')}:{int(bool(v['published']))}"
            for v in event.get("views", []))
        rows.append("|".join([
            str(event["rel_path_304"]), str(event.get("status")),
            str(event.get("resource_key")), str(event.get("etag_304")),
            str(event.get("entity_sha256")),
            json.dumps(event.get("request_vary", {}), ensure_ascii=False,
                       sort_keys=True, separators=(",", ":")),
            ",".join(event.get("error_codes", [])), ";".join(views)]))
    return sorted(rows)

def _upsert_views(connection: sqlite3.Connection, event_id: int, event: dict) -> None:
    connection.execute("DELETE FROM validation_views WHERE event_id = ?", (event_id,))
    for view in event.get("views", []):
        connection.execute(
            """INSERT INTO validation_views (
                event_id, contract, view_rel_path, encoding, method,
                success, published, entity_sha256, output_sha256, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, view["contract"], view.get("view_rel_path"),
             view.get("encoding"), view.get("method"),
             int(bool(view["success"])), int(bool(view["published"])),
             view["entity_sha256"], view.get("output_sha256"),
             json.dumps(view, ensure_ascii=False, sort_keys=True)))

def upsert_validation_event(connection: sqlite3.Connection, batch_id: str,
                            event: dict[str, Any], now: str) -> int:
    """幂等写入一个 304 验证事件及其两个合同视图。"""
    connection.execute(
        """INSERT INTO validation_events (
            batch_id, rel_path_304, status, resource_key, etag_304,
            request_vary_json, captured_at_304, donor_rel_path,
            donor_captured_at, entity_sha256, sidecar_200_sha256,
            sidecar_304_sha256, header_edition, synthesized_headers_json,
            error_codes_json, reason, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(batch_id, rel_path_304) DO UPDATE SET
            status = excluded.status, resource_key = excluded.resource_key,
            etag_304 = excluded.etag_304,
            request_vary_json = excluded.request_vary_json,
            captured_at_304 = excluded.captured_at_304,
            donor_rel_path = excluded.donor_rel_path,
            donor_captured_at = excluded.donor_captured_at,
            entity_sha256 = excluded.entity_sha256,
            sidecar_200_sha256 = excluded.sidecar_200_sha256,
            sidecar_304_sha256 = excluded.sidecar_304_sha256,
            header_edition = excluded.header_edition,
            synthesized_headers_json = excluded.synthesized_headers_json,
            error_codes_json = excluded.error_codes_json,
            reason = excluded.reason, updated_at = excluded.updated_at""",
        (batch_id, event["rel_path_304"], event["status"],
         event.get("resource_key"), event.get("etag_304"),
         json.dumps(event.get("request_vary", {}), ensure_ascii=False, sort_keys=True),
         event.get("captured_at_304"), event.get("donor_rel_path"),
         event.get("donor_captured_at"), event.get("entity_sha256"),
         event.get("sidecar_200_sha256"), event.get("sidecar_304_sha256"),
         event.get("header_edition"),
         json.dumps(event.get("synthesized_headers", []), ensure_ascii=False),
         json.dumps(event.get("error_codes", []), ensure_ascii=False),
         event.get("reason", ""), now, now))
    row = connection.execute(
        "SELECT id FROM validation_events WHERE batch_id = ? AND rel_path_304 = ?",
        (batch_id, event["rel_path_304"])).fetchone()
    assert row is not None
    event_id = int(row["id"])
    _upsert_views(connection, event_id, event)
    return event_id

def validation_summary(connection: sqlite3.Connection, batch_id: str) -> dict[str, int]:
    event_rows = connection.execute(
        "SELECT COUNT(*) AS n FROM validation_events WHERE batch_id = ?",
        (batch_id,)).fetchone()["n"]
    view_rows = connection.execute(
        """SELECT COUNT(*) AS n FROM validation_views
        JOIN validation_events ON validation_events.id = validation_views.event_id
        WHERE validation_events.batch_id = ?""",
        (batch_id,)).fetchone()["n"]
    return {"validation_event_rows": int(event_rows),
            "validation_view_rows": int(view_rows)}
