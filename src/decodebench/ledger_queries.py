"""只读 SQLite 查询，供报告与本地复核台复用。"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def _connect_readonly(db_path: Path) -> sqlite3.Connection:
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def list_batches(db_path: Path) -> list[dict[str, Any]]:
    if not db_path.is_file():
        return []
    connection = _connect_readonly(db_path)
    try:
        rows = connection.execute(
            """
            SELECT batch_id, batch_key, input_root, rule_version, config_fingerprint,
                   created_at, updated_at, run_count, status, file_count,
                   conflict_count, transcoded_count
            FROM batches
            ORDER BY created_at DESC, batch_id ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_batch(db_path: Path, batch_id: str) -> dict[str, Any] | None:
    if not db_path.is_file():
        return None
    connection = _connect_readonly(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        return _dict(row)
    finally:
        connection.close()


def list_files(db_path: Path, batch_id: str) -> list[dict[str, Any]]:
    if not db_path.is_file():
        return []
    connection = _connect_readonly(db_path)
    try:
        rows = connection.execute(
            """
            SELECT id, rel_path, source_size, source_sha256, final_encoding,
                   confidence, method, conflict_count, warning_count, risk_level,
                   transcode_success, output_rel_path, output_sha256, replacement_used,
                   sidecar_sha256, entity_sha256, decoded_sha256,
                   content_encoding_status, content_encoding_published,
                   transcode_partial
            FROM files
            WHERE batch_id = ?
            ORDER BY rel_path ASC
            """,
            (batch_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_file_detail(
    db_path: Path, batch_id: str, rel_path: str
) -> dict[str, Any] | None:
    if not db_path.is_file():
        return None
    connection = _connect_readonly(db_path)
    try:
        file_row = connection.execute(
            """
            SELECT * FROM files WHERE batch_id = ? AND rel_path = ?
            """,
            (batch_id, rel_path),
        ).fetchone()
        if file_row is None:
            return None
        file_data = dict(file_row)
        file_id = int(file_data["id"])
        decision = connection.execute(
            "SELECT * FROM decisions WHERE file_id = ?", (file_id,)
        ).fetchone()
        evidence = connection.execute(
            """
            SELECT ordinal, source, declared, byte_offset, line_number,
                   matches_decision, note
            FROM evidence WHERE file_id = ? ORDER BY ordinal ASC
            """,
            (file_id,),
        ).fetchall()
        warnings = connection.execute(
            """
            SELECT code, severity, message, line_number, byte_offset, snippet
            FROM warnings WHERE file_id = ?
            ORDER BY code ASC, line_number ASC, byte_offset ASC, id ASC
            """,
            (file_id,),
        ).fetchall()
        evidence_rows = []
        for row in evidence:
            item = dict(row)
            item["matches_decision"] = (
                None
                if item["matches_decision"] is None
                else bool(item["matches_decision"])
            )
            evidence_rows.append(item)
        file_data["decision"] = _dict(decision)
        file_data["evidence"] = evidence_rows
        file_data["warnings"] = [dict(row) for row in warnings]
        return file_data
    finally:
        connection.close()
