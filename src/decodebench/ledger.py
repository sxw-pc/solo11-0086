"""SQLite 台账：批次、文件、证据、决策与警告。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from . import RULE_VERSION
from .config import Config
from .ledger_schema import SCHEMA


def idempotency_key(source_sha256: str, config_fingerprint: str) -> str:
    return f"{source_sha256}:{RULE_VERSION}:{config_fingerprint}"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize(db_path: Path) -> None:
    connection = _connect(db_path)
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


def _batch_identity(files: list[dict[str, Any]], config: Config) -> tuple[str, str]:
    parts = sorted(
        f"{idempotency_key(str(item['source_sha256']), config.fingerprint)}|{item['rel_path']}"
        for item in files
    )
    source = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    batch_key = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return batch_key, batch_key[:20]


def _upsert_batch(
    connection: sqlite3.Connection,
    batch_id: str,
    batch_key: str,
    config: Config,
    now: str,
    file_count: int,
    conflict_count: int,
    transcoded_count: int,
) -> None:
    connection.execute(
        """
        INSERT INTO batches (
            batch_id, batch_key, input_root, rule_version, config_fingerprint,
            created_at, updated_at, run_count, status, file_count,
            conflict_count, transcoded_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'completed', ?, ?, ?)
        ON CONFLICT(batch_key) DO UPDATE SET
            updated_at = excluded.updated_at,
            run_count = batches.run_count + 1,
            status = 'reprocessed',
            file_count = excluded.file_count,
            conflict_count = excluded.conflict_count,
            transcoded_count = excluded.transcoded_count
        """,
        (
            batch_id,
            batch_key,
            config.scan_root.as_posix(),
            RULE_VERSION,
            config.fingerprint,
            now,
            now,
            file_count,
            conflict_count,
            transcoded_count,
        ),
    )


def _upsert_file(
    connection: sqlite3.Connection,
    batch_id: str,
    item: dict[str, Any],
    config: Config,
    now: str,
) -> int:
    decision = item["decision"]
    transcode = item["transcode"]
    source_key = idempotency_key(str(item["source_sha256"]), config.fingerprint)
    connection.execute(
        """
        INSERT INTO files (
            batch_id, idempotency_key, rel_path, source_size, source_sha256,
            source_mtime, final_encoding, confidence, method, conflict_count,
            warning_count, risk_level, transcode_success, output_rel_path,
            output_sha256, replacement_used, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(idempotency_key, rel_path) DO UPDATE SET
            batch_id = excluded.batch_id,
            source_size = excluded.source_size,
            source_sha256 = excluded.source_sha256,
            source_mtime = excluded.source_mtime,
            final_encoding = excluded.final_encoding,
            confidence = excluded.confidence,
            method = excluded.method,
            conflict_count = excluded.conflict_count,
            warning_count = excluded.warning_count,
            risk_level = excluded.risk_level,
            transcode_success = excluded.transcode_success,
            output_rel_path = excluded.output_rel_path,
            output_sha256 = excluded.output_sha256,
            replacement_used = excluded.replacement_used,
            updated_at = excluded.updated_at
        """,
        (
            batch_id,
            source_key,
            item["rel_path"],
            item["source_size"],
            item["source_sha256"],
            item["source_mtime"],
            decision["encoding"],
            float(decision["confidence"]),
            decision["method"],
            len(decision["conflicts"]),
            item["warning_count"],
            item["mojibake"]["level"],
            int(bool(transcode["success"])),
            transcode["output_rel_path"],
            transcode["output_sha256"],
            int(int(transcode["replacement_count"]) > 0),
            now,
            now,
        ),
    )
    row = connection.execute(
        "SELECT id FROM files WHERE idempotency_key = ? AND rel_path = ?",
        (source_key, item["rel_path"]),
    ).fetchone()
    assert row is not None
    file_id = int(row["id"])
    connection.execute("DELETE FROM evidence WHERE file_id = ?", (file_id,))
    connection.execute("DELETE FROM decisions WHERE file_id = ?", (file_id,))
    connection.execute("DELETE FROM warnings WHERE file_id = ?", (file_id,))
    for ordinal, evidence in enumerate(item["evidence"]):
        connection.execute(
            """
            INSERT INTO evidence (
                file_id, ordinal, source, declared, byte_offset, line_number,
                matches_decision, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                ordinal,
                evidence["source"],
                evidence["declared"],
                evidence["offset"],
                evidence["line"],
                None if evidence["matches_decision"] is None else int(bool(evidence["matches_decision"])),
                evidence["note"],
            ),
        )
    connection.execute(
        """
        INSERT INTO decisions (
            file_id, encoding, confidence, method, reason, conflicts_json, error_codes_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            decision["encoding"],
            float(decision["confidence"]),
            decision["method"],
            decision["reason"],
            json.dumps(decision["conflicts"], ensure_ascii=False),
            json.dumps(decision["error_codes"], ensure_ascii=False),
        ),
    )
    for warning in item["warnings"]:
        connection.execute(
            """
            INSERT INTO warnings (
                file_id, code, severity, message, line_number, byte_offset, snippet
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                warning["code"],
                warning["severity"],
                warning["message"],
                warning["line"],
                warning["offset"],
                warning["snippet"],
            ),
        )
    return file_id


def _ledger_summary(connection: sqlite3.Connection, batch_id: str) -> dict[str, Any]:
    file_count = connection.execute(
        "SELECT COUNT(*) AS n FROM files WHERE batch_id = ?", (batch_id,)
    ).fetchone()["n"]
    conflict_count = connection.execute(
        "SELECT COUNT(*) AS n FROM files WHERE batch_id = ? AND conflict_count > 0",
        (batch_id,),
    ).fetchone()["n"]
    transcoded = connection.execute(
        "SELECT COUNT(*) AS n FROM files WHERE batch_id = ? AND transcode_success = 1",
        (batch_id,),
    ).fetchone()["n"]
    evidence_rows = connection.execute(
        """
        SELECT COUNT(*) AS n FROM evidence
        JOIN files ON files.id = evidence.file_id WHERE files.batch_id = ?
        """,
        (batch_id,),
    ).fetchone()["n"]
    warning_rows = connection.execute(
        """
        SELECT COUNT(*) AS n FROM warnings
        JOIN files ON files.id = warnings.file_id WHERE files.batch_id = ?
        """,
        (batch_id,),
    ).fetchone()["n"]
    return {
        "batch_id": batch_id,
        "files_in_batch": int(file_count),
        "conflict_files": int(conflict_count),
        "transcoded_files": int(transcoded),
        "evidence_rows": int(evidence_rows),
        "decision_rows": int(file_count),
        "warning_rows": int(warning_rows),
        "files_table_total": int(
            connection.execute("SELECT COUNT(*) AS n FROM files").fetchone()["n"]
        ),
        "batches_table_total": int(
            connection.execute("SELECT COUNT(*) AS n FROM batches").fetchone()["n"]
        ),
    }


def record_batch(config: Config, manifest: dict[str, Any], now: str) -> dict[str, Any]:
    """幂等写入一个批次；相同 key 只更新既有批次与文件。"""
    initialize(config.db_path)
    files = manifest["files"]
    batch_key, batch_id = _batch_identity(files, config)
    conflict_count = sum(1 for item in files if item["decision"]["conflicts"])
    transcoded_count = sum(1 for item in files if item["transcode"]["success"])
    connection = _connect(config.db_path)
    try:
        with connection:
            _upsert_batch(
                connection,
                batch_id,
                batch_key,
                config,
                now,
                len(files),
                conflict_count,
                transcoded_count,
            )
            for item in files:
                _upsert_file(connection, batch_id, item, config, now)
        return _ledger_summary(connection, batch_id)
    finally:
        connection.close()
