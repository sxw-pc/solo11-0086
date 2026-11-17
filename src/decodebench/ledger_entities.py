"""实体与片段台账：逻辑实体决策、组装字节摘要与片段来源。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any


def assembly_identity(assembly: dict[str, Any]) -> str:
    """实体台账的批次键；无片段声明时返回空串，保持旧批次键。"""
    parts: list[str] = []
    for entity in assembly.get("entities", []):
        parts.append(
            json.dumps(
                {
                    "entity_id": entity["entity_id"],
                    "status": entity["status"],
                    "assembled_sha256": entity["assembled_sha256"],
                    "fragments": sorted(
                        (item["rel_path"], item["sha256"] or "")
                        for item in entity["fragments"]
                    ),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    if not parts:
        return ""
    identity = {
        "contract": assembly.get("contract"),
        "priority_capture_ids": list(assembly.get("priority_capture_ids") or []),
        "entities": sorted(parts),
    }
    source = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _upsert_entity(
    connection: sqlite3.Connection,
    batch_id: str,
    entity: dict[str, Any],
    fragments: list[dict[str, Any]],
    now: str,
) -> None:
    entity_key = f"{batch_id}|{entity['entity_id']}"
    transcode = entity.get("transcode") or {}
    decision = entity.get("decision") or {}
    conflict = entity.get("conflict") or {}
    connection.execute(
        """
        INSERT INTO entities (
            batch_id, entity_key, entity_id, status, complete, entity_size,
            capture_id, assembled_sha256, final_encoding, confidence, method,
            transcode_success, output_rel_path, output_utf8_sha256,
            conflict_offset, conflict_json, excluded_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_key) DO UPDATE SET
            status = excluded.status,
            complete = excluded.complete,
            entity_size = excluded.entity_size,
            capture_id = excluded.capture_id,
            assembled_sha256 = excluded.assembled_sha256,
            final_encoding = excluded.final_encoding,
            confidence = excluded.confidence,
            method = excluded.method,
            transcode_success = excluded.transcode_success,
            output_rel_path = excluded.output_rel_path,
            output_utf8_sha256 = excluded.output_utf8_sha256,
            conflict_offset = excluded.conflict_offset,
            conflict_json = excluded.conflict_json,
            excluded_json = excluded.excluded_json,
            updated_at = excluded.updated_at
        """,
        (
            batch_id,
            entity_key,
            entity["entity_id"],
            entity["status"],
            int(bool(entity["complete"])),
            entity["entity_size"],
            entity["capture_id"],
            entity["assembled_sha256"],
            decision.get("encoding"),
            None if not decision else float(decision["confidence"]),
            decision.get("method"),
            int(bool(transcode.get("success"))),
            transcode.get("output_rel_path"),
            transcode.get("output_sha256"),
            conflict.get("byte_offset") if isinstance(conflict, dict) else None,
            json.dumps(conflict, ensure_ascii=False),
            json.dumps(entity.get("excluded") or [], ensure_ascii=False),
            now,
            now,
        ),
    )
    row = connection.execute(
        "SELECT id FROM entities WHERE entity_key = ?", (entity_key,)
    ).fetchone()
    assert row is not None
    entity_row = int(row["id"])
    connection.execute(
        "DELETE FROM entity_fragments WHERE entity_id_row = ?", (entity_row,)
    )
    ordered = sorted(
        fragments,
        key=lambda item: (
            str(item["capture_id"]),
            int(item["byte_start"]),
            str(item["rel_path"]),
        ),
    )
    for ordinal, fragment in enumerate(ordered):
        connection.execute(
            """
            INSERT INTO entity_fragments (
                entity_id_row, ordinal, rel_path, capture_id, byte_start,
                byte_end_inclusive, entity_size, validator, source_sha256,
                fragment_sha256, status, consumed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity_row,
                ordinal,
                fragment["rel_path"],
                fragment["capture_id"],
                int(fragment["byte_start"]),
                int(fragment["byte_end_inclusive"]),
                int(fragment["entity_size"]),
                fragment["validator"],
                fragment["source_sha256"],
                fragment["sha256"],
                fragment["status"],
                int(bool(fragment["consumed"])),
            ),
        )


def upsert_entities(
    connection: sqlite3.Connection,
    batch_id: str,
    assembly: dict[str, Any],
    now: str,
) -> None:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for fragment in assembly.get("fragments", []):
        grouped.setdefault(str(fragment["entity_id"]), []).append(fragment)
    for entity in assembly.get("entities", []):
        _upsert_entity(
            connection, batch_id, entity, grouped.get(str(entity["entity_id"]), []), now
        )


def entity_counts(connection: sqlite3.Connection, batch_id: str) -> dict[str, int]:
    rows = connection.execute(
        "SELECT COUNT(*) AS n FROM entities WHERE batch_id = ?", (batch_id,)
    ).fetchone()
    complete = connection.execute(
        "SELECT COUNT(*) AS n FROM entities WHERE batch_id = ? AND complete = 1",
        (batch_id,),
    ).fetchone()
    transcoded = connection.execute(
        "SELECT COUNT(*) AS n FROM entities WHERE batch_id = ? AND transcode_success = 1",
        (batch_id,),
    ).fetchone()
    fragments = connection.execute(
        """
        SELECT COUNT(*) AS n FROM entity_fragments
        JOIN entities ON entities.id = entity_fragments.entity_id_row
        WHERE entities.batch_id = ?
        """,
        (batch_id,),
    ).fetchone()
    return {
        "entities_in_batch": int(rows["n"]),
        "entities_complete": int(complete["n"]),
        "entities_transcoded": int(transcoded["n"]),
        "entity_fragment_rows": int(fragments["n"]),
    }
