"""实体台账记录的稳定字段顺序序列化。"""

from __future__ import annotations

from typing import Any

from .models import EntityResult, GroupResult


def group_row(group: GroupResult) -> dict[str, Any]:
    return {
        "capture_id": group.capture_id,
        "status": group.status,
        "reasons": list(group.reasons),
        "entity_size": group.entity_size,
        "fragments": [
            {
                "rel_path": item.rel_path,
                "capture_id": item.decl.capture_id,
                "byte_start": item.decl.byte_start,
                "byte_end_inclusive": item.decl.byte_end_inclusive,
                "sha256": item.sha256,
                "status": item.status,
            }
            for item in group.fragments
        ],
        "combinations": [
            {
                "sha256": item.sha256,
                "size": len(item.data),
                "fragments": [
                    {
                        "rel_path": fragment.rel_path,
                        "capture_id": fragment.decl.capture_id,
                        "byte_start": fragment.decl.byte_start,
                        "byte_end_inclusive": fragment.decl.byte_end_inclusive,
                        "sha256": fragment.sha256,
                    }
                    for fragment in item.fragments
                ],
            }
            for item in group.combinations
        ],
        "overlap_conflicts": list(group.overlap_conflicts),
        "explored": group.explored,
    }


def entity_record(result: EntityResult) -> dict[str, Any]:
    """逻辑实体的决策编码、组装摘要、片段区间与排除证据。"""
    return {
        "entity_id": result.entity_id,
        "status": result.status,
        "complete": result.complete,
        "entity_size": result.entity_size,
        "capture_id": result.capture_id,
        "reasons": list(result.reasons),
        "assembled_sha256": result.assembled_sha256,
        "selected": (
            {
                "sha256": result.selected.sha256,
                "fragments": [
                    {
                        "rel_path": item.rel_path,
                        "capture_id": item.decl.capture_id,
                        "byte_start": item.decl.byte_start,
                        "byte_end_inclusive": item.decl.byte_end_inclusive,
                        "sha256": item.sha256,
                    }
                    for item in result.selected.fragments
                ],
            }
            if result.selected is not None
            else None
        ),
        "groups": [group_row(group) for group in result.groups],
        "excluded": result.excluded,
        "conflict": result.conflict,
        "shared_fragments": result.shared_fragments,
        "fragments": [
            {
                "rel_path": item.rel_path,
                "capture_id": item.decl.capture_id,
                "byte_start": item.decl.byte_start,
                "byte_end_inclusive": item.decl.byte_end_inclusive,
                "entity_size": item.decl.entity_size,
                "validator": item.decl.validator,
                "sha256": item.sha256,
                "status": item.status,
                "reasons": list(item.reasons),
            }
            for item in result.fragments
        ],
    }
