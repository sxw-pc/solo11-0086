"""按 entity_id 分组组装；未声明分段的文件不进入此模块。"""

from __future__ import annotations

from .assembly_contract import capture_of, decide_contract, excluded_rows
from .assembly_groups import group_result
from .assembly_records import entity_record, group_row  # noqa: F401  (re-export)
from .config import Config
from .fragments import build_groups, shared_fragments, validator_digest
from .models import EntityResult, GroupResult, LoadedFragment

__all__ = [
    "assemble_entities",
    "entity_record",
    "group_row",
    "capture_of",
]


def _identity(
    fragments: list[LoadedFragment],
) -> tuple[int | None, list[str], str]:
    """消歧实体总长；validator 只在单个捕获组内要求一致。"""
    readable = [item for item in fragments if item.raw is not None]
    pool = readable or fragments
    if not pool:
        return None, ["没有可读取的片段"], "invalid_declaration"
    sizes = sorted({item.decl.entity_size for item in pool})
    reasons: list[str] = []
    if len(sizes) > 1:
        reasons.append(
            "entity_size 声明互相矛盾: " + ", ".join(str(value) for value in sizes)
        )
        return None, reasons, "identity_mismatch"
    usable = [item for item in fragments if item.raw is not None and item.status == "ok"]
    if not usable:
        return sizes[0], ["没有通过校验的片段字节"], "incomplete"
    return sizes[0], [], ""


def assemble_entities(
    loaded: list[LoadedFragment], config: Config
) -> list[EntityResult]:
    """按 entity_id 分组组装；只处理带片段声明的文件。"""
    by_entity: dict[str, list[LoadedFragment]] = {}
    for fragment in loaded:
        by_entity.setdefault(fragment.decl.entity_id, []).append(fragment)
    results = [
        _assemble_entity(
            entity_id,
            sorted(
                by_entity[entity_id],
                key=lambda item: (
                    item.decl.capture_id,
                    item.decl.byte_start,
                    item.rel_path,
                ),
            ),
            config,
        )
        for entity_id in sorted(by_entity)
    ]
    results.sort(key=lambda item: item.entity_id)
    return results


def _assemble_entity(
    entity_id: str, fragments: list[LoadedFragment], config: Config
) -> EntityResult:
    entity_size, identity_reasons, identity_status = _identity(fragments)
    shared = shared_fragments(fragments)
    if entity_size is None or identity_status:
        groups = [
            GroupResult(
                capture_id,
                identity_status or "invalid_declaration",
                list(identity_reasons),
                group_fragments,
                [],
                [],
                0,
                entity_size or 0,
            )
            for capture_id, group_fragments in sorted(build_groups(fragments).items())
        ]
        return EntityResult(
            entity_id,
            identity_status or "invalid_declaration",
            list(identity_reasons),
            entity_size,
            None,
            groups,
            fragments,
            shared_fragments=shared,
        )
    valid = [
        item for item in fragments if item.status == "ok" and item.raw is not None
    ]
    budget = config.assembly_max_combinations
    groups = [
        group_result(capture_id, group_fragments, entity_size, budget)
        for capture_id, group_fragments in sorted(build_groups(valid).items())
    ]
    status, reasons, selected, excluded, conflict = decide_contract(groups, config)
    if selected is not None:
        digest = validator_digest(selected.fragments[0].decl.validator)
        if digest is not None and digest != selected.sha256:
            return EntityResult(
                entity_id,
                "validator_mismatch",
                [
                    f"validator 摘要 {digest} 与组装字节摘要 "
                    f"{selected.sha256} 不一致"
                ],
                entity_size,
                None,
                groups,
                fragments,
                excluded=excluded_rows(groups, None),
                conflict=conflict,
                shared_fragments=shared,
            )
    return EntityResult(
        entity_id,
        status,
        reasons,
        entity_size,
        capture_of(selected) if selected is not None else None,
        groups,
        fragments,
        assembled=selected.data if selected is not None else None,
        assembled_sha256=selected.sha256 if selected is not None else None,
        selected=selected,
        excluded=excluded,
        conflict=conflict,
        shared_fragments=shared,
    )
